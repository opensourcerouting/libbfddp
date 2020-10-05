/*
 * BFD Data Plane daemon packet handling.
 *
 * Copyright (C) 2020 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael F. Zalamena
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the “Software”), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

/* Required from PRIu64 macro. */
#include <inttypes.h>

#include <sys/time.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "bfddp.h"
#include "bfddp_extra.h"
#include "bfddp_packet.h"
#include "bfddpd.h"

/* Error statistics */
static struct bfd_error_statistics error_stats;

void
bfddp_process_echo_time(const struct bfddp_echo *echo)
{
	uint64_t bfdt, dpt, dpt_total;
	struct timeval tv;

	/* Collect registered timestamps. */
	bfdt = be64toh(echo->bfdd_time);
	dpt = be64toh(echo->dp_time);

	/* Measure new time. */
	gettimeofday(&tv, NULL);

	/* Calculate total time taken until here. */
	dpt_total = (uint64_t)((tv.tv_sec * 1000000) + tv.tv_usec);

	bfddp_log("echo-reply: BFD process time was %" PRIu64 " microseconds. "
	          "Packet total processing time was %" PRIu64 " microseconds\n",
	          bfdt - dpt, dpt_total - dpt);
}

/*
 * BFD Protocol.
 */
ssize_t
bfd_tx_control_cb(struct bfd_session *bs, __attribute__((unused)) void *arg,
		  const struct bfddp_control_packet *bcp)
{
	struct bfd_session_data *bsd = bs->bs_data;
	socklen_t salen;
	ssize_t rv;

	if (bs->bs_dst.bs_dst_sa.sa_family == AF_INET)
		salen = sizeof(struct sockaddr_in);
	else
		salen = sizeof(struct sockaddr_in6);

	rv = sendto(bsd->bsd_sock, bcp, bcp->length, 0, &bs->bs_dst.bs_dst_sa,
		    salen);
	if (rv <= 0) {
		plog("sendto failed: %s", strerror(errno));
	}

	return rv;
}

static void
_bfd_recv_packet_v4(struct msghdr *msg, struct bfd_packet_metadata *bpm)
{
	struct sockaddr_in *sin;
	struct in_pktinfo *ipi;
	struct cmsghdr *cmsg;
	int32_t ttl;

	memcpy(&bpm->bpm_dst, msg->msg_name, sizeof(struct sockaddr_in));

	for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cmsg->cmsg_level != IPPROTO_IP) {
			plog("unhandled cmsg_level %d", cmsg->cmsg_level);
			continue;
		}

		/* Process ancillary data. */
		switch (cmsg->cmsg_type) {
		case IP_PKTINFO:
			ipi = (struct in_pktinfo *)CMSG_DATA(cmsg);
			sin = (struct sockaddr_in *)&bpm->bpm_src;

			memset(sin, 0, sizeof(*sin));
			sin->sin_family = AF_INET;
			memcpy(&sin->sin_addr, &ipi->ipi_addr,
			       sizeof(sin->sin_addr));
			bpm->bpm_ifindex = (uint32_t)ipi->ipi_ifindex;
			break;
		case IP_TTL:
			ttl = *(int32_t *)CMSG_DATA(cmsg);
			if (ttl < 0 || ttl > 255) {
				plog("bad TTL %d", ttl);
			}

			bpm->bpm_ttl = (uint8_t)ttl;
			break;

		default:
			plog("unhandled cmsg_type %d", cmsg->cmsg_level);
			break;
		}
	}
}

static void
_bfd_recv_packet_v6(struct msghdr *msg, struct bfd_packet_metadata *bpm)
{
#if 1
	struct in6_pktinfo {
		struct in6_addr ipi6_addr;
		int ipi6_ifindex;
	} *ipi6;
#else
	struct in6_pktinfo *ipi6;
#endif
	struct sockaddr_in6 *sin6;
	struct cmsghdr *cmsg;
	int32_t ttl;

	for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cmsg->cmsg_level != IPPROTO_IPV6) {
			plog("unhandled cmsg_level %d", cmsg->cmsg_level);
			continue;
		}

		/* Process ancillary data. */
		switch (cmsg->cmsg_type) {
		case IPV6_PKTINFO:
			ipi6 = (struct in6_pktinfo *)CMSG_DATA(cmsg);
			sin6 = (struct sockaddr_in6 *)&bpm->bpm_src;

			memset(sin6, 0, sizeof(*sin6));
			sin6->sin6_family = AF_INET6;
			memcpy(&bpm->bpm_src.sin6_addr, &ipi6->ipi6_addr,
			       sizeof(struct in6_addr));
			bpm->bpm_ifindex = (uint32_t)ipi6->ipi6_ifindex;
			if (IN6_IS_ADDR_LINKLOCAL(&ipi6->ipi6_addr))
				sin6->sin6_scope_id =
					(uint32_t)ipi6->ipi6_ifindex;
			break;
		case IPV6_HOPLIMIT:
			ttl = *(int32_t *)CMSG_DATA(cmsg);
			if (ttl < 0 || ttl > 255) {
				plog("bad TTL %d", ttl);
			}

			bpm->bpm_ttl = (uint8_t)ttl;
			break;

		default:
			plog("unhandled cmsg_type %d", cmsg->cmsg_level);
			break;
		}
	}
}

static int
bfd_recv_packet(int sock, struct bfd_packet_metadata *bpm)
{
	ssize_t rv;
	struct sockaddr_storage ss = {};
	struct iovec iov[1] = {};
	struct msghdr msg = {};
	char cmsgbuf[256];

	/* Configure IOV to receive data. */
	iov[0].iov_base = bpm->bpm_data;
	iov[0].iov_len = sizeof(bpm->bpm_data);

	/* Configure message receive header. */
	msg.msg_name = &ss;
	msg.msg_namelen = sizeof(ss);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	do {
		rv = recvmsg(sock, &msg, 0);
		/* Handle signals: just restart syscall. */
		if (rv == -1 && errno == EINTR)
			continue;
	} while (rv <= 0);

	/* Socket closed or failure. */
	if (rv <= 0)
		return (int)rv;

	bpm->bpm_datalen = (uint16_t)rv;

	switch (ss.ss_family) {
	case AF_INET:
		_bfd_recv_packet_v4(&msg, bpm);
		break;
	case AF_INET6:
		_bfd_recv_packet_v6(&msg, bpm);
		break;

	default:
		return -1;
	}

	plog("Received packet [ttl=%d ifindex=%d datalen=%d]", bpm->bpm_ttl,
	     bpm->bpm_ifindex, bpm->bpm_datalen);

	return (int)rv;
}

static bool
bfd_session_check_dst(const struct bfd_session *bs,
		      const struct bfd_packet_metadata *bpm)
{
	struct sockaddr_in *bsin;

	switch (bpm->bpm_dst.sin6_family) {
	case AF_INET:
		bsin = (struct sockaddr_in *)&bpm->bpm_dst;
		return bs->bs_dst.bs_dst_sin.sin_addr.s_addr
		       == bsin->sin_addr.s_addr;

	case AF_INET6:
		return memcmp(&bs->bs_dst, &bpm->bpm_dst.sin6_addr,
			      sizeof(bs->bs_dst));
	}

	return false;
}

static bool
bfd_session_check_src(const struct bfd_session *bs,
		      const struct bfd_packet_metadata *bpm)
{
	struct sockaddr_in *bsin;

	switch (bpm->bpm_src.sin6_family) {
	case AF_INET:
		bsin = (struct sockaddr_in *)&bpm->bpm_src;
		return bs->bs_src.bs_src_sin.sin_addr.s_addr
		       == bsin->sin_addr.s_addr;

	case AF_INET6:
		return memcmp(&bs->bs_src, &bpm->bpm_src.sin6_addr,
			      sizeof(bs->bs_src));
	}

	return false;
}

void
bfd_process_control_packet(struct bfd_packet_metadata *bpm)
{
	struct bfddp_control_packet *bcp;
	struct bfd_session *bs;
	enum bfddp_packet_validation bpv;
	enum bfddp_packet_validation_extra bpve;

	bcp = (struct bfddp_control_packet *)bpm->bpm_data;
	bpv = bfddp_session_validate_packet(bcp, (size_t)bpm->bpm_datalen);
	switch (bpv) {
	case BPV_INVALID_LENGTH:
		/* FALLTHROUGH */
	case BPV_PACKET_TOO_SMALL:
		error_stats.invalid_len_drops++;
		return;
	case BPV_INVALID_VERSION:
		error_stats.version_drops++;
		return;
	case BPV_ZERO_MULTIPLIER:
		error_stats.multiplier_drops++;
		return;
	case BPV_ZERO_LOCAL_ID:
		error_stats.my_disc_drops++;
		return;
	case BPV_INVALID_REMOTE_ID:
		return;

	case BPV_OK:
		/* Packet is valid, proceed. */
		break;
	}

	/*
	 * If our ID is not set, then we must look up the session using other
	 * packet attributes: source address, peer address, interface etc...
	 *
	 * Otherwise just look up the peer ID and match its address (to avoid
	 * spoofing).
	 */
	if (bcp->remote_id == 0) {
		bs = bfd_session_lookup_by_packet(bpm);
		if (bs == NULL) {
			plog("session not found");
			error_stats.invalid_session_drops++;
			return;
		}
	} else {
		bs = bfd_session_lookup(ntohl(bcp->remote_id));
		if (bs == NULL) {
			plog("session for ID %u found", ntohl(bcp->remote_id));
			error_stats.invalid_session_drops++;
			return;
		}

		/* Make sure we are looking at the correct session. */
		if (bfd_session_check_dst(bs, bpm) == false) {
			plog("invalid session address");
			error_stats.invalid_session_drops++;
			return;
		}
	}

	bpve = bfddp_session_rx_packet(bs, NULL, bcp);
	switch (bpve) {
	case BPVE_UNEXPECTED_MULTI:
		error_stats.multi_point_drops++;
		break;
	case BPVE_REMOTE_ID_INVALID:
		break;
	case BPVE_UNEXPECTED_AUTH:
	case BPVE_AUTH_MISSING:
	case BPVE_AUTH_INVALID:
		break;

	case BPVE_OK:
		/* NOTHING */
		break;
	}
}

void
bfd_recv_control_packet(int sock)
{
	int plen;
	struct bfd_packet_metadata bpm = {};

	plen = bfd_recv_packet(sock, &bpm);
	/* Handle failures. */
	if (plen <= 0)
		return;

	bfd_process_control_packet(&bpm);
}

/*
 * BFD Protocol.
 */
ssize_t
bfd_tx_echo_cb(struct bfd_session *bs, __attribute__((unused)) void *arg,
	       const struct bfddp_echo_packet *bep)
{
	struct bfd_session_data *bsd = bs->bs_data;
	socklen_t salen;
	ssize_t rv;

	if (bs->bs_dst.bs_dst_sa.sa_family == AF_INET)
		salen = sizeof(struct sockaddr_in);
	else
		salen = sizeof(struct sockaddr_in6);

	rv = sendto(bsd->bsd_sock, bep, bep->length, 0, &bs->bs_dst.bs_dst_sa,
		    salen);
	if (rv <= 0) {
		plog("sendto failed: %s", strerror(errno));
	}

	return rv;
}

void
bfd_process_echo_packet(struct bfd_packet_metadata *bpm)
{
	struct bfddp_echo_packet *bep;
	struct bfd_session *bs;
	enum bfddp_packet_validation bpv;

	bep = (struct bfddp_echo_packet *)bpm->bpm_data;
	bpv = bfddp_session_validate_echo_packet(bep, (size_t)bpm->bpm_datalen);
	if (bpv != BPV_OK)
		return;

	/*
	 * Lookup the session based on the local ID.
	 */
	bs = bfd_session_lookup(ntohl(bep->local_id));
	if (bs == NULL) {
		plog("session for ID %u not found", nthol(bep->local_id));
		return;
	}

	/* Make sure we are looking at the correct session. */
	if (bfd_session_check_src(bs, bpm) == false) {
		plog("invalid session address");
		return;
	}

	bfddp_session_rx_echo_packet(bs, NULL, bep);
}

void
bfd_recv_echo_packet(int sock)
{
	ssize_t plen;
	struct bfd_packet_metadata bpm = {};

	plen = bfd_recv_packet(sock, &bpm);
	/* Handle failures. */
	if (plen <= 0)
		return;

	bpm.bpm_datalen = (uint16_t)plen;
	bfd_process_echo_packet(&bpm);
}
