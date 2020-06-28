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

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "bfddp.h"
#include "bfddp_packet.h"
#include "bfddpd.h"

static uint64_t
hu64tonu64(uint64_t value)
{
	union {
		uint32_t v32[2];
		uint64_t v64;
	} vu, *vp;

	vp = (void *)&value;
	vu.v32[0] = htonl(vp->v32[1]);
	vu.v32[1] = htonl(vp->v32[0]);

	return vu.v64;
}

static uint64_t
nu64tohu64(uint64_t value)
{
	union {
		uint32_t v32[2];
		uint64_t v64;
	} vu, *vp;

	vp = (void *)&value;
	vu.v32[0] = ntohl(vp->v32[1]);
	vu.v32[1] = ntohl(vp->v32[0]);

	return vu.v64;
}

void
bfddp_send_echo_request(struct bfddp_ctx *bctx)
{
	struct bfddp_message msg = {};
	struct timeval tv;

	/* Prepare header. */
	msg.header.version = BFD_DP_VERSION;
	msg.header.length = htons(sizeof(struct bfddp_message_header) +
		sizeof(struct bfddp_echo));
	msg.header.type = htons(ECHO_REQUEST);

	/* Payload data. */
	gettimeofday(&tv, NULL);
	msg.data.echo.dp_time =
		hu64tonu64((uint64_t)((tv.tv_sec * 1000000) + tv.tv_usec));

	if (bfddp_write_enqueue(bctx, &msg) == 0)
		errx(1, "%s: bfddp_write_enqueue failed", __func__);
}

void
bfddp_send_echo_reply(struct bfddp_ctx *bctx, uint64_t bfdd_time)
{
	struct bfddp_message msg = {};
	struct timeval tv;

	/* Prepare header. */
	msg.header.version = BFD_DP_VERSION;
	msg.header.length = htons(sizeof(struct bfddp_message_header) +
		sizeof(struct bfddp_echo));
	msg.header.type = htons(ECHO_REPLY);

	/* Payload data. */
	gettimeofday(&tv, NULL);
	msg.data.echo.dp_time =
		hu64tonu64((uint64_t)((tv.tv_sec * 1000000) + tv.tv_usec));
	msg.data.echo.bfdd_time = bfdd_time;

	if (bfddp_write_enqueue(bctx, &msg) == 0)
		errx(1, "%s: bfddp_write_enqueue failed", __func__);
}

void
bfddp_process_echo_time(const struct bfddp_echo *echo)
{
	uint64_t bfdt, dpt, dpt_total;
	struct timeval tv;

	/* Collect registered timestamps. */
	bfdt = nu64tohu64(echo->bfdd_time);
	dpt = nu64tohu64(echo->dp_time);

	/* Measure new time. */
	gettimeofday(&tv, NULL);

	/* Calculate total time taken until here. */
	dpt_total = (uint64_t)((tv.tv_sec * 1000000) + tv.tv_usec);

	printf("echo-reply: BFD process time was %" PRIu64 " microseconds. "
	       "Packet total processing time was %" PRIu64 " microseconds\n",
	       bfdt - dpt, dpt_total - dpt);
}

void
bfddp_send_session_state_change(const struct bfd_session *bs)
{
	struct bfddp_message msg = {};

	/* Prepare header. */
	msg.header.version = BFD_DP_VERSION;
	msg.header.length = htons(sizeof(msg.header) + sizeof(msg.data.state));
	msg.header.type = htons(BFD_STATE_CHANGE);

	/* Prepare payload. */
	msg.data.state.lid = htonl(bs->bs_lid);
	msg.data.state.rid = htonl(bs->bs_rid);
	msg.data.state.state = (uint8_t)bs->bs_state;
	msg.data.state.diagnostics = (uint8_t)bs->bs_rdiag;

	if (bs->bs_rcbit)
		msg.data.state.remote_flags |= RBIT_CPI;
	if (bs->bs_rdemand)
		msg.data.state.remote_flags |= RBIT_DEMAND;

	msg.data.state.remote_flags = htonl(msg.data.state.remote_flags);

	if (bfddp_write_enqueue(bs->bs_bctx, &msg) == 0) {
		plog("state change enqueue failed");
	}
}

/*
 * BFD Protocol.
 */
void
bfd_send_control_packet(const struct bfd_session *bs)
{
	struct bfddp_control_packet cp = {};
	socklen_t salen;
	bool poll = bs->bs_poll;
	uint8_t state = bs->bs_state & 0x03;

	/* Sanity check: don't allow POLL and FINAL in the same packet. */
	if (bs->bs_poll && bs->bs_final) {
		plog("POLL and FINAL enabled at the same time");
		poll = false;
	}

	cp.version_diag = (uint8_t)((1 << 5) | (bs->bs_diag & 0x1F));
	cp.state_bits =
		(uint8_t)((state << 6u)		  /* Current state. */
			  | (poll << 5u)	  /* Poll bit */
			  | (bs->bs_final << 4u)  /* Final bit */
			  | (bs->bs_cbit << 3u)	  /* Control Plane I. bit */
			  | (0 << 2u)		  /* Authentication bit. */
			  | (bs->bs_demand << 1u) /* Demand mode bit */
			  | (0 << 0u));		  /* Multi point bit. */

	cp.detection_multiplier = bs->bs_dmultiplier;
	cp.length = sizeof(cp);
	cp.local_id = htonl(bs->bs_lid);
	cp.remote_id = htonl(bs->bs_rid);

	switch (bs->bs_state) {
	case STATE_ADMINDOWN:
	case STATE_DOWN:
		cp.desired_tx = htonl(bs->bs_cur_tx);
		cp.required_rx = htonl(bs->bs_cur_rx);
		cp.required_echo_rx = htonl(bs->bs_cur_erx);
		break;
	case STATE_INIT:
	case STATE_UP:
		cp.desired_tx = htonl(bs->bs_tx);
		cp.required_rx = htonl(bs->bs_rx);
		cp.required_echo_rx = htonl(bs->bs_erx);
		break;
	}

	if (bs->bs_dst.bs_dst_sa.sa_family == AF_INET)
		salen = sizeof(struct sockaddr_in);
	else
		salen = sizeof(struct sockaddr_in6);

	if (sendto(bs->bs_sock, &cp, cp.length, 0, &bs->bs_dst.bs_dst_sa, salen)
	    <= 0) {
		plog("sendto failed: %s", strerror(errno));
	}
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
bfd_session_extra_check(const struct bfd_session *bs,
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

void
bfd_recv_control_packet(int sock)
{
	struct bfddp_control_packet *bcp;
	struct bfd_session *bs;
	enum bfd_state_value state;
	int plen;
	struct bfd_packet_metadata bpm = {};

	plen = bfd_recv_packet(sock, &bpm);
	/* Assert we have the received the whole packet. */
	if (plen < (int)sizeof(*bcp)) {
		plog("packet read is too small (%d < %zu)", plen, sizeof(*bcp));
		return;
	}

	bcp = (struct bfddp_control_packet *)bpm.bpm_data;
	/* Check packet header length. */
	if (bcp->length < sizeof(*bcp) || bcp->length > plen) {
		plog("invalid packet header length (%d)", plen);
		return;
	}

	/* Invalid detection multiplier. */
	if (bcp->detection_multiplier == 0) {
		plog("invalid packet detection multiplier (%d)",
		     bcp->detection_multiplier);
		return;
	}

	/* Discard multi point packets. */
	if (bcp->state_bits & (STATE_MULTI_BIT)) {
		plog("multi point not implemented");
		return;
	}

	/* Discard sessions using ID zero. */
	if (bcp->local_id == 0) {
		plog("remote session is using ID zero");
		return;
	}

	state = (bcp->state_bits >> 6);
	/* Invalid remote ID with established session. */
	if ((state == STATE_INIT || state == STATE_UP) && bcp->remote_id == 0) {
		plog("remote peer sent bad local session id");
		return;
	}

	/*
	 * If our ID is not set, then we must look up the session using other
	 * packet attributes: source address, peer address, interface etc...
	 *
	 * Otherwise just look up the peer ID and match its address (to avoid
	 * spoofing).
	 */
	if (bcp->remote_id == 0) {
		bs = bfd_session_lookup_by_packet(&bpm);
		if (bs == NULL) {
			plog("session not found");
			return;
		}
	} else {
		bs = bfd_session_lookup(ntohl(bcp->remote_id));
		if (bs == NULL) {
			plog("session for ID %u found", ntohl(bcp->remote_id));
			return;
		}

		/* Make sure we are looking at the correct session. */
		if (bfd_session_extra_check(bs, &bpm) == false) {
			plog("invalid session address");
			return;
		}
	}

	/* Alert about unsupported modes. */
	if (bcp->state_bits & STATE_AUTH_BIT) {
		plog("unsupported authentication mode");
		return;
	}
	if (bcp->state_bits & STATE_DEMAND_BIT) {
		plog("unsupported demand mode");
		return;
	}

	/* Copy remote system status. */
	bs->bs_rstate = state;
	bs->bs_rdiag = bcp->version_diag & 0x1F;
	bs->bs_rid = ntohl(bcp->local_id);
	bs->bs_rtx = ntohl(bcp->desired_tx);
	bs->bs_rrx = ntohl(bcp->required_rx);
	bs->bs_rerx = ntohl(bcp->required_echo_rx);
	bs->bs_rdmultiplier = bcp->detection_multiplier;
	bs->bs_rcbit = !!(bcp->state_bits & STATE_CPI_BIT);
	bs->bs_rdemand = !!(bcp->state_bits & STATE_DEMAND_BIT);

	/* Terminate poll sequence. */
	if (bcp->state_bits & STATE_POLL_BIT) {
		bs->bs_poll = false;
		bs->bs_final = true;

		/* Speed up session convergence. */
		bfd_send_control_packet(bs);
	} else if (bcp->state_bits & STATE_FINAL_BIT) {
		bs->bs_final = false;
		bfd_session_final_event(bs);
	}

	bfd_session_state_machine(bs, bs->bs_rstate);

	/* We received the peer packet, update the expiration timer. */
	bfd_session_update_control_rx(bs);

	/* Handle echo timer not implemented. */
}
