/*
 * BFD Data Plane session handling.
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

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "bfddp.h"
#include "bfddp_packet.h"
#include "bfddpd.h"

#include "openbsd-tree.h"

/*
 * BFD Session data structure handling.
 */
static int
bsessions_cmp(const struct bfd_session *bsa, const struct bfd_session *bsb)
{
	return (int)(bsa->bs_lid - bsb->bs_lid);
}

RBT_HEAD(bsessionst, bfd_session) bsessionst;
RBT_PROTOTYPE(bsessionst, bfd_session, entry, bsessions_cmp);
RBT_GENERATE(bsessionst, bfd_session, entry, bsessions_cmp);

/*
 * Helper functions.
 */
static int
sock_set_nonblock(int sock)
{
	int flags;

	flags = fcntl(sock, F_GETFD);
	if (flags == -1)
		return -1;

	if (flags & O_NONBLOCK)
		return 0;

	flags |= O_NONBLOCK;
	if (fcntl(sock, F_SETFD, flags) == -1)
		return -1;

	return 0;
}

static int
bfd_socket(struct sockaddr *sa)
{
	static uint16_t port = BFD_SOURCE_PORT_BEGIN;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
	struct sockaddr_in *sin = (struct sockaddr_in *)sa;
	uint16_t port_start = port;
	int rv, sock, value;

	sock = socket(sa->sa_family, SOCK_DGRAM, 0);
	if (sock == -1) {
		slog("socket: %s", strerror(errno));
		return -1;
	}

	if (sock_set_nonblock(sock) == -1) {
		slog("fcntl: %s", strerror(errno));
		return -1;
	}

	switch (sa->sa_family) {
	case AF_INET:
		/* Set packet TTL. */
		value = 255;
		rv = setsockopt(sock, IPPROTO_IP, IP_TTL, &value,
				sizeof(value));
		if (rv == -1)
			goto close_and_return;

		/* Receive the packet TTL information from `recvmsg`. */
		value = 1;
		rv = setsockopt(sock, IPPROTO_IP, IP_RECVTTL, &value,
				sizeof(value));
		if (rv == -1)
			goto close_and_return;

		/* Receive the interface information from `recvmsg`. */
		value = 1;
		rv = setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &value,
				sizeof(value));
		if (rv == -1)
			goto close_and_return;

		/* Set packet ToS. */
		value = 0xC0 /* CS6 */;
		rv = setsockopt(sock, IPPROTO_IP, IP_TOS, &value,
				sizeof(value));
		if (rv == -1)
			goto close_and_return;

		for (; port != port_start; port++) {
			if (port == BFD_SOURCE_PORT_END)
				port = BFD_SOURCE_PORT_BEGIN;

			sin->sin_port = htons(port);
			if (bind(sock, sa, sizeof(*sin)) == 0)
				break;
		}
		break;
	case AF_INET6:
		/* IPv6 socket for IPv6 peers only, don't try mapped IPv4. */
		value = 1;
		rv = setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &value,
				sizeof(value));
		if (rv == -1)
			goto close_and_return;

		/* Get interface information from `recvmsg`. */
		value = 1;
		rv = setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &value,
				sizeof(value));
		if (rv == -1)
			goto close_and_return;

		/* Set packet TTL. */
		value = 255;
		rv = setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &value,
				sizeof(value));
		if (rv == -1)
			goto close_and_return;

		/* Set packet ToS. */
		value = 0xC0 /* CS6 */;
		rv = setsockopt(sock, IPPROTO_IPV6, IPV6_TCLASS, &value,
				sizeof(value));
		if (rv == -1)
			goto close_and_return;

		/* Receive packet hop count on `recvmsg`. */
		value = 1;
		rv = setsockopt(sock, IPPROTO_IPV6, IPV6_HOPLIMIT, &value,
				sizeof(value));
		if (rv == -1)
			goto close_and_return;

		for (; port != port_start; port++) {
			if (port == BFD_SOURCE_PORT_END)
				port = BFD_SOURCE_PORT_BEGIN;

			sin6->sin6_port = htons(port);
			if (bind(sock, sa, sizeof(*sin6)) == 0)
				break;
		}
		break;

	default:
		goto close_and_return;
	}

	return sock;

close_and_return:
	close(sock);
	return -1;
}


/*
 * Public API.
 */
void
bfd_session_init(void)
{
	RBT_INIT(bsessionst, &bsessionst);
}

static void
bfd_session_free(struct bfd_session *bs)
{
	RBT_REMOVE(bsessionst, &bsessionst, bs);
	events_ctx_del_fd(bs->bs_ec, bs->bs_sock);
	events_ctx_del_timer(bs->bs_ec, &bs->bs_rxev);
	events_ctx_del_timer(bs->bs_ec, &bs->bs_txev);
	close(bs->bs_sock);
	free(bs);
}

void
bfd_session_finish(void)
{
	struct bfd_session *bs;

	while ((bs = RBT_MIN(bsessionst, &bsessionst)) != NULL)
		bfd_session_free(bs);
}

struct bfd_session *
bfd_session_lookup(uint32_t lid)
{
	struct bfd_session bsk;

	bsk.bs_lid = lid;

	return RBT_FIND(bsessionst, &bsessionst, &bsk);
}

struct bfd_session *
bfd_session_lookup_by_packet(const struct bfd_packet_metadata *bpm)
{
	struct sockaddr_in *sin;
	struct bfd_session *bs;

	RBT_FOREACH(bs, bsessionst, &bsessionst) {
		/* Filter by interface (if set). */
		if (bs->bs_ifindex && bs->bs_ifindex != bpm->bpm_ifindex)
			continue;
		/* Filter by address type. */
		if ((bs->bs_ipv4 && bpm->bpm_src.sin6_family != AF_INET)
		    || (!bs->bs_ipv4 && bpm->bpm_src.sin6_family != AF_INET6))
			continue;
		/* Filter by address. */
		if (bs->bs_ipv4) {
			sin = (struct sockaddr_in *)&bpm->bpm_dst;
			if (bs->bs_dst.bs_dst_sin.sin_addr.s_addr
			    != sin->sin_addr.s_addr)
				continue;

			sin = (struct sockaddr_in *)&bpm->bpm_src;
			if (bs->bs_src.bs_src_sin.sin_addr.s_addr
			    && bs->bs_src.bs_src_sin.sin_addr.s_addr
				       != sin->sin_addr.s_addr)
				continue;
		} else {
			if (memcmp(&bs->bs_dst.bs_dst_sin6.sin6_addr,
				   &bpm->bpm_dst.sin6_addr,
				   sizeof(struct in6_addr)))
				continue;
			if (memcmp(&bs->bs_src.bs_src_sin6.sin6_addr,
				   &bpm->bpm_src.sin6_addr,
				   sizeof(struct in6_addr)))
				continue;
		}

		break;
	}

	return bs;
}

void
bfd_session_update(struct bfd_session *bs, const struct bfddp_session *bdps)
{
	struct in_addr *ia;
	uint16_t port;

	/*
	 * Load flags.
	 *
	 * NOTE: normalize boolean values (e.g. `!!`) so packet build functions
	 * can use it with shift (e.g. (multihop << X)).
	 */
	bs->bs_multihop = !!(bdps->flags & SESSION_MULTIHOP);
	bs->bs_passive = !!(bdps->flags & SESSION_PASSIVE);
	bs->bs_demand = !!(bdps->flags & SESSION_DEMAND);
	bs->bs_cbit = !!(bdps->flags & SESSION_CBIT);
	bs->bs_echo = !!(bdps->flags & SESSION_ECHO);

	if (bs->bs_multihop)
		port = htons(BFD_MULTI_HOP_PORT);
	else
		port = htons(BFD_SINGLE_HOP_PORT);

	/* Load addresses. */
	bs->bs_ipv4 = !(bdps->flags & SESSION_IPV6);
	if (bs->bs_ipv4) {
		ia = (struct in_addr *)&bdps->src;
		bs->bs_src.bs_src_sin.sin_family = AF_INET;
		bs->bs_src.bs_src_sin.sin_addr.s_addr = ia->s_addr;

		ia = (struct in_addr *)&bdps->dst;
		bs->bs_dst.bs_dst_sin.sin_family = AF_INET;
		bs->bs_dst.bs_dst_sin.sin_addr.s_addr = ia->s_addr;
		bs->bs_dst.bs_dst_sin.sin_port = port;
	} else {
		bs->bs_src.bs_src_sin6.sin6_family = AF_INET6;
		memcpy(&bs->bs_src.bs_src_sin6.sin6_addr, &bdps->src,
		       sizeof(struct in6_addr));
		if (IN6_IS_ADDR_LINKLOCAL(&bs->bs_src.bs_src_sin6.sin6_addr))
			bs->bs_src.bs_src_sin6.sin6_scope_id = bdps->ifindex;

		bs->bs_dst.bs_dst_sin6.sin6_family = AF_INET6;
		memcpy(&bs->bs_dst.bs_dst_sin6.sin6_addr, &bdps->dst,
		       sizeof(struct in6_addr));
		bs->bs_dst.bs_dst_sin6.sin6_port = port;
		if (IN6_IS_ADDR_LINKLOCAL(&bs->bs_dst.bs_dst_sin6.sin6_addr))
			bs->bs_dst.bs_dst_sin6.sin6_scope_id = bdps->ifindex;
	}

	/* Load timers. */
	bs->bs_tx = ntohl(bdps->min_tx);
	bs->bs_rx = ntohl(bdps->min_rx);
	bs->bs_erx = ntohl(bdps->min_echo_rx);
	bs->bs_hold = ntohl(bdps->hold_time);
	bs->bs_dmultiplier = bdps->detect_mult;

	bs->bs_minttl = bdps->ttl;
	bs->bs_ifindex = ntohl(bdps->ifindex);
	if (bdps->ifname[0])
		snprintf(bs->bs_ifname, sizeof(bs->bs_ifname), "%s",
			 bdps->ifname);

	/* Create socket only if not open or configuration changed. */
	if (bs->bs_sock != -1) {
		bfd_session_debug(bs, "update session");
		bfd_session_dump(bs);
		return;
	}

	bfd_session_debug(bs, "new session");
	bfd_session_dump(bs);

	bs->bs_sock = bfd_socket(&bs->bs_src.bs_src_sa);

	/* Start transmission if not passive mode. */
	bfd_session_update_control_tx(bs);
}

static void
bfd_session_set_slowstart(struct bfd_session *bs)
{
	/* Slow start settings. */
	bs->bs_cur_dmultiplier = SLOWSTART_DMULT;
	bs->bs_cur_tx = SLOWSTART_TX;
	bs->bs_cur_rx = SLOWSTART_RX;
	bs->bs_cur_erx = SLOWSTART_ERX;
}

static void
bfd_session_reset_remote(struct bfd_session *bs)
{
	/* Default remote settings. */
	bs->bs_rdmultiplier = SLOWSTART_DMULT;
	bs->bs_rtx = SLOWSTART_TX;
	bs->bs_rrx = SLOWSTART_RX;
	bs->bs_rerx = SLOWSTART_ERX;
}

struct bfd_session *
bfd_session_new(struct events_ctx *ec, struct bfddp_ctx *bctx,
		const struct bfddp_session *bdps)
{
	struct bfd_session *bs;

	/* Look up session first. */
	bs = bfd_session_lookup(bdps->lid);
	if (bs != NULL) {
		bfd_session_update(bs, bdps);
		return bs;
	}

	/* Create if it doesn't exist. */
	bs = calloc(1, sizeof(*bs));
	if (bs == NULL)
		return NULL;

	/* Copy important pointers. */
	bs->bs_ec = ec;
	bs->bs_bctx = bctx;

	/* Set file descriptor to invalid value. */
	bs->bs_sock = -1;

	/* Local settings. */
	bs->bs_lid = bdps->lid;
	bs->bs_state = STATE_DOWN;
	bfd_session_set_slowstart(bs);

	/* Remote settings. */
	bs->bs_rstate = STATE_DOWN;
	bfd_session_reset_remote(bs);

	bfd_session_update(bs, bdps);

	RBT_INSERT(bsessionst, &bsessionst, bs);

	return bs;
}

static void
bfd_session_sm_admindown(__attribute__((unused)) struct bfd_session *bs,
			 __attribute__((unused)) enum bfd_state_value nstate)
{
	/* NOTHING. */
}

static void
bfd_session_sm_down(struct bfd_session *bs, enum bfd_state_value nstate)
{
	switch (nstate) {
	case STATE_ADMINDOWN:
		/* NOTHING. */
		break;
	case STATE_DOWN:
		bs->bs_state = STATE_INIT;
		bfd_session_debug(bs, "down -> init");
		break;
	case STATE_INIT:
		bs->bs_state = STATE_UP;
		bfd_session_debug(bs, "down -> up");

		/* Start polling. */
		bs->bs_poll = true;
		break;
	case STATE_UP:
		/* NOTHING: we haven't and the peer hasn't sent INIT yet. */
		break;
	}
}

static void
bfd_session_sm_init(struct bfd_session *bs, enum bfd_state_value nstate)
{
	switch (nstate) {
	case STATE_ADMINDOWN:
		bs->bs_state = STATE_DOWN;
		bfd_session_debug(bs, "init -> down");
		break;
	case STATE_DOWN:
		/* We are waiting peer's INIT. */
		break;
	case STATE_INIT:
		/* FALLTHROUGH. */
	case STATE_UP:
		bs->bs_state = STATE_UP;
		bs->bs_diag = 0;
		bfd_session_debug(bs, "init -> up");

		/* Start polling. */
		bs->bs_poll = true;
		break;
	}
}

static void
bfd_session_sm_up(struct bfd_session *bs, enum bfd_state_value nstate)
{
	switch (nstate) {
	case STATE_ADMINDOWN:
		/* FALLTHROUGH. */
	case STATE_DOWN:
		bs->bs_state = STATE_DOWN;

		bfd_session_set_slowstart(bs);
		/* Disable echo timers. */

		bfd_session_debug(bs, "up -> down");
		break;
	case STATE_INIT:
		/* FALLTHROUGH. */
	case STATE_UP:
		/* NOTHING. */
		break;
	}
}

void
bfd_session_state_machine(struct bfd_session *bs, enum bfd_state_value nstate)
{
	switch (bs->bs_state) {
	case STATE_ADMINDOWN:
		bfd_session_sm_admindown(bs, nstate);
		break;
	case STATE_DOWN:
		bfd_session_sm_down(bs, nstate);
		break;
	case STATE_INIT:
		bfd_session_sm_init(bs, nstate);
		break;
	case STATE_UP:
		bfd_session_sm_up(bs, nstate);
		break;
	}
}

static uint32_t
apply_jitter(uint32_t total, bool dm_one)
{
	uint32_t jitter;

	if (dm_one)
		jitter = (uint32_t)(random() % 11);
	else
		jitter = (uint32_t)(random() % 26);

	return total - (total * (jitter / 100));
}

static uint32_t
bfd_session_next_control_tx(struct bfd_session *bs)
{
	uint32_t selected_timer;

	/*
	 * RFC 5880 Section 6.8.7. Transmitting BFD Control Packets:
	 * Select the larger of 'Desired Transmission' and 'Remote Min Recv.'.
	 */
	if (bs->bs_cur_tx > bs->bs_rrx)
		selected_timer = bs->bs_cur_tx;
	else
		selected_timer = bs->bs_rrx;

	return apply_jitter(selected_timer, bs->bs_rdmultiplier == 1);
}

static int64_t
bfd_session_control_tx_timeout(__attribute__((unused)) struct events_ctx *ec,
			       void *arg)
{
	/* Send again. */
	bfd_send_control_packet(arg);

	/* Reschedule timer. */
	return bfd_session_next_control_tx(arg) / 1000;
}

static int64_t
bfd_session_control_rx_timeout(__attribute__((unused)) struct events_ctx *ec,
			       void *arg)
{
	struct bfd_session *bs = arg;

	bfd_session_debug(bs, "control packet receive timeout");

	bfd_session_reset_remote(bs);

	/* Tell FRR's BFD daemon the session is down. */
	bs->bs_state = STATE_DOWN;
	bs->bs_diag = DIAG_CONTROL_EXPIRED;
	bfd_session_set_slowstart(bs);
	bfddp_send_session_state_change(bs);

	/* Remove the timer pointer since we'll get rid of it. */
	bs->bs_rxev = NULL;

	/* Get rid of this timer. */
	return -1;
}

void
bfd_session_update_control_tx(struct bfd_session *bs)
{
	bfd_send_control_packet(bs);

	if (bs->bs_txev)
		bs->bs_txev = events_ctx_update_timer(
			bs->bs_ec, bs->bs_txev,
			bfd_session_next_control_tx(bs) / 1000,
			bfd_session_control_tx_timeout, bs);
	else
		bs->bs_txev = events_ctx_add_timer(
			bs->bs_ec, bfd_session_next_control_tx(bs) / 1000,
			bfd_session_control_tx_timeout, bs);
}

void
bfd_session_update_control_rx(struct bfd_session *bs)
{
	uint32_t next_to;

	/*
	 * RFC 5880 Section 6.8.4. Calculating the Detection Time:
	 *
	 * > In Asynchronous mode, the Detection Time calculated in the local
	 * > system is equal to the value of Detect Mult received from the
	 * > remote system, multiplied by the agreed transmit interval of the
	 * > remote system (the greater of bfd.RequiredMinRxInterval and the
	 * > last received Desired Min TX Interval). The Detect Mult value is
	 * > (roughly speaking, due to jitter) the number of packets that have
	 * > to be missed in a row to declare the session to be down.
	 */
	if (bs->bs_cur_rx > bs->bs_rtx)
		next_to = bs->bs_cur_rx * bs->bs_rdmultiplier;
	else
		next_to = bs->bs_rtx * bs->bs_rdmultiplier;

	if (bs->bs_rxev)
		bs->bs_rxev = events_ctx_update_timer(
			bs->bs_ec, bs->bs_rxev, next_to / 1000,
			bfd_session_control_rx_timeout, bs);
	else
		bs->bs_rxev = events_ctx_add_timer(
			bs->bs_ec, next_to / 1000,
			bfd_session_control_rx_timeout, bs);
}

void
bfd_session_final_event(struct bfd_session *bs)
{
	/* Negotiation ended, apply new intervals. */
	bs->bs_cur_dmultiplier = bs->bs_dmultiplier;
	bs->bs_cur_tx = bs->bs_tx;
	bs->bs_cur_rx = bs->bs_rx;
	bs->bs_cur_erx = bs->bs_erx;

	bfd_session_update_control_rx(bs);
	bfd_session_update_control_tx(bs);

	bfd_session_debug(bs, "final event");
	bfd_session_dump(bs);
}
