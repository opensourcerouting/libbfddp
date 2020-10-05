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

#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "bfddp_extra.h"
#include "bfddpd.h"

/*
 * BFD Session data structure handling.
 */
static int
bsessions_cmp(const struct bfd_session_data *bsda,
	      const struct bfd_session_data *bsdb)
{
	return (int)(bsda->bsd_bs->bs_lid - bsdb->bsd_bs->bs_lid);
}

RBT_HEAD(bsessionst, bfd_session_data) bsessionst;
RBT_PROTOTYPE(bsessionst, bfd_session_data, entry, bsessions_cmp);
RBT_GENERATE(bsessionst, bfd_session_data, entry, bsessions_cmp);

static void bfd_session_update_control_tx(struct bfd_session *bs, void *arg);
static void bfd_session_update_echo_tx(struct bfd_session *bs, void *arg);

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
		goto close_and_return;
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

static int
bfd_session_new(struct bfd_session *bs, __attribute__((unused)) void *arg)
{
	struct events_ctx *ec = arg;
	struct bfd_session_data *bsd;

	/* Sanity check: duplicated session. */
	if (bfd_session_lookup(bs->bs_lid) != NULL) {
		slog("duplicated session detected (lid=%u)", bs->bs_lid);
		return -1;
	}

	/* Create if it doesn't exist. */
	bsd = calloc(1, sizeof(*bsd));
	if (bsd == NULL) {
		slog("not enough memory");
		return -1;
	}

	/* Copy important pointers. */
	bs->bs_data = bsd;
	bsd->bsd_bs = bs;
	bsd->bsd_ec = ec;

	/* Set file descriptor to invalid value. */
	bsd->bsd_sock = -1;

	RBT_INSERT(bsessionst, &bsessionst, bsd);

	return 0;
}

static void
bfd_session_update(struct bfd_session *bs, __attribute__((unused)) void *arg)
{
	struct bfd_session_data *bsd = bs->bs_data;

	/* Create socket only if not open or configuration changed. */
	if (bsd->bsd_sock != -1) {
		bfd_session_debug(bs, "update session");
		bfd_session_dump(bs);
		return;
	}

	bfd_session_debug(bs, "new session");
	bfd_session_dump(bs);

	bsd->bsd_sock = bfd_socket(&bs->bs_src.bs_src_sa);
}

static void
bfd_session_free(struct bfd_session *bs, __attribute__((unused)) void *arg)
{
	struct bfd_session_data *bsd = bs->bs_data;

	RBT_REMOVE(bsessionst, &bsessionst, bsd);
	events_ctx_del_fd(bsd->bsd_ec, bsd->bsd_sock);
	events_ctx_del_timer(bsd->bsd_ec, &bsd->bsd_rxev);
	events_ctx_del_timer(bsd->bsd_ec, &bsd->bsd_txev);

	if (bsd->bsd_sock >= 0)
		close(bsd->bsd_sock);

	free(bsd);
}

static void
bfd_session_control_tx_timeout(__attribute__((unused)) struct events_ctx *ec,
			       void *arg)
{
	bfd_session_update_control_tx(arg, NULL);
}

static void
bfd_session_update_control_tx(struct bfd_session *bs,
			      __attribute__((unused)) void *arg)
{
	struct bfd_session_data *bsd = bs->bs_data;

	bfddp_send_control_packet(bs, arg);

	if (bsd->bsd_txev)
		bsd->bsd_txev = events_ctx_update_timer(
			bsd->bsd_ec, bsd->bsd_txev,
			bfddp_session_next_control_tx_interval(bs, true) / 1000,
			bfd_session_control_tx_timeout, bs);
	else {
		bsd->bsd_txev = events_ctx_add_timer(
			bsd->bsd_ec,
			bfddp_session_next_control_tx_interval(bs, true) / 1000,
			bfd_session_control_tx_timeout, bs);
		events_ctx_keep_timer(bsd->bsd_txev);
	}
}

static void
bfd_session_control_rx_timeout(__attribute__((unused)) struct events_ctx *ec,
			       void *arg)
{
	struct bfd_session *bs = arg;

	bfddp_session_rx_timeout(bs, NULL);

	bfd_session_debug(bs, "control packet receive timeout");
}

static void
bfd_session_stop_control_tx(struct bfd_session *bs,
			    __attribute__((unused)) void *arg)
{
	struct bfd_session_data *bsd = bs->bs_data;

	events_ctx_del_timer(bsd->bsd_ec, &bsd->bsd_txev);
}

static void
bfd_session_update_control_rx(struct bfd_session *bs,
			      __attribute__((unused)) void *arg)
{
	struct bfd_session_data *bsd = bs->bs_data;

	if (bsd->bsd_rxev)
		bsd->bsd_rxev = events_ctx_update_timer(
			bsd->bsd_ec, bsd->bsd_rxev,
			bfddp_session_next_control_rx_interval(bs) / 1000,
			bfd_session_control_rx_timeout, bs);
	else {
		bsd->bsd_rxev = events_ctx_add_timer(
			bsd->bsd_ec,
			bfddp_session_next_control_rx_interval(bs) / 1000,
			bfd_session_control_rx_timeout, bs);
		events_ctx_keep_timer(bsd->bsd_rxev);
	}
}

static void
bfd_session_stop_control_rx(struct bfd_session *bs,
			    __attribute__((unused)) void *arg)
{
	struct bfd_session_data *bsd = bs->bs_data;

	events_ctx_del_timer(bsd->bsd_ec, &bsd->bsd_rxev);
}

static void
bfd_session_state_change(struct bfd_session *bs,
			 __attribute__((unused)) void *arg,
			 enum bfd_state_value ostate,
			 enum bfd_state_value nstate)
{
	struct bfd_session_data *bsd = bs->bs_data;

	if (nstate == STATE_UP)
		bsd->bsd_up_count++;
	else if (ostate == STATE_UP)
		bsd->bsd_down_count++;

	bfd_session_debug(bs, "State changed %s -> %s",
			  bfd_session_get_state_string(ostate),
			  bfd_session_get_state_string(nstate));
	bfd_session_dump(bs);
}

static void
bfd_session_echo_tx_timeout(__attribute__((unused)) struct events_ctx *ec,
			    void *arg)
{
	bfd_session_update_echo_tx(arg, NULL);
}

static void
bfd_session_update_echo_tx(struct bfd_session *bs,
			   __attribute__((unused)) void *arg)
{
	struct bfd_session_data *bsd = bs->bs_data;

	bfddp_send_echo_packet(bs, arg);

	if (bsd->bsd_echo_txev)
		bsd->bsd_echo_txev = events_ctx_update_timer(
			bsd->bsd_ec, bsd->bsd_echo_txev,
			bfddp_session_next_echo_tx_interval(bs, true) / 1000,
			bfd_session_echo_tx_timeout, bs);
	else {
		bsd->bsd_echo_txev = events_ctx_add_timer(
			bsd->bsd_ec,
			bfddp_session_next_echo_tx_interval(bs, true) / 1000,
			bfd_session_echo_tx_timeout, bs);
		events_ctx_keep_timer(bsd->bsd_echo_txev);
	}
}

static void
bfd_session_echo_rx_timeout(__attribute__((unused)) struct events_ctx *ec,
			    void *arg)
{
	struct bfd_session *bs = arg;

	bfddp_session_rx_echo_timeout(bs, arg);

	bfd_session_debug(bs, "echo packet receive timeout");
}

static void
bfd_session_stop_echo_tx(struct bfd_session *bs,
			 __attribute__((unused)) void *arg)
{
	struct bfd_session_data *bsd = bs->bs_data;

	events_ctx_del_timer(bsd->bsd_ec, &bsd->bsd_echo_txev);
}

static void
bfd_session_update_echo_rx(struct bfd_session *bs,
			   __attribute__((unused)) void *arg)
{
	struct bfd_session_data *bsd = bs->bs_data;

	if (bsd->bsd_echo_rxev)
		bsd->bsd_echo_rxev = events_ctx_update_timer(
			bsd->bsd_ec, bsd->bsd_echo_rxev,
			bfddp_session_next_echo_rx_interval(bs) / 1000,
			bfd_session_echo_rx_timeout, bs);
	else {
		bsd->bsd_echo_rxev = events_ctx_add_timer(
			bsd->bsd_ec,
			bfddp_session_next_echo_rx_interval(bs) / 1000,
			bfd_session_echo_rx_timeout, bs);
		events_ctx_keep_timer(bsd->bsd_echo_rxev);
	}
}

static void
bfd_session_stop_echo_rx(struct bfd_session *bs,
			 __attribute__((unused)) void *arg)
{
	struct bfd_session_data *bsd = bs->bs_data;

	events_ctx_del_timer(bsd->bsd_ec, &bsd->bsd_echo_rxev);
}


/*
 * Public API.
 */
void
bfd_session_init(void)
{
	struct bfddp_callbacks bfd_callbacks = {
		.bc_session_new = bfd_session_new,
		.bc_session_update = bfd_session_update,
		.bc_session_free = bfd_session_free,
		.bc_tx_control = bfd_tx_control_cb,
		.bc_tx_control_update = bfd_session_update_control_tx,
		.bc_tx_control_stop = bfd_session_stop_control_tx,
		.bc_rx_control_update = bfd_session_update_control_rx,
		.bc_rx_control_stop = bfd_session_stop_control_rx,
		.bc_state_change = bfd_session_state_change,
		.bc_tx_echo = bfd_tx_echo_cb,
		.bc_tx_echo_update = bfd_session_update_echo_tx,
		.bc_tx_echo_stop = bfd_session_stop_echo_tx,
		.bc_rx_echo_update = bfd_session_update_echo_rx,
		.bc_rx_echo_stop = bfd_session_stop_echo_rx,
	};

	/* Register our callbacks. */
	bfddp_initialize(&bfd_callbacks);

	/* Initialize our session data structure. */
	RBT_INIT(bsessionst, &bsessionst);
}

void
bfd_session_finish(void)
{
	struct bfd_session_data *bsd;
	struct bfd_session *bs;

	/* Free all memory. */
	while ((bsd = RBT_MIN(bsessionst, &bsessionst)) != NULL) {
		bs = bsd->bsd_bs;
		bfddp_session_free(&bs, NULL);
	}
}

struct bfd_session *
bfd_session_lookup(uint32_t lid)
{
	struct bfd_session_data *bsd;
	struct bfd_session_data bsdk;
	struct bfd_session bs;
	struct bfd_session *pbs;

	pbs = bfddp_callbacks.bc_session_lookup(lid);
	if (pbs != NULL)
		return pbs;

	bsdk.bsd_bs = &bs;
	bs.bs_lid = lid;

	bsd = RBT_FIND(bsessionst, &bsessionst, &bsdk);
	if (bsd == NULL)
		return NULL;

	return bsd->bsd_bs;
}

struct bfd_session *
bfd_session_lookup_by_packet(const struct bfd_packet_metadata *bpm)
{
	struct sockaddr_in *sin;
	struct bfd_session *bs;
	struct bfd_session_data *bsd;

	bs = bfddp_callbacks.bc_session_lookup_by_packet(bpm);
	if (bs != NULL)
		return bs;

	RBT_FOREACH(bsd, bsessionst, &bsessionst) {
		bs = bsd->bsd_bs;
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

		return bs;
	}

	return NULL;
}

uint32_t
bfd_session_random(void)
{
	static int initialized = false;

	if (initialized == false) {
		/* Seed the random number generator */
		srandom((uint32_t)time(NULL));
		initialized = true;
	}

	return (uint32_t)random();
}

uint32_t
bfd_session_gen_discriminator(void)
{
	uint32_t discriminator;

	do {
		discriminator = bfd_session_random();
	} while ((discriminator != 0)
		 && (bfd_session_lookup(discriminator) != NULL));

	return discriminator;
}
