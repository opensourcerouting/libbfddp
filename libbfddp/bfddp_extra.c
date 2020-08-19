/*
 * BFD Data Plane library implementation.
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

#include <sys/time.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bfddp_extra.h"

/*
 * Callback handling.
 */

static int
bfddp_session_new_dummy(__attribute__((unused)) struct bfd_session *bs,
			__attribute__((unused)) void *arg)
{
	return 0;
}

static void
bfddp_session_update_dummy(__attribute__((unused)) struct bfd_session *bs,
			   __attribute__((unused)) void *arg)
{
}

static void
bfddp_session_state_change_dummy(
	__attribute__((unused)) struct bfd_session *bs,
	__attribute__((unused)) void *arg,
	__attribute__((unused)) enum bfd_state_value ostate,
	__attribute__((unused)) enum bfd_state_value nstate)
{
}

/* Our selected BFD integration callbacks. */
struct bfddp_callbacks bfddp_callbacks;

void
bfddp_initialize(struct bfddp_callbacks *bc)
{
	bfddp_callbacks = *bc;

	if (bfddp_callbacks.bc_session_new == NULL)
		bfddp_callbacks.bc_session_new = bfddp_session_new_dummy;
	if (bfddp_callbacks.bc_session_update == NULL)
		bfddp_callbacks.bc_session_update = bfddp_session_update_dummy;
	if (bfddp_callbacks.bc_session_free == NULL)
		bfddp_callbacks.bc_session_free = bfddp_session_update_dummy;
	if (bfddp_callbacks.bc_state_change == NULL)
		bfddp_callbacks.bc_state_change =
			bfddp_session_state_change_dummy;

#define CALLBACK_CHECK(cb)                                                     \
	do {                                                                   \
		if (bfddp_callbacks.cb == NULL) {                              \
			fprintf(stderr, "%s: callback " #cb " not set\n",      \
				__func__);                                     \
			exit(1);                                               \
		}                                                              \
	} while (0)

	CALLBACK_CHECK(bc_tx_control);
	CALLBACK_CHECK(bc_tx_control_update);
	CALLBACK_CHECK(bc_tx_control_stop);
	CALLBACK_CHECK(bc_rx_control_update);
	CALLBACK_CHECK(bc_rx_control_stop);

#undef CALLBACK_CHECK
}

/*
 * Session functions.
 */
static void
bfddp_session_set_slowstart(struct bfd_session *bs)
{
	/* Slow start settings. */
	bs->bs_cur_dmultiplier = SLOWSTART_DMULT;
	bs->bs_cur_tx = SLOWSTART_TX;
	bs->bs_cur_rx = SLOWSTART_RX;
	bs->bs_cur_erx = SLOWSTART_ERX;
}

static void
bfddp_session_reset_remote(struct bfd_session *bs)
{
	/* Default remote settings. */
	bs->bs_rdmultiplier = SLOWSTART_DMULT;
	bs->bs_rtx = SLOWSTART_TX;
	bs->bs_rrx = SLOWSTART_RX;
	bs->bs_rerx = SLOWSTART_ERX;
}

void
bfddp_session_update(struct bfd_session *bs, void *arg,
		     const struct bfddp_session *bds)
{
	bool timers_changed = false;
	struct in_addr *ia;
	uint16_t port;
	uint32_t min_rx, min_tx;
	uint32_t flags = ntohl(bds->flags);

	/*
	 * Load flags.
	 *
	 * NOTE: normalize boolean values (e.g. `!!`) so packet build functions
	 * can use it with shift (e.g. (multihop << X)).
	 */
	bs->bs_admin_shutdown = !!(flags & SESSION_SHUTDOWN);
	bs->bs_multihop = !!(flags & SESSION_MULTIHOP);
	bs->bs_passive = !!(flags & SESSION_PASSIVE);
	bs->bs_demand = !!(flags & SESSION_DEMAND);
	bs->bs_cbit = !!(flags & SESSION_CBIT);
	bs->bs_echo = !!(flags & SESSION_ECHO);

	if (bs->bs_multihop)
		port = htons(BFD_MULTI_HOP_PORT);
	else
		port = htons(BFD_SINGLE_HOP_PORT);

	bs->bs_ipv4 = !(bds->flags & SESSION_IPV6);
	if (bs->bs_ipv4) {
		ia = (struct in_addr *)&bds->src;
		bs->bs_src.bs_src_sin.sin_family = AF_INET;
		bs->bs_src.bs_src_sin.sin_addr.s_addr = ia->s_addr;

		ia = (struct in_addr *)&bds->dst;
		bs->bs_dst.bs_dst_sin.sin_family = AF_INET;
		bs->bs_dst.bs_dst_sin.sin_addr.s_addr = ia->s_addr;
		bs->bs_dst.bs_dst_sin.sin_port = port;
	} else {
		bs->bs_src.bs_src_sin6.sin6_family = AF_INET6;
		memcpy(&bs->bs_src.bs_src_sin6.sin6_addr, &bds->src,
		       sizeof(struct in6_addr));
		if (IN6_IS_ADDR_LINKLOCAL(&bs->bs_src.bs_src_sin6.sin6_addr))
			bs->bs_src.bs_src_sin6.sin6_scope_id = bds->ifindex;

		bs->bs_dst.bs_dst_sin6.sin6_family = AF_INET6;
		memcpy(&bs->bs_dst.bs_dst_sin6.sin6_addr, &bds->dst,
		       sizeof(struct in6_addr));
		bs->bs_dst.bs_dst_sin6.sin6_port = port;
		if (IN6_IS_ADDR_LINKLOCAL(&bs->bs_dst.bs_dst_sin6.sin6_addr))
			bs->bs_dst.bs_dst_sin6.sin6_scope_id = bds->ifindex;
	}

	/* Load timers. */
	min_tx = ntohl(bds->min_tx);
	min_rx = ntohl(bds->min_rx);
	if (bs->bs_tx != min_tx || bs->bs_rx != min_rx)
		timers_changed = true;

	bs->bs_tx = min_tx;
	bs->bs_rx = min_rx;
	bs->bs_erx = ntohl(bds->min_echo_rx);
	bs->bs_hold = ntohl(bds->hold_time);
	bs->bs_dmultiplier = bds->detect_mult;

	bs->bs_minttl = bds->ttl;
	bs->bs_ifindex = ntohl(bds->ifindex);
	if (bds->ifname[0])
		snprintf(bs->bs_ifname, sizeof(bs->bs_ifname), "%s",
			 bds->ifname);

	bfddp_callbacks.bc_session_update(bs, arg);

	/* Handle administrative shutdown. */
	if (bs->bs_admin_shutdown) {
		/* Send a control packet to tell we are shutting down. */
		bs->bs_state = STATE_ADMINDOWN;
		bfddp_send_control_packet(bs, arg);

		/* Stop all timers. */
		bfddp_callbacks.bc_rx_control_stop(bs, arg);
		bfddp_callbacks.bc_tx_control_stop(bs, arg);
		return;
	}

	/*
	 * If we were shutdown, then transition between administrative down to
	 * down.
	 */
	if (bs->bs_state == STATE_ADMINDOWN) {
		bs->bs_state = STATE_DOWN;
		/* Notify application about ADMINDOWN transition. */
		bfddp_callbacks.bc_state_change(bs, arg, STATE_ADMINDOWN,
						STATE_DOWN);
	}

	/*
	 * Control plane asked for passive mode: stop sending packets
	 * if the remote peer is down or unknown, otherwise enable it.
	 */
	if (bs->bs_passive && bs->bs_state == STATE_DOWN) {
		bfddp_callbacks.bc_rx_control_stop(bs, arg);
		bfddp_callbacks.bc_tx_control_stop(bs, arg);
		return;
	}

	/*
	 * Timers changes happens when the session is new or the previous
	 * configured interval is different.
	 */
	if (timers_changed && bs->bs_state == STATE_UP)
		bs->bs_poll = true;

	bfddp_callbacks.bc_rx_control_update(bs, arg);
	bfddp_callbacks.bc_tx_control_update(bs, arg);
}

struct bfd_session *
bfddp_session_new(struct bfddp_ctx *bctx, void *arg,
		  const struct bfddp_session *bds)
{
	struct bfd_session *bs;

	bs = calloc(1, sizeof(*bs));
	if (bs == NULL)
		return NULL;

	/* Point to our data plane context. */
	bs->bs_bctx = bctx;

	/* Local settings. */
	bs->bs_lid = ntohl(bds->lid);
	bs->bs_state = STATE_DOWN;
	bfddp_session_set_slowstart(bs);

	/* Remote settings. */
	bs->bs_rstate = STATE_DOWN;
	bfddp_session_reset_remote(bs);

	/* Tell application that it can use our data. */
	if (bfddp_callbacks.bc_session_new(bs, arg) == -1) {
		free(bs);
		return NULL;
	}

	/* Re use the update code. */
	bfddp_session_update(bs, arg, bds);

	return bs;
}

void
bfddp_session_free(struct bfd_session **bs, void *arg)
{
	/* Check if pointer is already NULL. */
	if ((*bs) == NULL)
		return;

	/* Call application `free()` first, then free our data. */
	bfddp_callbacks.bc_session_free(*bs, arg);

	/* Free our resources. */
	free(*bs);
	*bs = NULL;
}

ssize_t
bfddp_send_control_packet(struct bfd_session *bs, void *arg)
{
	struct bfddp_control_packet bcp = {};
	bool poll = bs->bs_poll;
	uint8_t state = bs->bs_state & 0x03;
	ssize_t rv;

	/* Sanity check: don't allow POLL and FINAL in the same packet. */
	if (bs->bs_poll && bs->bs_final)
		poll = false;

	bcp.version_diag = (uint8_t)((1 << 5) | (bs->bs_diag & 0x1F));
	bcp.state_bits =
		(uint8_t)((state << 6u)		  /* Current state. */
			  | (poll << 5u)	  /* Poll bit */
			  | (bs->bs_final << 4u)  /* Final bit */
			  | (bs->bs_cbit << 3u)	  /* Control Plane I. bit */
			  | (0 << 2u)		  /* Authentication bit. */
			  | (bs->bs_demand << 1u) /* Demand mode bit */
			  | (0 << 0u));		  /* Multi point bit. */

	bcp.detection_multiplier = bs->bs_dmultiplier;
	bcp.length = sizeof(bcp);
	bcp.local_id = htonl(bs->bs_lid);
	bcp.remote_id = htonl(bs->bs_rid);

	switch (bs->bs_state) {
	case STATE_ADMINDOWN:
	case STATE_DOWN:
		bcp.desired_tx = htonl(bs->bs_cur_tx);
		bcp.required_rx = htonl(bs->bs_cur_rx);
		bcp.required_echo_rx = htonl(bs->bs_cur_erx);
		break;
	case STATE_INIT:
	case STATE_UP:
		bcp.desired_tx = htonl(bs->bs_tx);
		bcp.required_rx = htonl(bs->bs_rx);
		bcp.required_echo_rx = htonl(bs->bs_erx);
		break;
	}

	rv = bfddp_callbacks.bc_tx_control(bs, arg, &bcp);

	/* Update session output data. */
	if (rv > 0) {
		bs->bs_ctx_bytes += (size_t)rv;
		bs->bs_ctx_packets++;
	}

	return rv;
}

void
bfddp_session_rx_timeout(struct bfd_session *bs, void *arg)
{
	enum bfd_state_value pstate = bs->bs_state;

	bfddp_session_reset_remote(bs);

	/* Tell FRR's BFD daemon the session is down. */
	bs->bs_state = STATE_DOWN;
	bs->bs_diag = bs->bs_rdiag = DIAG_CONTROL_EXPIRED;
	bfddp_session_set_slowstart(bs);

	/* Disable timers if configured for passive mode. */
	if (bs->bs_passive) {
		bfddp_callbacks.bc_rx_control_stop(bs, arg);
		bfddp_callbacks.bc_tx_control_stop(bs, arg);
	}

	/*
	 * Only send notification if state changed.
	 *
	 * This prevents a extra notification in case the remote peer
	 * asked and ceased to send control packets earlier than expiration
	 * timer.
	 */
	if (bs->bs_state != pstate)
		bfddp_send_session_state_change(bs);

	/* Notify application about state change. */
	bfddp_callbacks.bc_state_change(bs, arg, pstate, bs->bs_state);
}

static void
bfddp_session_sm_admindown(__attribute__((unused)) struct bfd_session *bs,
			   __attribute__((unused)) void *arg,
			   __attribute__((unused)) enum bfd_state_value nstate)
{
	/* NOTHING. */
}

static void
bfddp_session_sm_down(struct bfd_session *bs, void *arg,
		      enum bfd_state_value nstate)
{
	switch (nstate) {
	case STATE_ADMINDOWN:
		/* NOTHING. */
		break;
	case STATE_DOWN:
		bs->bs_state = STATE_INIT;

		/* Notify state change. */
		bfddp_send_session_state_change(bs);

		/*
		 * If passive mode we must manually send packet (TX timer is
		 * disabled).
		 */
		if (bs->bs_passive)
			bfddp_send_control_packet(bs, arg);
		break;
	case STATE_INIT:
		bs->bs_state = STATE_UP;

		/* Start polling. */
		bs->bs_poll = true;

		/* Notify state change. */
		bfddp_send_session_state_change(bs);
		break;
	case STATE_UP:
		/* NOTHING: we haven't and the peer hasn't sent INIT yet. */
		break;
	}
}

static void
bfddp_session_sm_init(struct bfd_session *bs, void *arg,
		      enum bfd_state_value nstate)
{
	switch (nstate) {
	case STATE_ADMINDOWN:
		bs->bs_state = STATE_DOWN;

		/* Notify state change. */
		bfddp_send_session_state_change(bs);
		break;
	case STATE_DOWN:
		/*
		 * We are waiting peer's INIT.
		 *
		 * If we are passive, then we must manually respond to this
		 * packet (TX timer is disabled).
		 */
		if (bs->bs_passive)
			bfddp_send_control_packet(bs, arg);
		break;
	case STATE_INIT:
		/* FALLTHROUGH. */
	case STATE_UP:
		bs->bs_state = STATE_UP;
		bs->bs_diag = 0;

		/* Start polling. */
		bs->bs_poll = true;

		/* Notify state change. */
		bfddp_send_session_state_change(bs);
		break;
	}
}

static void
bfddp_session_sm_up(struct bfd_session *bs, __attribute__((unused)) void *arg,
		    enum bfd_state_value nstate)
{
	switch (nstate) {
	case STATE_ADMINDOWN:
		/* FALLTHROUGH. */
	case STATE_DOWN:
		bs->bs_state = STATE_DOWN;

		bfddp_session_set_slowstart(bs);
		/* Disable echo timers. */

		/* Notify state change. */
		bfddp_send_session_state_change(bs);
		break;
	case STATE_INIT:
		/* FALLTHROUGH. */
	case STATE_UP:
		/* NOTHING. */
		break;
	}
}

void
bfddp_session_state_machine(struct bfd_session *bs, void *arg,
			    enum bfd_state_value nstate)
{
	enum bfd_state_value ostate = bs->bs_state;

	switch (ostate) {
	case STATE_ADMINDOWN:
		bfddp_session_sm_admindown(bs, arg, nstate);
		break;
	case STATE_DOWN:
		bfddp_session_sm_down(bs, arg, nstate);
		break;
	case STATE_INIT:
		bfddp_session_sm_init(bs, arg, nstate);
		break;
	case STATE_UP:
		bfddp_session_sm_up(bs, arg, nstate);
		break;
	}

	/* Call application callback to notify about state change. */
	if (ostate != bs->bs_state) {
		/*
		 * If state changed from UP to DOWN and we are in passive mode,
		 * then * we need to disable the RX/TX timers to avoid sending
		 * new control packets.
		 */
		if (bs->bs_passive
		    && (ostate == STATE_UP && bs->bs_state == STATE_DOWN)) {
			bfddp_callbacks.bc_rx_control_stop(bs, arg);
			bfddp_callbacks.bc_tx_control_stop(bs, arg);
		}

		bfddp_callbacks.bc_state_change(bs, arg, ostate, bs->bs_state);
	}
}

enum bfddp_packet_validation
bfddp_session_validate_packet(const struct bfddp_control_packet *bcp,
			      size_t bcplen)
{
	enum bfd_state_value state;
	uint8_t version;

	/* Assert we have the received the whole packet. */
	if (bcplen < (int)sizeof(*bcp))
		return BPV_PACKET_TOO_SMALL;

	/* Check packet header length. */
	if (bcp->length < sizeof(*bcp) || bcp->length > bcplen)
		return BPV_INVALID_LENGTH;

	/* Check version. */
	version = (bcp->version_diag >> 5) & 0x07;
	if (version != BFD_PROTOCOL_VERSION)
		return BPV_INVALID_VERSION;

	/* Invalid detection multiplier. */
	if (bcp->detection_multiplier == 0)
		return BPV_ZERO_MULTIPLIER;

	/* Discard sessions using ID zero. */
	if (bcp->local_id == 0)
		return BPV_ZERO_LOCAL_ID;

	/* Invalid remote ID with established session. */
	state = (bcp->state_bits >> 6);
	if ((state == STATE_INIT || state == STATE_UP) && bcp->remote_id == 0)
		return BPV_INVALID_REMOTE_ID;

	return BPV_OK;
}

void
bfddp_session_rx_packet(struct bfd_session *bs, void *arg,
			const struct bfddp_control_packet *bcp)
{
	enum bfd_state_value state = (bcp->state_bits >> 6);
	bool timers_changed = false;

	/* Update session input data. */
	bs->bs_crx_bytes += sizeof(*bcp);
	bs->bs_crx_packets++;

	/* Copy remote system status. */
	bs->bs_rstate = state;
	bs->bs_rdiag = bcp->version_diag & 0x1F;
	bs->bs_rid = ntohl(bcp->local_id);

	/* Detect timers change: */
	if (ntohl(bcp->desired_tx) != bs->bs_rtx)
		timers_changed = true;
	else if (ntohl(bcp->required_rx) != bs->bs_rrx)
		timers_changed = true;
	else if (ntohl(bcp->required_echo_rx) != bs->bs_rerx)
		timers_changed = true;
	else if (bcp->detection_multiplier != bs->bs_rdmultiplier)
		timers_changed = true;

	bs->bs_rtx = ntohl(bcp->desired_tx);
	bs->bs_rrx = ntohl(bcp->required_rx);
	bs->bs_rerx = ntohl(bcp->required_echo_rx);
	bs->bs_rdmultiplier = bcp->detection_multiplier;
	bs->bs_rcbit = !!(bcp->state_bits & STATE_CPI_BIT);
	bs->bs_rdemand = !!(bcp->state_bits & STATE_DEMAND_BIT);

	/* Skip the rest if this session is shutdown. */
	if (bs->bs_admin_shutdown)
		return;

	/*
	 * RFC 5880 Section 6.8.6. Reception of BFD Control Packets:
	 *
	 * > If a Poll Sequence is being transmitted by the local system
	 * > and the Final (F) bit in the received packet is set, the
	 * > Poll Sequence MUST be terminated.
	 */
	if (bs->bs_poll && (bcp->state_bits & STATE_FINAL_BIT)) {
		bs->bs_poll = false;
		bs->bs_final = false;

		/* Negotiation ended, apply new intervals. */
		bs->bs_cur_dmultiplier = bs->bs_dmultiplier;
		bs->bs_cur_tx = bs->bs_tx;
		bs->bs_cur_rx = bs->bs_rx;
		bs->bs_cur_erx = bs->bs_erx;

		/* Tell control plane about timers change. */
		bfddp_send_session_state_change(bs);
	} else {
		if (timers_changed) {
			/*
			 * Notify control plane about new timers if this is not
			 * the final event.
			 */
			bfddp_send_session_state_change(bs);

			/*
			 * Update transmission timer to avoid session
			 * disruption.
			 *
			 * NOTE:
			 * Receive timer update will be called later this
			 * function.
			 */
			bfddp_callbacks.bc_tx_control_update(bs, arg);
		}
	}

	/*
	 * RFC 5880 Section 6.8.6. Reception of BFD Control Packets:
	 *
	 * > If the Poll (P) bit is set, send a BFD Control packet to the
	 * > remote system with the Poll (P) bit clear, and the Final (F)
	 * > bit set (see section 6.8.7).
	 */
	if (bcp->state_bits & STATE_POLL_BIT) {
		bs->bs_poll = false;
		bs->bs_final = true;

		/* Speed up session convergence. */
		bfddp_send_control_packet(bs, arg);

		bs->bs_final = false;
	}

	bfddp_session_state_machine(bs, arg, bs->bs_rstate);

	/* We received the peer packet, update the expiration timer. */
	bfddp_callbacks.bc_rx_control_update(bs, arg);

	/* Handle echo timer not implemented. */
}

/*
 * FRR BFD communication functions.
 */
size_t
bfddp_send_echo_request(struct bfddp_ctx *bctx)
{
	struct bfddp_message msg = {};
	struct timeval tv;

	/* Prepare header. */
	msg.header.version = BFD_DP_VERSION;
	msg.header.length = htons(sizeof(struct bfddp_message_header)
				  + sizeof(struct bfddp_echo));
	msg.header.type = htons(ECHO_REQUEST);

	/* Payload data. */
	gettimeofday(&tv, NULL);
	msg.data.echo.dp_time =
		hu64tonu64((uint64_t)((tv.tv_sec * 1000000) + tv.tv_usec));

	return bfddp_write_enqueue(bctx, &msg);
}

size_t
bfddp_send_echo_reply(struct bfddp_ctx *bctx, uint64_t bfdd_time)
{
	struct bfddp_message msg = {};
	struct timeval tv;

	/* Prepare header. */
	msg.header.version = BFD_DP_VERSION;
	msg.header.length = htons(sizeof(struct bfddp_message_header)
				  + sizeof(struct bfddp_echo));
	msg.header.type = htons(ECHO_REPLY);

	/* Payload data. */
	gettimeofday(&tv, NULL);
	msg.data.echo.dp_time =
		hu64tonu64((uint64_t)((tv.tv_sec * 1000000) + tv.tv_usec));
	msg.data.echo.bfdd_time = bfdd_time;

	return bfddp_write_enqueue(bctx, &msg);
}

size_t
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
	msg.data.state.detection_multiplier = bs->bs_rdmultiplier;
	msg.data.state.desired_tx = htonl(bs->bs_rtx);
	msg.data.state.required_rx = htonl(bs->bs_rrx);
	msg.data.state.required_echo_rx = htonl(bs->bs_rerx);

	if (bs->bs_rcbit)
		msg.data.state.remote_flags |= RBIT_CPI;
	if (bs->bs_rdemand)
		msg.data.state.remote_flags |= RBIT_DEMAND;

	msg.data.state.remote_flags = htonl(msg.data.state.remote_flags);

	return bfddp_write_enqueue(bs->bs_bctx, &msg);
}

size_t
bfddp_session_reply_counters(struct bfddp_ctx *bctx, uint16_t id,
			     const struct bfd_session *bs)
{
	struct bfddp_message rmsg = {};
	uint16_t msglen =
		sizeof(rmsg.header) + sizeof(rmsg.data.session_counters);

	/* Fill in message header. */
	rmsg.header.version = BFD_DP_VERSION;
	rmsg.header.length = htons(msglen);
	rmsg.header.type = htons(BFD_SESSION_COUNTERS);
	rmsg.header.id = id;

	/* Failed to find session. */
	if (bs == NULL) {
		/* Send answer anyway so it doesn't wait forever. */
		return bfddp_write_enqueue(bctx, &rmsg);
	}

	/* Fill payload. */
	rmsg.data.session_counters.control_input_bytes =
		hu64tonu64(bs->bs_crx_bytes);
	rmsg.data.session_counters.control_input_packets =
		hu64tonu64(bs->bs_crx_packets);
	rmsg.data.session_counters.control_output_bytes =
		hu64tonu64(bs->bs_ctx_bytes);
	rmsg.data.session_counters.control_output_packets =
		hu64tonu64(bs->bs_ctx_packets);

	return bfddp_write_enqueue(bs->bs_bctx, &rmsg);
}

/*
 * Misc functions.
 */
uint64_t
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

uint64_t
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

uint32_t
bfddp_session_next_control_tx_interval(struct bfd_session *bs, bool add_jitter)
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

	if (add_jitter)
		return apply_jitter(selected_timer, bs->bs_rdmultiplier == 1);

	return selected_timer;
}

uint32_t
bfddp_session_next_control_rx_interval(struct bfd_session *bs)
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
	 *
	 * Extra bit: wait for polling to end before start using the requested
	 * intervals.
	 */
	if ((bs->bs_cur_rx > bs->bs_rtx) || bs->bs_poll)
		next_to = bs->bs_cur_rx * bs->bs_rdmultiplier;
	else
		next_to = bs->bs_rtx * bs->bs_rdmultiplier;

	return next_to;
}
