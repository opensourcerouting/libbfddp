/*
 * BFD data plane daemon header.
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

/**
 * \file bfddpd.h
 */
#ifndef _SOFT_BFDDP_H
#define _SOFT_BFDDP_H

#include <stdbool.h>
#include <stdlib.h>

#include "bfddp.h"

#include "openbsd-tree.h"

/* Forward declarations. */
struct bfd_session;

/*
 * debug.c
 */

/**
 * Call debug message with session info.
 */
void bfd_session_debug(const struct bfd_session *bs, const char *fmt, ...)
	__attribute__((__format__(printf, 2, 3)));

/**
 * Dump all session information.
 */
void bfd_session_dump(const struct bfd_session *bs);

/*
 * events.c.
 */
#ifdef EVENTS_DEBUG
#define dlog(fmt, args...) printf("events: " fmt "\n", ##args)
#else
#define dlog(fmt, args...) /* empty */
#endif /* EVENTS_DEBUG */

/**
 * Events context data structure to help with `poll()`ing.
 */
struct events_ctx
#ifdef DOYXGEN_DOC
{
}
#endif /* DOXYGEN_DOC */
;

/** Auxiliary data structure for keeping timer data. */
struct timer_ctx
#ifdef DOYXGEN_DOC
{
}
#endif /* DOXYGEN_DOC */
;

/**
 * Events context poll callbacks.
 *
 * Return `-1` to remove file descriptor from events context or the events you
 * want to watch now (e.g. `POLLIN`, `POLLOUT`).
 */
typedef int (*events_ctx_cb)(struct events_ctx *ec, int fd, short revents,
			     void *arg);

/**
 * Events context timer poll callbacks.
 *
 * Return `-1` to remove timer from events context or `N` (where `N` >= 0)
 * to schedule it again with the same parameters and next time out in `N`
 * milliseconds.
 */
typedef int64_t (*events_ctx_timer_cb)(struct events_ctx *ec, void *arg);

/**
 * Allocates events context data structure to be used with `bfddp_poll`.
 *
 * \param[in] max_fds maximum number of simulatenous FDs supported.
 *
 * \returns `NULL` on failure or a valid events context.
 *
 * \see
 * events_ctx_poll, events_ctx_add_fd, events_ctx_del_fd, events_ctx_add_timer,
 * events_ctx_del_timer.
 */
struct events_ctx *events_ctx_new(size_t max_fds);

/**
 * Free all memory allocated by events context.
 *
 * \param ec the events context.
 */
void events_ctx_free(struct events_ctx **ec);

/**
 * Runs `poll` and call file descriptors/timers respective callbacks.
 *
 * \param ec the events context.
 *
 * \returns
 * `-1` on untreatable failures, `0` on interruptions or timeouts and
 * `N` for the amount of handled events.
 * If return is `0` and `errno == EINTR` we got interrupted, otherwise it was
 * a timeout.
 *
 * \see
 * events_ctx_add_fd, events_ctx_del_fd, events_ctx_add_timer,
 * events_ctx_del_timer.
 */
int events_ctx_poll(struct events_ctx *ec);

/**
 * Add file descriptor to the events context. A file descriptor can only be
 * added once, second time this function is called with the same `fd` the
 * `events`, `cb` and `arg` get updated.
 *
 * \param ec the events context.
 * \param[in] fd the file descriptor to be monitored.
 * \param[in] events the events you want to monitor (e.g. `POLLIN`, `POLLOUT`).
 * \param[in] cb pointer to callback function.
 * \param[in] arg pointer to argument data (will be used with the callback).
 *
 * \returns `-1` on event queue full or `0` on success.
 *
 * \see events_ctx_del_fd, events_ctx_cb.
 */
int events_ctx_add_fd(struct events_ctx *ec, int fd, short events,
		      events_ctx_cb cb, void *arg);

/**
 * Delete file descriptor to the events context.
 *
 * \param ec the events context.
 * \param[in] fd the file descriptor to be monitored.
 *
 * \see events_ctx_add_fd.
 */
void events_ctx_del_fd(struct events_ctx *ec, int fd);

/**
 * Add wake up timer. Only one timer with the provided parameters can exist,
 * so if you want to use the same callback with the same timeout you must
 * specify a different `arg`.
 *
 * If the same parameters are provided and the timer already existed, it will
 * be updated to expire in `to` milliseconds from now.
 *
 * \param ec the events context.
 * \param to timeout in milliseconds.
 * \param cb time out callback.
 * \param arg pointer to argument (will be passed to callback).
 *
 * \returns
 * `NULL` and `errno != 0` on syscall failures, `NULL` and `errno == 0` on data
 * structure insertion failure or a pointer to the timer context.
 *
 * \see events_ctx_update_timer, events_ctx_del_timer, events_ctx_timer_cb.
 */
struct timer_ctx *events_ctx_add_timer(struct events_ctx *ec, unsigned long to,
					events_ctx_timer_cb cb, void *arg);

/**
 * Update wake up timer. Use the pointer returned by `events_ctx_add_timer` to
 * update the timer's timeout and set it to the return value.
 *
 * \param ec the events context.
 * \param tc timer context.
 * \param to new time out.
 * \param cb new time out callback.
 * \param arg pointer to argument (will be passed to callback).
 *
 * \see events_ctx_add_timer, events_ctx_del_timer, events_ctx_timer_cb.
 */
struct timer_ctx *events_ctx_update_timer(struct events_ctx *ec,
					   struct timer_ctx *tc,
					   unsigned long to,
					   events_ctx_timer_cb cb, void *arg);

/**
 * Remove timer from events context. If `tc` is `NULL` nothing happens.
 *
 * \param ec the events context.
 * \param tc pointer to the timer_ctx pointer.
 *
 * \see events_ctx_update_timer, events_ctx_timer_cb.
 */
void events_ctx_del_timer(struct events_ctx *ec, struct timer_ctx **tc);

/*
 * packet.c
 */
#ifdef PACKET_DEBUG
#define plog(fmt, args...) printf("packet: " fmt "\n", ##args)
#else
#define plog(fmt, args...) /* empty */
#endif /* PACKET_DEBUG */

/* FRR protocol packets. */
void bfddp_send_echo_request(struct bfddp_ctx *bctx);
void bfddp_send_echo_reply(struct bfddp_ctx *bctx, uint64_t bfdd_time);
void bfddp_process_echo_time(const struct bfddp_echo *echo);
void bfddp_send_session_state_change(const struct bfd_session *bs);

/**
 * Sends back to BFD daemon the updated session counters.
 *
 * \param bctx the data plane context to return answer.
 * \param msg the request message.
 */
int bfd_session_reply_counters(struct bfddp_ctx *bctx,
			       const struct bfddp_message *msg);

/* BFD Protocol packets. */
void bfd_send_control_packet(struct bfd_session *bs);

/** Packet read data+metadata. */
struct bfd_packet_metadata {
	/** Source address of the incoming packet. */
	struct sockaddr_in6 bpm_src;
	/** Destination address of the incoming packet. */
	struct sockaddr_in6 bpm_dst;
	/** Packet TTL value. */
	uint8_t bpm_ttl;
	/** Packet interface index. */
	uint32_t bpm_ifindex;

	/** Packet data buffer length. */
	uint16_t bpm_datalen;
	/** Packet data buffer. */
	uint8_t bpm_data[4096];
};

/**
 * Implement 'RFC 5880 Section 6.8.6. Reception of BFD Control Packets'
 * processing. This routine will call the session state machine function.
 *
 * \param sock the BFD UDP listening socket.
 */
void bfd_recv_control_packet(int sock);

/*
 * session.c
 */
#ifdef SESSION_DEBUG
#define slog(fmt, args...) printf("session: " fmt "\n", ##args)
#else
#define slog(fmt, args...) /* empty */
#endif /* SESSION_DEBUG */

/** BFD single hop UDP port, as defined in RFC 5881 Section 4. Encapsulation. */
#define BFD_SINGLE_HOP_PORT 3786

/** BFD multi hop UDP port, as defined in RFC 5883 Section 5. Encapsulation. */
#define BFD_MULTI_HOP_PORT 4784

#define SLOWSTART_DMULT 3
#define SLOWSTART_TX 1000000u
#define SLOWSTART_RX 1000000u
#define SLOWSTART_ERX 0u

/*
 * BFD single hop source UDP ports. As defined in RFC 5881 Section 4.
 * Encapsulation.
 */
#define BFD_SOURCE_PORT_BEGIN 49152
#define BFD_SOURCE_PORT_END 65535

struct bfd_session {
	/** Events context pointer for scheduling timers/fds. */
	struct events_ctx *bs_ec;
	/** BFD Data Plane context for talking with FRR. */
	struct bfddp_ctx *bs_bctx;

	/** BFD Control packet transmission timeout event. */
	struct timer_ctx *bs_txev;
	/** BFD Control packet receive timeout event. */
	struct timer_ctx *bs_rxev;

	/** Peer multiple hop indicator. */
	bool bs_multihop;
	/** Demand mode indicator. */
	bool bs_demand;
	/** Control Plane Indenpendant indicator. */
	bool bs_cbit;
	/** Echo mode indicator. */
	bool bs_echo;
	/** Passive mode indicator. */
	bool bs_passive;
	/** BFD timers poll indicator. */
	bool bs_poll;
	/** BFD final indicator. */
	bool bs_final;

	/** IPv4 address indicator. */
	bool bs_ipv4;
	/** Local address. */
	union {
		struct sockaddr bs_src_sa;
		struct sockaddr_in bs_src_sin;
		struct sockaddr_in6 bs_src_sin6;
	} bs_src;
	/** Remote address. */
	union {
		struct sockaddr bs_dst_sa;
		struct sockaddr_in bs_dst_sin;
		struct sockaddr_in6 bs_dst_sin6;
	} bs_dst;

	/** Local discriminator. */
	uint32_t bs_lid;
	/** Remote discriminator. */
	uint32_t bs_rid;

	/** Desired minimum transmission interval. */
	uint32_t bs_tx;
	/** Current desired minimum transmission interval. */
	uint32_t bs_cur_tx;
	/** Required minimum receive interval. */
	uint32_t bs_rx;
	/** Current required minimum receive interval. */
	uint32_t bs_cur_rx;
	/** Required minimum echo receive interval. */
	uint32_t bs_erx;
	/** Current required minimum echo receive interval. */
	uint32_t bs_cur_erx;
	/** Milliseconds to wait before starting session. */
	uint32_t bs_hold;
	/** Detection multipler. */
	uint8_t bs_dmultiplier;
	/** Currently used detection multipler. */
	uint8_t bs_cur_dmultiplier;

	/** Minimum amount of TTL to expect. */
	uint8_t bs_minttl;

	/** Interface index. */
	uint32_t bs_ifindex;
	/** Interface name. */
	char bs_ifname[64];

	/** Local state. */
	enum bfd_state_value bs_state;
	/** Local diagnostic. */
	enum bfd_diagnostic_value bs_diag;
	/** Remote state. */
	enum bfd_state_value bs_rstate;
	/** Remote diagnostic. */
	enum bfd_diagnostic_value bs_rdiag;

	/** Remote Control Plane Independent bit value. */
	bool bs_rcbit;
	/** Remote Demand mode bit value. */
	bool bs_rdemand;

	/** Remote desired minimum transmission interval. */
	uint32_t bs_rtx;
	/** Remote required minimum receive interval. */
	uint32_t bs_rrx;
	/** Remote required minimum echo receive interval. */
	uint32_t bs_rerx;
	/** Remote detection multipler. */
	uint8_t bs_rdmultiplier;

	/** Session socket. */
	int bs_sock;

	/** Session control packet input counter. */
	uint64_t bs_crx_bytes;
	/** Session control packet bytes input counter. */
	uint64_t bs_crx_packets;
	/** Session control packet output counter. */
	uint64_t bs_ctx_bytes;
	/** Session control packet bytes output counter. */
	uint64_t bs_ctx_packets;

	RBT_ENTRY(bfd_session) entry;
};

/**
 * Session internal data structures initialization.
 */
void bfd_session_init(void);

/**
 * Session internal data structures tear down.
 */
void bfd_session_finish(void);

/**
 * Creates a new BFD session and associates it with the event context `ec`,
 * the FRR BFD instance `bctx` and use the FRR's BFD message
 *
 * \param ec the event context that will handle the session events.
 * \param bctx the FRR BFD data plane to talk to.
 * \param bdps the FRR's BFD message with session information.
 */
struct bfd_session *bfd_session_new(struct events_ctx *ec,
				    struct bfddp_ctx *bctx,
				    const struct bfddp_session *bdps);

/**
 * Update BFD session parameters using FRR's BFD message.
 *
 * \param bs the BFD session.
 * \param bdps FRR's BFD message.
 */
void bfd_session_update(struct bfd_session *bs,
			const struct bfddp_session *bdps);

/**
 * Deletes BFD session using FRR's BFD message information.
 *
 * \param bdps FRR's BFD message.
 */
void bfd_session_delete(const struct bfddp_session *bdps);

/**
 * Look up session using discriminator.
 *
 * \param lid the local discriminator.
 */
struct bfd_session *bfd_session_lookup(uint32_t lid);

/**
 * Look up new session (e.g. without discriminator) for the correct BFD
 * session using the packet metadata.
 *
 * \param bpm the packet metadata.
 */
struct bfd_session *
bfd_session_lookup_by_packet(const struct bfd_packet_metadata *bpm);

/**
 * This function should be called everytime a control packet is received
 * to handle peer state transitions.
 *
 * \param bs the BFD session.
 * \param nstate peer's new state.
 */
void bfd_session_state_machine(struct bfd_session *bs,
			       enum bfd_state_value nstate);

/**
 * This function should be called everytime a control packet is received,
 * it will update the control packet expiration timer.
 *
 * \param bs the BFD session.
 */
void bfd_session_update_control_rx(struct bfd_session *bs);

/**
 * Update transmission timer: call this function when the local desired
 * transmission interval or the remote minimum receive interval changes.
 *
 * \param bs the BFD session.
 */
void bfd_session_update_control_tx(struct bfd_session *bs);

/**
 * This function should be called everytime a control packet is received
 * with the final bit.
 *
 * \param bs the BFD session.
 */
void bfd_session_final_event(struct bfd_session *bs);

#endif /* _SOFT_BFDDP_H */
