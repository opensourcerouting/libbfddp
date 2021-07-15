/*
 * BFD Data Plane library extra functions.
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
 * \file bfddp_extra.h
 */
#ifndef BFDDP_EXTRA_H
#define BFDDP_EXTRA_H

#include <netinet/in.h>
#include <sys/socket.h>

#include <stdbool.h>
#include <stdint.h>

#include "bfddp.h"
#include "bfddp_packet.h"

LIBBFDDP_BEGIN_DECLS

/** The BFD session structure for holding information. */
struct bfd_session {
	/** Peer multiple hop indicator. */
	bool bs_multihop;
	/** Demand mode indicator. */
	bool bs_demand;
	/** Control Plane Independent indicator. */
	bool bs_cbit;
	/** Echo mode indicator. */
	bool bs_echo;
	/** Passive mode indicator. */
	bool bs_passive;
	/** BFD timers poll indicator. */
	bool bs_poll;
	/** BFD final indicator. */
	bool bs_final;
	/** BFD administrative shutdown state. */
	bool bs_admin_shutdown;

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
	/** Required minimum echo receive interval. */
	uint32_t bs_etx;
	/** Milliseconds to wait before starting session. */
	uint32_t bs_hold;
	/** Detection multiplier. */
	uint8_t bs_dmultiplier;
	/** Currently used detection multiplier. */
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
	/** Remote detection multiplier. */
	uint8_t bs_rdmultiplier;

	/** Session control packet bytes input counter. */
	uint64_t bs_crx_bytes;
	/** Session control packet input counter. */
	uint64_t bs_crx_packets;
	/** Session control packet bytes output counter. */
	uint64_t bs_ctx_bytes;
	/** Session control packet output counter. */
	uint64_t bs_ctx_packets;
	/** Number of times this session went UP */
	uint64_t bs_up_count;
	/** Number of times this session went DOWN */
	uint64_t bs_down_count;
	/** Session echo packet bytes input counter. */
	uint64_t bs_erx_bytes;
	/** Session echo packet input counter. */
	uint64_t bs_erx_packets;
	/** Session echo packet bytes output counter. */
	uint64_t bs_etx_bytes;
	/** Session echo packet output counter. */
	uint64_t bs_etx_packets;

	/** Data plane context we belong to. */
	struct bfddp_ctx *bs_bctx;

	/** Implementation dependent data. */
	void *bs_data;
};


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


/*
 * Callbacks.
 */

/**
 * BFD session creation callback: use it to attach your application data
 * to session without adding boiler plate code. Use `bs_data` to store your
 * private data.
 *
 * The session will contain no configuration, use `bfddp_session_update_cb`
 * callback to handle configuration changes.
 *
 * Return failure if something fatal happened to avoid moving forward with the
 * session setup.
 *
 * \param bs the newly create BFD session (empty/no configurations).
 * \param arg application argument.
 *
 * \returns `-1` on failure otherwise `0`.
 */
typedef int (*bfddp_session_new_cb)(struct bfd_session *bs, void *arg);

/**
 * BFD session update callback: called every time FRR BFD updates the
 * session configurations.
 *
 * The appropriated timers callback will be called depending on the
 * configuration coming from FRR: shutdown disables all timers, passive
 * disables timer if the session is down and so on.
 *
 * \param bs the updated BFD session.
 * \param arg application argument.
 */
typedef void (*bfddp_session_update_cb)(struct bfd_session *bs, void *arg);

/**
 * BFD session deletion callback: use it to detach your application data from
 * session.
 *
 * \param bs BFD session being removed.
 * \param arg application argument.
 */
typedef void (*bfddp_session_free_cb)(struct bfd_session *bs, void *arg);

/**
 * BFD control packet transmission callback. Implements the lower level
 * details of sending the packet (e.g. using a socket or writing into hardware
 * memory).
 *
 * \param bs the BFD session.
 * \param arg application argument.
 * \param bcp the BFD control packet ready to be sent.
 *
 * \returns `-1` or `0` on failure otherwise the number of bytes to account.
 */
typedef ssize_t (*bfddp_tx_control_cb)(struct bfd_session *bs, void *arg,
				       const struct bfddp_control_packet *bcp);

/**
 * Add or update session control packet transmission timer.
 *
 * This is called when the BFD protocol state machine requires the packet to be
 * transmitted and start a transmission timer. It will only be called again to
 * update the transmission timers to a new negotiated interval.
 *
 * The packet sending and retriggering of the timer must be done by the
 * application since the library has no knowledge about timers.
 *
 * \param bs the BFD session.
 * \param arg application argument.
 */
typedef void (*bfddp_tx_control_update_cb)(struct bfd_session *bs, void *arg);

/**
 * Stop session control packet transmission timer.
 *
 * This is called when the BFD protocol state machine wants to stop
 * transmitting new control packets.
 *
 * \param bs the BFD session.
 * \param arg application argument.
 */
typedef void (*bfddp_tx_control_stop_cb)(struct bfd_session *bs, void *arg);

/**
 * Add or update session receive control packet timer.
 *
 * This is called every time the state machine wants to know if a control
 * packet timeout will expire. This function will be called often, basically
 * every time the application receives a BFD control packet with
 * `bfddp_session_rx_packet`.
 *
 * The application must call `bfddp_session_rx_timeout` if the timer expired.
 *
 * \param bs the BFD session.
 * \param arg application argument.
 */
typedef void (*bfddp_rx_control_update_cb)(struct bfd_session *bs, void *arg);

/**
 * Stop session receive control packet timer.
 *
 * This is called when the BFD protocol state machine wants to stop receiving
 * `bfddp_session_rx_timeout` notifications.
 *
 * \param bs the BFD session.
 * \param arg application argument.
 */
typedef void (*bfddp_rx_control_stop_cb)(struct bfd_session *bs, void *arg);

/**
 * BFD state change: it is called every time the session state changes.
 *
 * \param bs the BFD session.
 * \param arg application argument.
 * \param ostate the old BFD session state.
 * \param nstate the new BFD session state.
 */
typedef void (*bfddp_state_change_cb)(struct bfd_session *bs, void *arg,
				      enum bfd_state_value ostate,
				      enum bfd_state_value nstate);

/**
 * BFD session lookup by discrimiator callback: use it to lookup the session
 * in your application.
 *
 * \param lid The local discriminator ID.
 */
typedef struct bfd_session *(*bfddp_session_lookup_cb)(uint32_t lid);

/**
 * BFD session lookup by packet callback: use it to lookup the session
 * in your application.
 *
 * \param bpm The bfd packet data.
 */
typedef struct bfd_session *(*bfddp_session_lookup_by_packet_cb)(
	const struct bfd_packet_metadata *bpm);

/**
 * BFD send state change: it is called every time the control plane must be
 * notified of a session change.
 *
 * \param bs the BFD session.
 */
typedef size_t (*bfddp_send_session_state_change_cb)(
	const struct bfd_session *bs);

/**
 * BFD echo packet transmission callback. Implements the lower level
 * details of sending the packet (e.g. using a socket or writing into hardware
 * memory).
 *
 * \param bs the BFD session.
 * \param arg application argument.
 * \param bep the BFD echo packet ready to be sent.
 *
 * \returns `-1` or `0` on failure otherwise the number of bytes to account.
 */
typedef ssize_t (*bfddp_tx_echo_cb)(struct bfd_session *bs, void *arg,
				    const struct bfddp_echo_packet *bcp);

/**
 * Add or update session echo packet transmission timer.
 *
 * This is called when the BFD protocol state machine requires the packet to be
 * transmitted and start a transmission timer. It will only be called again to
 * update the transmission timers to a new negotiated interval.
 *
 * The packet sending and retriggering of the timer must be done by the
 * application since the library has no knowledge about timers.
 *
 * \param bs the BFD session.
 * \param arg application argument.
 */
typedef void (*bfddp_tx_echo_update_cb)(struct bfd_session *bs, void *arg);

/**
 * Stop session echo packet transmission timer.
 *
 * This is called when the BFD protocol state machine wants to stop
 * transmitting new echo packets.
 *
 * \param bs the BFD session.
 * \param arg application argument.
 */
typedef void (*bfddp_tx_echo_stop_cb)(struct bfd_session *bs, void *arg);

/**
 * Add or update session receive echo packet timer.
 *
 * This is called every time the state machine wants to know if an echo
 * packet timeout will expire. This function will be called often, basically
 * every time the application receives a BFD echo packet with
 * `bfddp_session_rx_echo_packet`.
 *
 * The application must call `bfddp_session_echo_rx_timeout` if the timer
 * expired.
 *
 * \param bs the BFD session.
 * \param arg application argument.
 */
typedef void (*bfddp_rx_echo_update_cb)(struct bfd_session *bs, void *arg);

/**
 * Stop session receive echo packet timer.
 *
 * This is called when the BFD protocol state machine wants to stop receiving
 * `bfddp_session_echo_rx_timeout` notifications.
 *
 * \param bs the BFD session.
 * \param arg application argument.
 */
typedef void (*bfddp_rx_echo_stop_cb)(struct bfd_session *bs, void *arg);

/** The BFD data plane callbacks.  */
struct bfddp_callbacks {
	/** Optional callback. */
	bfddp_session_new_cb bc_session_new;
	/** Optional callback. */
	bfddp_session_update_cb bc_session_update;
	/** Optional callback. */
	bfddp_session_free_cb bc_session_free;
	/** Optional callback. */
	bfddp_session_lookup_cb bc_session_lookup;
	/** Optional callback. */
	bfddp_session_lookup_by_packet_cb bc_session_lookup_by_packet;
	/** Optional callback. */
	bfddp_send_session_state_change_cb bc_send_session_state_change;

	/** Mandatory callback. */
	bfddp_tx_control_cb bc_tx_control;
	/** Mandatory callback. */
	bfddp_tx_control_update_cb bc_tx_control_update;
	/** Mandatory callback. */
	bfddp_tx_control_stop_cb bc_tx_control_stop;

	/** Mandatory callback. */
	bfddp_rx_control_update_cb bc_rx_control_update;
	/** Mandatory callback. */
	bfddp_rx_control_stop_cb bc_rx_control_stop;

	/** Optional callback. */
	bfddp_state_change_cb bc_state_change;

	/** Mandatory callback. */
	bfddp_tx_echo_cb bc_tx_echo;
	/** Mandatory callback. */
	bfddp_tx_echo_update_cb bc_tx_echo_update;
	/** Mandatory callback. */
	bfddp_tx_echo_stop_cb bc_tx_echo_stop;
	/** Mandatory callback. */
	bfddp_rx_echo_update_cb bc_rx_echo_update;
	/** Mandatory callback. */
	bfddp_rx_echo_stop_cb bc_rx_echo_stop;
};

/**
 * Set the library callbacks.
 *
 * \param bc the callbacks structure filled.
 */
void bfddp_initialize(struct bfddp_callbacks *bc);

extern struct bfddp_callbacks bfddp_callbacks;

/*
 * BFD implementation functions.
 */

/**
 * Allocates a new session data structure with the information that came from
 * FRR's BFD daemon.
 *
 * \param bctx FRR BFD data plane to talk to.
 * \param arg application argument.
 * \param bds BFD session message contents.
 */
struct bfd_session *bfddp_session_new(struct bfddp_ctx *bctx, void *arg,
				      const struct bfddp_session *bds);

/**
 * Allocates a new session data structure with the information that came from
 * FRR's BFD daemon.
 *
 * \param bs the BFD session.
 * \param arg application argument.
 * \param bds the BFD message.
 */
void bfddp_session_update(struct bfd_session *bs, void *arg,
			  const struct bfddp_session *bds);

/**
 * Allocates a new session data structure with the information that came from
 * FRR's BFD daemon.
 *
 * \param bs the BFD session.
 * \param arg application argument.
 */
void bfddp_session_free(struct bfd_session **bs, void *arg);

/**
 * Fill the BFD control packet with the information present in the session data
 * structure.
 *
 * \param bs the BFD session.
 * \param bcp the control packet buffer.
 */
void bfddp_fill_control_packet(const struct bfd_session *bs,
			       struct bfddp_control_packet *bcp);

/**
 * Sends a control packet using the session current state for generating
 * the packet. Packet modifications and others may be done before sending
 * the packet with the `bfddp_tx_control` callback.
 *
 * \param bs the BFD session.
 * \param arg application argument.
 *
 * \returns the callback return value.
 */
ssize_t bfddp_send_control_packet(struct bfd_session *bs, void *arg);

/**
 * Function that should be called when the session receive timer expires.
 *
 * \param bs the BFD session.
 * \param arg application argument.
 */
void bfddp_session_rx_timeout(struct bfd_session *bs, void *arg);

/**
 * Fill the BFD echo packet with the information present in the session data
 * structure.
 *
 * \param bs the BFD session.
 * \param bep the echo packet buffer.
 */
void bfddp_fill_echo_packet(const struct bfd_session *bs,
			    struct bfddp_echo_packet *bep);

/**
 * Sends an echo packet using the session current state for generating
 * the packet. Packet modifications and others may be done before sending
 * the packet with the `bfddp_tx_control` callback.
 *
 * \param bs the BFD session.
 * \param arg application argument.
 *
 * \returns the callback return value.
 */
ssize_t bfddp_send_echo_packet(struct bfd_session *bs, void *arg);

/**
 * Function that should be called when the session echo receive timer expires.
 *
 * \param bs the BFD session.
 * \param arg application argument.
 */
void bfddp_session_rx_echo_timeout(struct bfd_session *bs, void *arg);

/**
 * Call this function when you want to change the peer state.
 *
 * \param bs the BFD session to change state.
 * \param arg application argument.
 * \param nstate new session state.
 */
void bfddp_session_state_machine(struct bfd_session *bs, void *arg,
				 enum bfd_state_value nstate);

/** BFD initial packet validation. */
enum bfddp_packet_validation {
	/** Packet is valid. */
	BPV_OK = 0,
	/** Received packet is too small. */
	BPV_PACKET_TOO_SMALL,
	/** Invalid BFD header version field. */
	BPV_INVALID_VERSION,
	/** Packet header length has invalid value. */
	BPV_INVALID_LENGTH,
	/** Detection multiplier is set to zero. */
	BPV_ZERO_MULTIPLIER,
	/** Local ID (the peer's ID) is set to zero. */
	BPV_ZERO_LOCAL_ID,
	/** State is INIT or UP, but the remote system hasn't learned our ID. */
	BPV_INVALID_REMOTE_ID,
};

/**
 * Validate the packet before attempting to access its fields.
 *
 * \param bcp the packet binary.
 * \param bcplen the packet binary size.
 *
 * \returns one of the values of `bfddp_packet_validation`.
 */
enum bfddp_packet_validation
bfddp_session_validate_packet(const struct bfddp_control_packet *bcp,
			      size_t bcplen);

/**
 * Validate the packet before attempting to access its fields.
 *
 * \param bep the packet binary.
 * \param beplen the packet binary size.
 *
 * \returns one of the values of `bfddp_packet_validation`.
 */
enum bfddp_packet_validation
bfddp_session_validate_echo_packet(const struct bfddp_echo_packet *bep,
				   size_t beplen);

/** BFD control packet session validation results. */
enum bfddp_packet_validation_extra {
	/** Everything is fine. */
	BPVE_OK = 0,
	/** Invalid remote ID (our ID) discriminator. */
	BPVE_REMOTE_ID_INVALID,
	/** Authentication set, but not configured. */
	BPVE_UNEXPECTED_AUTH,
	/** Multi bit set, but not configured. */
	BPVE_UNEXPECTED_MULTI,
	/** Authentication not set, but configured. */
	BPVE_AUTH_MISSING,
	/** Authentication set, configured but different. */
	BPVE_AUTH_INVALID,
};

/**
 * Function that should be called when the session receives a control packet.
 *
 * \param bs the BFD session.
 * \param arg application argument.
 * \param bcp the BFD control packet.
 */
enum bfddp_packet_validation_extra
bfddp_session_rx_packet(struct bfd_session *bs, void *arg,
			const struct bfddp_control_packet *bcp);

/**
 * Function that should be called when the session receives an echo packet.
 *
 * \param bs the BFD session.
 * \param arg application argument.
 * \param bep the BFD echo packet.
 */
void bfddp_session_rx_echo_packet(struct bfd_session *bs, void *arg,
				  const struct bfddp_echo_packet *bep);

/*
 * Control plane helper functions.
 */

/**
 * Send echo request to control plane.
 *
 * \param bctx the FRR BFD control plane to talk to.
 *
 * \returns `bfddp_write_enqueue` result.
 */
size_t bfddp_send_echo_request(struct bfddp_ctx *bctx);

/**
 * Send echo reply to control plane.
 *
 * \param bctx the FRR BFD control plane to talk to.
 * \param bfdd_time the FRR BFD time it measured.
 *
 * \returns `bfddp_write_enqueue` result.
 */
size_t bfddp_send_echo_reply(struct bfddp_ctx *bctx, uint64_t bfdd_time);

/**
 * Send session state change to control plane.
 *
 * \param bs the BFD session.
 *
 * \returns `bfddp_write_enqueue` result.
 */
size_t bfddp_send_session_state_change(const struct bfd_session *bs);

/**
 * Send session counters in reply to control plane.
 *
 * \param bctx the FRR BFD control plane to talk to.
 * \param id the message ID to reply to.
 * \param bs the BFD session (may be `NULL` if not found).
 *
 * \returns `bfddp_write_enqueue` result.
 */
size_t bfddp_session_reply_counters(struct bfddp_ctx *bctx, uint16_t id,
				    const struct bfd_session *bs);


/*
 * Misc functions.
 */

/**
 * Generate next send interval timeout.
 *
 * \param bs the BFD session to get the negotiated intervals.
 * \param add_jitter apply jitter to the calculated interval (usually this
 * is required to avoid sessions packet synchronization).
 *
 * \returns interval until next transmission in microseconds.
 */
uint32_t bfddp_session_next_control_tx_interval(struct bfd_session *bs,
						bool add_jitter);

/**
 * Generate next echo receive expiration interval timeout.
 *
 * \param bs the BFD session to get the negotiated intervals.
 *
 * \returns interval until next receive expiration in microseconds.
 */
uint32_t bfddp_session_next_echo_rx_interval(struct bfd_session *bs);

/**
 * Generate next echo send interval timeout.
 *
 * \param bs the BFD session to get the negotiated intervals.
 * \param add_jitter apply jitter to the calculated interval (usually this
 * is required to avoid sessions packet synchronization).
 *
 * \returns interval until next transmission in microseconds.
 */
uint32_t bfddp_session_next_echo_tx_interval(struct bfd_session *bs,
					     bool add_jitter);

/**
 * Generate next receive expiration interval timeout.
 *
 * \param bs the BFD session to get the negotiated intervals.
 *
 * \returns interval until next receive expiration in microseconds.
 */
uint32_t bfddp_session_next_control_rx_interval(struct bfd_session *bs);

LIBBFDDP_END_DECLS

#endif /* BFDDP_EXTRA_H */
