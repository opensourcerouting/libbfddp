/*
 * BFD Data Plane daemon debug functions.
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

#include <arpa/inet.h>

#include <stdarg.h>
#include <stdio.h>

#include "bfddpd.h"

static const char *bfd_session_states[] = {
	"ADMIN DOWN",
	"DOWN",
	"INIT",
	"UP"
};

_Static_assert(sizeof(bfd_session_states)/sizeof(*bfd_session_states) == (STATE_UP + 1),
			   "bfd_session_states[] array item(s) missing!");

static const char *bfd_session_diags[] = {
	"Nothing",
	"Control detection time expired",
	"Echo function failed",
	"Neighbor signaled down",
	"Forwarding plane reset",
	"Path down",
	"Concatenated path down",
	"Administratively down",
	"Reverse concatenated path down"
};

_Static_assert(sizeof(bfd_session_diags)/sizeof(*bfd_session_diags) == (DIAG_REV_CONCAT_PATH_DOWN + 1),
			   "bfd_session_diags[] array item(s) missing!");

void
bfd_session_debug(const struct bfd_session *bs, const char *fmt, ...)
{
	const char *mode;
	int af = bs->bs_dst.bs_dst_sa.sa_family;
	va_list vl;
	uint16_t sport = 0, dport = 0;
	char sbuf[INET6_ADDRSTRLEN] = {}, dbuf[INET6_ADDRSTRLEN] = {};
	char msg[512];

	switch (af) {
	case AF_INET:
		inet_ntop(af, &bs->bs_src.bs_src_sin.sin_addr, sbuf,
			  sizeof(sbuf));
		sport = ntohs(bs->bs_src.bs_src_sin.sin_port);

		inet_ntop(af, &bs->bs_dst.bs_dst_sin.sin_addr, dbuf,
			  sizeof(dbuf));
		dport = ntohs(bs->bs_dst.bs_dst_sin.sin_port);
		break;
	case AF_INET6:
		inet_ntop(af, &bs->bs_src.bs_src_sin6.sin6_addr, sbuf,
			  sizeof(sbuf));
		sport = ntohs(bs->bs_src.bs_src_sin6.sin6_port);

		inet_ntop(af, &bs->bs_dst.bs_dst_sin6.sin6_addr, dbuf,
			  sizeof(dbuf));
		dport = ntohs(bs->bs_dst.bs_dst_sin6.sin6_port);
		break;
	}

	if (bs->bs_multihop)
		mode = "multi hop";
	else
		mode = "single hop";

	va_start(vl, fmt);
	vsnprintf(msg, sizeof(msg), fmt, vl);
	va_end(vl);

	if (bs->bs_ifindex)
		bfddp_log("[%s %s:%d(%s|%d)->%s:%d] %s\n", mode, sbuf, sport,
		          bs->bs_ifname, bs->bs_ifindex, dbuf, dport, msg);
	else
		bfddp_log("[%s %s:%d->%s:%d] %s\n", mode, sbuf, sport, dbuf, dport,
		          msg);
}

void
bfd_session_dump(const struct bfd_session *bs)
{
	bfd_session_debug(
		bs, "%s%s%s%stx,rx,echo[%u,%u,(rx:%u, tx:%u) r:%u,%u,%u] multi[%d, r:%d]",
		bs->bs_passive ? "passive " : "",
		bs->bs_demand ? "demand " : "", bs->bs_cbit ? "cpi " : "",
		bs->bs_echo ? "echo " : "", bs->bs_tx, bs->bs_rx, bs->bs_erx,
		bs->bs_etx, bs->bs_rtx, bs->bs_rrx, bs->bs_rerx,
		bs->bs_dmultiplier, bs->bs_rdmultiplier);
}

const char *bfd_session_get_state_string(enum bfd_state_value state)
{
	if ((state >= STATE_ADMINDOWN) && (state <= STATE_UP)) {
		return bfd_session_states[state];
	} else {
		return "Unknown";
	}
}

const char *bfd_session_get_diag_string(enum bfd_diagnostic_value diag)
{
	if ((diag >= DIAG_NOTHING) && (diag <= DIAG_REV_CONCAT_PATH_DOWN)) {
		return bfd_session_diags[diag];
	} else {
		return "Unknown";
	}
}
