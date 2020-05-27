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

#include <err.h>
#include <sys/time.h>

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
