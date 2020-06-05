/*
 * Event manager implementation.
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

#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <time.h>

#include "openbsd-tree.h"

#include "bfddpd.h"

/** Auxiliary data structure for pollfd to keep arguments. */
struct pollfd_ctx {
	/** The `pollfd` itself. */
	struct pollfd *pfc_pf;
	/** The event callback. */
	events_ctx_cb pfc_cb;
	/** The `pollfd` argument. */
	void *pfc_arg;
};

/** Auxiliary data structure for keeping timer data. */
struct timer_ctx {
	/** User expire time argument. */
	unsigned long tc_to;
	/** Calculated time in microseconds to wait. */
	uint64_t tc_toc;
	/** The event callback. */
	events_ctx_timer_cb tc_cb;
	/** The `pollfd` argument. */
	void *tc_arg;

	/** Tree entry. */
	RBT_ENTRY(timer_ctx) entry;
};

/* Declare timers tree type. */
RBT_HEAD(timerst, timer_ctx);

struct events_ctx {
	/** Dynamically allocated poll file descriptors. */
	struct pollfd *ec_pfds;
	/** Dynamically allocated poll file descriptors context. */
	struct pollfd_ctx *ec_pfdcs;
	/** Amount of total available file descriptors. */
	nfds_t ec_pfds_total;
	/** Amount of used file descriptors. */
	nfds_t ec_pfds_used;

	/** Timers tree. */
	struct timerst ec_timerst;
	/** Current time cache. */
	struct timespec ec_tv;
	/** Next timer to timeout in milliseconds. */
	int ec_to;
};

static int
timerst_cmp(const struct timer_ctx *tca, const struct timer_ctx *tcb)
{
	/* Organize by clock first. */
	if (tca->tc_toc < tcb->tc_toc)
		return -1;
	else if (tca->tc_toc > tcb->tc_toc)
		return 1;

	/* Then by timeouts, callbacks and args. */
	if (tca->tc_to == tcb->tc_to) {
		if (tca->tc_cb == tcb->tc_cb)
			return (int)((long)tca->tc_arg - (long)tcb->tc_arg);
		else
			return (int)((long)tca->tc_cb - (long)tcb->tc_cb);
	} else
		return (int)(tca->tc_to - tcb->tc_to);
}

RBT_PROTOTYPE(timerst, timer_ctx, entry, timerst_cmp);
RBT_GENERATE(timerst, timer_ctx, entry, timerst_cmp);

struct events_ctx *
events_ctx_new(size_t max_fds)
{
	struct events_ctx *ec;
	struct pollfd *pfds;
	struct pollfd_ctx *pfdcs;
	int i;

	pfds = calloc(max_fds, sizeof(*pfds));
	if (pfds == NULL)
		return NULL;

	pfdcs = calloc(max_fds, sizeof(*pfdcs));
	if (pfdcs == NULL) {
		free(pfds);
		return NULL;
	}

	ec = calloc(1, sizeof(*ec));
	if (ec == NULL) {
		free(pfds);
		free(pfdcs);
		return NULL;
	}

	ec->ec_pfds = pfds;
	ec->ec_pfdcs = pfdcs;
	ec->ec_pfds_total = max_fds;
	RBT_INIT(timerst, &ec->ec_timerst);
	clock_gettime(CLOCK_MONOTONIC, &ec->ec_tv);

	/*
	 * Make pollfd_ctx pollfd point to the correct place and invalidate
	 * `pollfd`s `fd` so we don't cause any unecessary wake ups.
	 */
	for (i = 0; i < (long)max_fds; i++) {
		ec->ec_pfdcs[i].pfc_pf = &ec->ec_pfds[i];
		ec->ec_pfds[i].fd = -1;
	}

	return ec;
}

void
events_ctx_free(struct events_ctx **ec)
{
	struct events_ctx *ecp;
	struct timer_ctx *tc;

	/* Convenience: allow user to pass NULL pointers. */
	if (*ec == NULL)
		return;

	ecp = *ec;
	free(ecp->ec_pfds);
	free(ecp->ec_pfdcs);
	while ((tc = RBT_MIN(timerst, &ecp->ec_timerst)) != NULL)
		events_ctx_del_timer(ecp, &tc);

	free(ecp);
	*ec = NULL;
}

int
events_ctx_add_fd(struct events_ctx *ec, int fd, short events,
		  events_ctx_cb cb, void *arg)
{
	struct pollfd_ctx *pfdc;
	nfds_t i;

	/* Search for subscribed `fd`. */
	for (i = 0; i < ec->ec_pfds_used; i++) {
		if (ec->ec_pfds->fd != fd)
			continue;

		pfdc = &ec->ec_pfdcs[i];
		goto update_poll_ctx;
	}

	/* Otherwise do limits check and add new one. */
	if (ec->ec_pfds_used >= ec->ec_pfds_total)
		return -1;

	/* Array is always organized, so adding new descriptors is fast. */
	pfdc = &ec->ec_pfdcs[ec->ec_pfds_used];
	pfdc->pfc_pf = &ec->ec_pfds[ec->ec_pfds_used];
	ec->ec_pfds_used++;

	/* Add file descriptor to pollfd. */
	pfdc->pfc_pf->fd = fd;

update_poll_ctx:
	pfdc->pfc_cb = cb;
	pfdc->pfc_arg = arg;
	pfdc->pfc_pf->events = events;

	return 0;
}

void
events_ctx_del_fd(struct events_ctx *ec, int fd)
{
	size_t remaining;
	nfds_t i;

	for (i = 0; i < ec->ec_pfds_total; i++) {
		if (ec->ec_pfdcs[i].pfc_pf->fd == fd)
			break;
	}
	/* `fd` not found. */
	if (i == ec->ec_pfds_total)
		return;

	/* Remove file descriptor. */
	ec->ec_pfds[i].fd = -1;

	/* Now we must fill the gap created by the removal. */
	remaining = (ec->ec_pfds_used - 1) - i;
	/* Nothing to move. */
	if (remaining == 0)
		return;

	/* Move pollfd data around. */
	memmove(&ec->ec_pfds[i], &ec->ec_pfds[i + 1],
		remaining * sizeof(struct pollfd));
	memmove(&ec->ec_pfdcs[i], &ec->ec_pfdcs[i + 1],
		remaining * sizeof(struct pollfd_ctx));

	/* Update moved pointers. */
	for (; i < ec->ec_pfds_total; i++)
		ec->ec_pfdcs[i].pfc_pf = &ec->ec_pfds[i];
}

static void
events_ctx_timer_calculate(struct timer_ctx *tc, unsigned long to)
{
	struct timespec tv;

	clock_gettime(CLOCK_MONOTONIC, &tv);
	tc->tc_toc = (uint64_t)(tv.tv_sec * 1000)
		+ (uint64_t)(tv.tv_nsec / 1000000) + to;
}

struct timer_ctx *
events_ctx_add_timer(struct events_ctx *ec, unsigned long to,
		     events_ctx_timer_cb cb, void *arg)
{
	struct timer_ctx *tcp;

	/* Look up double registrations. */
	RBT_FOREACH(tcp, timerst, &ec->ec_timerst) {
		if (tcp->tc_to != to || tcp->tc_cb != cb || tcp->tc_arg != arg)
			continue;

		/* Exact same parameters, lets update the timer. */
		RBT_REMOVE(timerst, &ec->ec_timerst, tcp);
		goto update_timer;
	}

	/* Allocate memory and register into tree. */
	tcp = calloc(1, sizeof(*tcp));
	if (tcp == NULL)
		return NULL;

	tcp->tc_to = to;
	tcp->tc_cb = cb;
	tcp->tc_arg = arg;

update_timer:
	/* Calculate wake up time. */
	events_ctx_timer_calculate(tcp, to);

	/* Sanity check: insert should not fail, because its not duplicated. */
	if (RBT_INSERT(timerst, &ec->ec_timerst, tcp) != NULL) {
		dlog("timer insertion failed [to=%" PRIu64 "]", to);
		free(tcp);
		errno = 0;
		return NULL;
	}

	return tcp;
}

struct timer_ctx *
events_ctx_update_timer(struct events_ctx *ec, struct timer_ctx *tc,
			unsigned long to, events_ctx_timer_cb cb, void *arg)
{
	/* Remove from tree to avoid having it out of order. */
	RBT_REMOVE(timerst, &ec->ec_timerst, tc);

	tc->tc_to = to;
	tc->tc_cb = cb;
	tc->tc_arg = arg;

	/* Calculate wake up time. */
	events_ctx_timer_calculate(tc, to);

	/* Sanity check: insert should not fail, because its not duplicated. */
	if (RBT_INSERT(timerst, &ec->ec_timerst, tc) != NULL) {
		dlog("timer insertion failed [to=%" PRIu64 "]", to);
		free(tc);
		errno = 0;
		return NULL;
	}

	return tc;
}

void
events_ctx_del_timer(struct events_ctx *ec, struct timer_ctx **tc)
{
	struct timer_ctx *tcp;

	/* Convenience: allow user to pass NULL pointers. */
	if (*tc == NULL)
		return;

	tcp = *tc;
	RBT_REMOVE(timerst, &ec->ec_timerst, tcp);
	free(tcp);

	*tc = NULL;
}

static void
events_ctx_next_timeout(struct events_ctx *ec)
{
	struct timer_ctx *tc;
	uint64_t now;

	/* Find next expiration time. */
	tc = RBT_MIN(timerst, &ec->ec_timerst);
	if (tc == NULL) {
		dlog("no timers, wait forever");
		ec->ec_to = -1;
		return;
	}

	/* Get current time and turn it into milliseconds. */
	clock_gettime(CLOCK_MONOTONIC, &ec->ec_tv);
	now = (uint64_t)(ec->ec_tv.tv_sec * 1000)
	      + (uint64_t)(ec->ec_tv.tv_nsec / 1000000);

	/* Calculate the next timer expiration. */
	ec->ec_to = (tc->tc_toc < now) ? 0 : (int)(tc->tc_toc - now);

	dlog("next timeout: %d ms", ec->ec_to);
}

int
events_ctx_poll(struct events_ctx *ec)
{
	struct timer_ctx *tc, *tcn;
	struct pollfd_ctx *pfdc;
	struct pollfd *pfd;
	struct timespec tv;
	int processed;
	int events;
	int flags;
	uint64_t now;
	int64_t next;
	nfds_t i;

	/* Calculate next timer event. */
	events_ctx_next_timeout(ec);

	/* Check for events or sleep. */
	events = poll(ec->ec_pfds, ec->ec_pfds_used, ec->ec_to);

	/* Check for interruptions. */
	if (events == -1) {
		if (errno == EINTR)
			return 0;

		return -1;
	}

#ifdef EVENTS_DEBUG
	if (events == 0)
		dlog("  poll timed out");
	else
		dlog("  poll got %d file descriptors ready", events);
#endif /* EVENTS_DEBUG */

	/* Process timers first. */
	clock_gettime(CLOCK_MONOTONIC, &tv);
	now = (uint64_t)(tv.tv_sec * 1000) + (uint64_t)(tv.tv_nsec / 1000000);

	/* Process all timers that expired. */
	RBT_FOREACH_SAFE(tc, timerst, &ec->ec_timerst, tcn) {
		if (tc->tc_toc > now)
			break;

		next = tc->tc_cb(ec, tc->tc_arg);
		if (next == -1) {
			events_ctx_del_timer(ec, &tc);
			continue;
		}

		/* Set next expiration timer. */
		tc->tc_to = (unsigned long)next;
		events_ctx_update_timer(ec, tc, (unsigned long)next, tc->tc_cb,
					tc->tc_arg);
	}

	/* We've got a timeout, no file descriptors ready. */
	if (events == 0) {
		errno = 0;
		return 0;
	}

	/* Process all file descriptors. */
	processed = 0;
	for (i = 0; i < ec->ec_pfds_used; i++) {
		pfdc = &ec->ec_pfdcs[i];
		pfd = &ec->ec_pfds[i];
		if (pfdc->pfc_pf->revents == 0)
			continue;

		processed++;

		/* Remove from notifications if asked. */
		flags = pfdc->pfc_cb(ec, pfd->fd, pfd->revents, pfdc->pfc_arg);
		if (flags == -1) {
			events_ctx_del_fd(ec, pfd->fd);

			/*
			 * Removing event change array order, so lets repeat
			 * this index.
			 */
			i--;
			continue;
		} else
			pfd->events = (short)flags;

		/* We handled it all. */
		if (processed == events)
			break;
	}

	return processed;
}
