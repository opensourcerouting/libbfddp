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

/*
 * events.c.
 */
#ifndef EVENTS_DEBUG
#include <stdio.h>
#define dlog(fmt, args...) printf("events: " fmt "\n", ##args);
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
void bfddp_send_echo_request(struct bfddp_ctx *bctx);
void bfddp_send_echo_reply(struct bfddp_ctx *bctx, uint64_t bfdd_time);
void bfddp_process_echo_time(const struct bfddp_echo *echo);

#endif /* _SOFT_BFDDP_H */
