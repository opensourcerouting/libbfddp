/*
 * BFD Data Plane library header.
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
 * \file bfddp.h
 */
#ifndef BFD_DP_H
#define BFD_DP_H

#include <sys/socket.h>

#include <stdlib.h>

#include "bfddp_packet.h"

/**
 * BFD daemon communication context.
 */
struct bfddp_ctx
#ifdef DOYXGEN_DOC
{
}
#endif /* DOXYGEN_DOC */
;

#ifdef __cplusplus
#define LIBBFDDP_BEGIN_DECLS extern "C" {
#define LIBBFDDP_END_DECLS }
#else
#define LIBBFDDP_BEGIN_DECLS
#define LIBBFDDP_END_DECLS
#endif //__cplusplus

LIBBFDDP_BEGIN_DECLS

/**
 * Allocates memory for the data plane context and I/O buffers.
 *
 * \param[in] inbuflen amount of bytes for input buffer (minimum is 4096).
 * \param[in] outbuflen amount of bytes for output buffer (minimum is 4096).
 *
 * \returns `NULL` on failure otherwise a pointer to context.
 */
struct bfddp_ctx *bfddp_new(size_t inbuflen, size_t outbuflen);

/**
 * Releases all allocated memory and socket.
 *
 * \param[in,out] bctx the BFD daemon communication context.
 */
void bfddp_free(struct bfddp_ctx *bctx);

/**
 * Get the BFD Data Plane socket file descriptor. This function should only be
 * called after a successful `bfddp_connect()`.
 *
 * \param[in,out] bctx the BFD daemon communication context.
 *
 * \returns `-1` on closed socket or a valid file descriptor.
 *
 * \see bfddp_connect.
 */
int bfddp_get_fd(const struct bfddp_ctx *bctx);

/**
 * Sets the BFD Data Plane socket file descriptor. This function is useful when
 * socket handling is made outside the library code for any reason.
 *
 * \param[in,out] bctx the BFD daemon communication context.
 * \param[in] fd the socket file descriptor.
 */
void bfddp_set_fd(struct bfddp_ctx *bctx, int fd);

/**
 * Creates the BFD daemon socket to exchange the messages.
 *
 * \param[in,out] bctx the BFD daemon communication context.
 * \param[in] sa the BFD daemon listening address.
 * \param[in] salen `sa` struct size.
 *
 * \returns `0` on success otherwise `-1` and `errno` on failure.
 *
 * \see bfddp_new.
 */
int bfddp_connect(struct bfddp_ctx *bctx, const struct sockaddr *sa,
		  socklen_t salen);

/**
 * Tests if socket is connected or not and update status.
 *
 * \param[in,out] bctx the BFD daemon communication context.
 *
 * \returns `-1` on unrecoverable error (see `errno` for more details),
 * `1` if still not connected (see `errno` for more details) otherwise
 * `0` when connected.
 */
int bfddp_is_connected(struct bfddp_ctx *bctx);

/**
 * Read from BFD daemon socket and buffer internally. After calling this
 * function `bfddp_next_message` should be called to get the messages
 * from buffer.
 *
 * This function should be only called after `bfddp_connect`.
 *
 * \param[in,out] bctx the BFD daemon communication context.
 *
 * \returns
 * `-1` on failure (socket needs to be reopened), `0` on interruptions or
 * full buffers and number of bytes read on success.
 *
 * If the return is `-1` and the `errno` is `0` then it was a normal
 * connection close (the other side called `close()` on the socket).
 *
 * \see bfddp_connect.
 */
ssize_t bfddp_read(struct bfddp_ctx *bctx);

/**
 * Retrieves buffered message from data plane context buffer. After
 * reading all available messages, it is recommended to call
 * `bfddp_read_finish()`.
 *
 * \param[in,out] bctx the BFD daemon communication context.
 *
 * \returns
 * `NULL` when no complete messages are available or a pointer to the
 * message buffer.
 *
 * \see bfddp_read, bfddp_read_finish.
 */
struct bfddp_message *bfddp_next_message(struct bfddp_ctx *bctx);

/**
 * Reorder the input buffer so we can read more next `bfddp_read` call.
 *
 * \param[in,out] bctx the BFD daemon communication context.
 *
 * \see bfddp_read.
 */
void bfddp_read_finish(struct bfddp_ctx *bctx);

/**
 * Buffer BFD daemon messages in context. After filling the buffer the
 * function `bfddp_write()` should be called to send the buffered
 * messages.
 *
 * \param[in,out] bctx the BFD daemon communication context.
 * \param[in] msg the BFD daemon message.
 *
 * \returns `0` on full buffer or the number of bytes buffered.
 *
 * \see bfddp_write.
 */
size_t bfddp_write_enqueue(struct bfddp_ctx *bctx,
			   const struct bfddp_message *msg);

/**
 * Write to BFD daemon socket buffered data. Messages can be enqueued to
 * be sent using `bfddp_write_enqueue()`.
 *
 * This function should be only called after `bfddp_connect`.
 *
 * \param[in,out] bctx the BFD daemon communication context.
 *
 * \returns
 * `-1` on failure (socket needs to be reopened), `0` on interruptions or
 * empty buffers and number of bytes sent on success.
 *
 * If the return is `-1` and the `errno` is `0` then it was a normal
 * connection close (the other side called `close()` on the socket).
 *
 * \see bfddp_connect, bfddp_write_enqueue.
 */
ssize_t bfddp_write(struct bfddp_ctx *bctx);

/**
 * Function to get the amount of bytes pending to be sent.
 *
 * \param bctx the BFD daemon communication context.
 *
 * \returns `0` if output buffer is empty otherwise the number of bytes.
 */
size_t bfddp_write_pending(struct bfddp_ctx *bctx);

/** Logging abstraction layer definitions. */
struct bfddp_log {
	/** "err" logging function used by the library. */
	void (*err_log)(int err_val, const char *_format, ...);

	/** "errx" logging function used by the library. */
	void (*errx_log)(int err_val, const char *_format, ...);

	/** "warn" logging function used by the library. */
	void (*warn_log)(const char *_format, ...);

	/** general logging function used by the library. */
	int (*log)(const char *_format, ...);
};

/** Initialize the general logging functions used by the library. */
void bfddp_logging_init(struct bfddp_log *_this);

/** General "err" logging function. */
extern void (*bfddp_err)(int err_val, const char *_format, ...);

/** General "errx" logging function. */
extern void (*bfddp_errx)(int err_val, const char *_format, ...);

/** General "warn" logging function. */
extern void (*bfddp_warn)(const char *_format, ...);

/** General logging function. */
extern int (*bfddp_log)(const char *_format, ...);

LIBBFDDP_END_DECLS

#endif /* BFD_DP_H */
