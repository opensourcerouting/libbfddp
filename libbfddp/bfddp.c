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

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bfddp.h"

/** Macro to test for full buffer. */
#define BFDDP_BUF_FULL(buf) ((buf)->position == (buf)->total)
/** Macro to test for empty buffer. */
#define BFDDP_BUF_EMPTY(buf) ((buf)->packet == (buf)->position)

/**
 * Primite buffer structure.
 */
struct bfddp_buf {
	/** The buffer. */
	uint8_t *buf;
	/** Total size. */
	size_t total;
	/** Buffer read/write position. */
	size_t position;
	/** Buffer remaining bytes. */
	size_t remaining;
	/** Packet position in buffer. */
	size_t packet;
};

/**
 * BFD data plane context for dealing with socket.
 *
 * This is a opaque data structure not available for use.
 */
struct bfddp_ctx {
	/** The connection socket file descriptor. */
	int sock;
	/** Whether or not we are still trying to connect. */
	bool connecting;
	/** The connection input buffer. */
	struct bfddp_buf inbuf;
	/** The connection output buffer. */
	struct bfddp_buf outbuf;
};

/*
 * Local functions.
 */
static int
sock_set_nonblock(int sock)
{
	int flags;

	/* Get socket flags */
	flags = fcntl(sock, F_GETFL, NULL);
	if (flags == -1)
		return -1;

	/* Check if NON_BLOCK is already set. */
	if (flags & O_NONBLOCK)
		return 0;

	/* Set the NON_BLOCK flag. */
	flags |= O_NONBLOCK;
	if (fcntl(sock, F_SETFL, flags) == -1)
		return -1;

	return 0;
}

static int
socktcp_set_nodelay(int sock)
{
	int value;

	value = 1;
	if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value)))
		return -1;

	return 0;
}

/* Close the socket, handle interruptions and always restore previous errno. */
static void
sock_close(int sock)
{
	int errnoc = errno, rv;

	do {
		rv = close(sock);
		if (rv == 0)
			break;

		/* Only attempt to close the socket again if interrupted. */
		if (errno != EINTR)
			break;
	} while (rv == -1);

	/* Restore errno from function begin. */
	errno = errnoc;
}

static void
bfddp_buf_pulldown(struct bfddp_buf *buf)
{
	size_t movebytes;

	/* Buffer is already organized. */
	if (buf->position == 0)
		return;

	/* No data is available, just update the pointers. */
	if (BFDDP_BUF_EMPTY(buf)) {
		buf->remaining = buf->total;
		buf->position = 0;
		buf->packet = 0;
	}

	/* Calculate the amount of bytes we need to move. */
	movebytes = buf->position - buf->packet;

	/* Move the buffer data and update pointers. */
	memmove(buf->buf, buf->buf + buf->packet, movebytes);
	buf->remaining = buf->total - movebytes;
	buf->position = movebytes;
	buf->packet = 0;
}

/**
 * Read from socket into buffer.
 *
 * \param sock the socket to read from.
 * \param buf the buffer to store data.
 *
 * \returns
 * `-1` on failure (check `errno`, if `errno == 0` then the connection was
 * closed) otherwise the number of bytes read. When the return is `0` it means
 * means we got interrupted (check `errno` for `EINTR`, `EAGAIN` or
 * `EWOULDBLOCK) or the buffer is already full.
 */
static ssize_t
bfddp_buf_read(int sock, struct bfddp_buf *buf)
{
	ssize_t rv;

	/* Buffer full check so we avoid false connection close returns. */
	if (BFDDP_BUF_FULL(buf))
		return 0;

	/* Read the socket data as much as we can. */
	rv = read(sock, buf->buf + buf->position, buf->remaining);
	/* Connection closed, return error. */
	if (rv == 0) {
		errno = 0;
		return -1;
	}
	if (rv == -1) {
		/* We've got interrupted, this is not an error. */
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;

		/* Connection failed badly, return error. */
		return -1;
	}

	/* Update pointers. */
	buf->position += (size_t)rv;
	buf->remaining -= (size_t)rv;

	return rv;
}

static ssize_t
bfddp_buf_write(int sock, struct bfddp_buf *buf)
{
	ssize_t rv;

	/* Buffer empty check so we avoid false connection close returns. */
	if (BFDDP_BUF_EMPTY(buf))
		return 0;

	/* Write to the socket data as much as we can. */
	rv = write(sock, buf->buf + buf->packet, buf->position - buf->packet);
	/* Connection closed, return error. */
	if (rv == 0) {
		errno = 0;
		return -1;
	}
	if (rv == -1) {
		/* We've got interrupted, this is not an error. */
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;

		/* Connection failed badly, return error. */
		return -1;
	}

	/* Update pointers. */
	buf->packet += (size_t)rv;

	return rv;
}

/**
 * Test if non blocking `connect()` is still running.
 *
 * \param sock non blocking socket that already ran `connect()`.
 *
 * \returns `-1` on `getsockopt` failure, `0` on success or `connect()`
 * `errno`.
 */
static int
socktcp_is_connected(int sock)
{
	int rv = 0;
	socklen_t rvlen = sizeof(rv);

	if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &rv, &rvlen) == -1)
		return -1;

	return rv;
}

int
bfddp_is_connected(struct bfddp_ctx *bctx)
{
	int rv;

	/* We are already connected. */
	if (bctx->connecting == false)
		return 0;

	rv = socktcp_is_connected(bctx->sock);

	/* Test for successfully connected. */
	if (rv == 0) {
		bctx->connecting = false;
		return 0;
	}

	/* Handle error codes. */
	switch (rv) {
	case EINTR:
	case EAGAIN:
	case EALREADY:
	case EINPROGRESS:
		/* All of these are non-errors. */
		errno = rv;
		return 1;

	default:
		errno = rv;
		return -1;
	}
}

/*
 * Exported functions.
 */
struct bfddp_ctx *
bfddp_new(size_t inbuflen, size_t outbuflen)
{
	struct bfddp_ctx *bctx;

	bctx = calloc(1, sizeof(*bctx));
	if (bctx == NULL)
		return NULL;

	if (inbuflen <= 4096)
		inbuflen = 4096;

	bctx->inbuf.buf = malloc(inbuflen);
	if (bctx->inbuf.buf == NULL)
		goto free_and_fail;

	if (outbuflen <= 4096)
		outbuflen = 4096;

	bctx->outbuf.buf = malloc(outbuflen);
	if (bctx->outbuf.buf == NULL)
		goto free_and_fail;

	bctx->inbuf.total = bctx->inbuf.remaining = inbuflen;
	bctx->outbuf.total = bctx->outbuf.remaining = outbuflen;

	/* Initialize socket with known good value. */
	bctx->sock = -1;

	return bctx;

free_and_fail:
	free(bctx->inbuf.buf);
	free(bctx->outbuf.buf);
	free(bctx);
	return NULL;
}

void
bfddp_free(struct bfddp_ctx *bctx)
{
	if (bctx->sock != -1)
		close(bctx->sock);

	free(bctx->inbuf.buf);
	free(bctx->outbuf.buf);
	free(bctx);
}

int
bfddp_get_fd(const struct bfddp_ctx *bctx)
{
	return bctx->sock;
}

int
bfddp_connect(struct bfddp_ctx *bctx, const struct sockaddr *sa,
	      socklen_t salen)
{
	int rv, sock;

	sock = socket(sa->sa_family, SOCK_STREAM, 0);
	if (sock == -1)
		return -1;

	/* Set socket non blocking, otherwise fail. */
	if (sock_set_nonblock(sock) == -1) {
		sock_close(sock);
		return -1;
	}

	/* Send packets as soon as we write to the socket. */
	if (socktcp_set_nodelay(sock) == -1) {
		sock_close(sock);
		return -1;
	}

	/* Start the attempt of connecting. */
	rv = connect(sock, sa, salen);
	if (rv == -1 && (errno != EINPROGRESS && errno != EAGAIN)) {
		sock_close(sock);
		return -1;
	}

	bctx->sock = sock;
	bctx->connecting = (rv == -1);

	return 0;
}

ssize_t
bfddp_read(struct bfddp_ctx *bctx)
{
	struct bfddp_buf *buf = &bctx->inbuf;
	ssize_t rv, total = 0;

	/*
	 * Prevention check: user forgot to call `bfddp_read_finish`, lets
	 * make sure we have at least the minimum number of bytes to read a
	 * full message.
	 */
	if (buf->remaining <= sizeof(struct bfddp_message))
		bfddp_buf_pulldown(buf);

	/* Read from socket until full or interrupted. */
	do {
		rv = bfddp_buf_read(bctx->sock, buf);
		/* Connection closed or failed. */
		if (rv == -1) {
			if (total == 0)
				return -1;

			/* We read something, let the user check the buffer. */
			return total;
		}

		total += rv;

		/* Check for full buffers. */
		if (BFDDP_BUF_FULL(buf))
			return total;

		/* We've got interrupted. */
		if (rv == 0)
			return total;
	} while (rv > 0);

	return total;
}

struct bfddp_message *
bfddp_next_message(struct bfddp_ctx *bctx)
{
	struct bfddp_buf *buf = &bctx->inbuf;
	struct bfddp_message_header *header;
	size_t msglen;

	/* Check if we have no buffered messages. */
	if (buf->packet >= buf->position)
		return NULL;

	/* Check if we have the whole message. */
	header = (struct bfddp_message_header *)&buf->buf[buf->packet];
	msglen = ntohs(header->length);
	if ((buf->packet + msglen) > buf->position)
		return NULL;

	/* Update the packet pointer. */
	buf->packet += msglen;

	return (struct bfddp_message *)header;
}

void
bfddp_read_finish(struct bfddp_ctx *bctx)
{
	bfddp_buf_pulldown(&bctx->inbuf);
}

size_t
bfddp_write_enqueue(struct bfddp_ctx *bctx, const struct bfddp_message *msg)
{
	struct bfddp_buf *buf = &bctx->outbuf;
	size_t amount;

	amount = ntohs(msg->header.length);
	/* Buffer is full, tell user about it. */
	if (amount > buf->remaining)
		return 0;

	/* Enqueue the message. */
	memcpy(buf->buf + buf->position, msg, amount);
	buf->position += amount;
	buf->remaining -= amount;
	return amount;
}

ssize_t
bfddp_write(struct bfddp_ctx *bctx)
{
	struct bfddp_buf *buf = &bctx->outbuf;
	ssize_t rv, total = 0;

	/* Check if write buffer is empty. */
	if (BFDDP_BUF_EMPTY(buf)) {
		/* If buffer is empty we get optimized pulldown or nop. */
		bfddp_buf_pulldown(buf);
		return 0;
	}

	/* Write to socket until buffer is empty or interrupted. */
	do {
		rv = bfddp_buf_write(bctx->sock, buf);
		/* Connection closed or failed. */
		if (rv == -1)
			return -1;

		total += rv;

		/* Check for empty buffers. */
		if (BFDDP_BUF_EMPTY(buf))
			return total;

		/* We've got interrupted. */
		if (rv == 0)
			return total;
	} while (rv > 0);

	return total;
}

size_t
bfddp_write_pending(struct bfddp_ctx *bctx)
{
	struct bfddp_buf *buf = &bctx->outbuf;

	return buf->position - buf->packet;
}
