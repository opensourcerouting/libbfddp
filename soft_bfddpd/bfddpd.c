/*
 * BFD Data Plane daemon software implementation.
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
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>

#include <err.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "bfddp.h"
#include "bfddp_packet.h"
#include "bfddpd.h"

/** Verbose daemon configuration. */
bool verbose = false;
/** Termination signal value. */
volatile bool is_terminating = false;

/**
 * BFD Data Plane daemon main function: connects to BFD daemon and print
 * received messages.
 *
 * \param sa BFD daemon listening socket address.
 * \param salen BFD daemon listening socket address size.
 */
static void bfddp_main(const struct sockaddr *sa, socklen_t salen);

/**
 * BFD Data Plane daemon termination function: free all resources.
 */
static void bfddp_terminate(struct bfddp_ctx *bctx);

/**
 * Handle messages received by BFD daemon.
 */
static void bfddp_handle_message(struct events_ctx *ec, struct bfddp_ctx *bctx);

/*
 * Helper functions.
 */
static void
sig_termination_handler(int sig)
{
	fprintf(stderr, "received signal %d\n", sig);
	is_terminating = true;
}

static void __attribute__((noreturn))
usage(void)
{
	extern const char *__progname;

	fprintf(stderr,
		"Usage: %s [-v] TYPE:ADDRESS[:PORT]\n\n"
		"Connects to BFD daemon HAL socket at ADDRESS using TYPE "
		"optionally using PORT.\n\n"
		"TYPE can be one of the following values:\n"
		"  ipv4: to use an IPv4 address.\n"
		"  ipv6: to use an IPv6 address.\n"
		"  unix: to use an UNIX socket (special file).\n"
		"\n"
		"Options:\n"
		"  -v: verbose (dump complete messages).\n",
		__progname);

	exit(1);
}

static uint16_t
parse_port(const char *str)
{
	char *nulbyte;
	long rv;

	errno = 0;
	rv = strtol(str, &nulbyte, 10);
	/* No conversion performed. */
	if (rv == 0 && errno == EINVAL) {
		fprintf(stderr, "invalid BFD HAL address port: %s\n", str);
		exit(1);
	}
	/* Invalid number range. */
	if ((rv <= 0 || rv >= 65535) || errno == ERANGE) {
		fprintf(stderr, "invalid BFD HAL address port range: %s\n",
			str);
		exit(1);
	}
	/* There was garbage at the end of the string. */
	if (*nulbyte != 0) {
		fprintf(stderr, "invalid BFD HAL address port string: %s\n",
			str);
		exit(1);
	}

	return (uint16_t)rv;
}

static void
parse_address(const char *arg, struct sockaddr *sa, socklen_t *salen)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct sockaddr_un *sun;
	char *sptr;
	size_t typelen;
	char type[64];
	char addr[64];

	sptr = strchr(arg, ':');
	if (sptr == NULL) {
		fprintf(stderr, "Invalid address format: %s\n", arg);
		exit(1);
	}

	/* Calculate type string size. */
	typelen = (size_t)(sptr - arg);

	/* Copy type string. */
	sptr++;
	memcpy(type, arg, typelen);
	type[typelen] = 0;

	/* Copy address part. */
	snprintf(addr, sizeof(addr), "%s", sptr);

	/* Reset SA values. */
	memset(sa, 0, *salen);
	if (strcmp(type, "unix") == 0) {
		sun = (struct sockaddr_un *)sa;
		*salen = sizeof(*sun);
		sun->sun_family = AF_UNIX;
		snprintf(sun->sun_path, sizeof(sun->sun_path), "%s", addr);
	} else if (strcmp(type, "ipv4") == 0) {
		sin = (struct sockaddr_in *)sa;
		sin->sin_family = AF_INET;
		*salen = sizeof(*sin);

		/* Parse port if any. */
		sptr = strchr(sptr, ':');
		if (sptr == NULL) {
			sin->sin_port = htons(3000);
		} else {
			*sptr = 0;
			sin->sin_port = htons(parse_port(sptr + 1));
		}

		inet_pton(AF_INET, addr, &sin->sin_addr);
	} else if (strcmp(type, "ipv6") == 0) {
		sin6 = (struct sockaddr_in6 *)sa;
		sin6->sin6_family = AF_INET6;
		*salen = sizeof(*sin6);

		/* Parse port if any. */
		sptr = strrchr(sptr, ':');
		if (sptr == NULL) {
			sin6->sin6_port = htons(3000);
		} else {
			*sptr = 0;
			sin6->sin6_port = htons(parse_port(sptr + 1));
		}

		inet_pton(AF_INET6, addr, &sin6->sin6_addr);
	} else {
		fprintf(stderr, "invalid BFD HAL socket type: %s", type);
		exit(1);
	}
}

/*
 * Main functions.
 */
int
main(int argc, char *argv[])
{
	int opt;
	socklen_t addrlen;
	struct sigaction sa = {};
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
		struct sockaddr_un sun;
	} addr;

	while ((opt = getopt(argc, argv, "")) != -1) {
		switch (opt) {
		case 'v':
			verbose = true;
			break;

		default:
			usage();
			/* NOTREACHED */
		}
	}

	if (argc == 1)
		errx(1, "BFD HAL listening socket address missing");

	/* Parse address. */
	addrlen = sizeof(addr);
	parse_address(argv[1], (struct sockaddr *)&addr, &addrlen);

	/* Install signal handlers. */
	sa.sa_handler = sig_termination_handler;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	printf("start\n");

	/* Run main function. */
	bfddp_main(&addr.sa, addrlen);
	/* NOTREACHED */

	return 0;
}

/* Forward declaration. */
static int bfddp_connect_event(struct events_ctx *ec, int fd, short revents,
			       void *arg);

static void __attribute__((noreturn))
bfddp_main(const struct sockaddr *sa, socklen_t salen)
{
	struct bfddp_ctx *bctx;
	struct events_ctx *ec;

	/* Create event handler. */
	ec = events_ctx_new(64);
	if (ec == NULL)
		err(1, "%s: events_ctx_new", __func__);

	/* Allocate memory. */
	bctx = bfddp_new(0, 0);
	if (bctx == NULL)
		err(1, "%s: bfddp_new", __func__);

	/* Connect to BFD daemon. */
	if (bfddp_connect(bctx, sa, salen) == -1)
		err(1, "%s: bfddp_connect", __func__);

	/* Ask for events context to notify us. */
	events_ctx_add_fd(ec, bfddp_get_fd(bctx), POLLOUT, bfddp_connect_event,
			  bctx);

	/* Main daemon loop. */
	while (events_ctx_poll(ec) != -1) {
		/* Handle termination signals. */
		if (is_terminating) {
			/* Free events context memory. */
			events_ctx_free(&ec);

			/* Free library memory. */
			bfddp_terminate(bctx);
			/* NOTREACHED */
		}
	}

	/* NOTREACHED */
	exit(0);
}

/* Forward declaration. */
static int bfddp_event(struct events_ctx *ec, int fd, short revents, void *arg);

static int
bfddp_connect_event(struct events_ctx *ec, int fd, short revents, void *arg)
{
	int rv;

	/* Connection closed or failed. */
	if (revents & (POLLHUP | POLLERR | POLLNVAL))
		errx(1, "%s: connection closed", __func__);

	rv = bfddp_is_connected(arg);
	/* Handle fatal file descriptor errors: exit. */
	if (rv == -1)
		err(1, "%s: bfddp_is_connected", __func__);
	/* Handle interruptions: ask for more writes. */
	if (rv == 1)
		return POLLOUT;

	/* Ask for echo. */
	bfddp_send_echo_request(arg);

	/* Add our descriptor for read/write with new callback. */
	events_ctx_add_fd(ec, fd, POLLIN | POLLOUT, bfddp_event, arg);

	return POLLIN | POLLOUT;
}

static void
bfddp_write_event(struct bfddp_ctx *bctx)
{
	ssize_t rv;

	/* Attempt to flush output buffer. */
	rv = bfddp_write(bctx);
	if (rv == -1) {
		/* Connection failed. */
		if (errno != 0)
			err(1, "%s: bfddp_write", __func__);

		/* Connection closed. */
		printf("%s: bfddp_write: closed connection\n",
		       __func__);
		exit(1);
	}
	if (rv > 0)
		printf("=> Sent %zd bytes\n", rv);
}

static void
bfddp_read_event(struct events_ctx *ec, struct bfddp_ctx *bctx)
{
	ssize_t rv;

	/* Read as much as we can. */
	rv = bfddp_read(bctx);
	if (rv == -1) {
		/* Connection failed. */
		if (errno != 0)
			err(1, "%s: bfddp_read", __func__);

		/* Connection closed. */
		printf("%s: bfddp_read: closed connection\n",
		       __func__);
		exit(1);
	}
	if (rv > 0)
		printf("<= Received %zd bytes\n", rv);

	/* After reading the socket we process the messages. */
	bfddp_handle_message(ec, bctx);
}

static int
bfddp_event(struct events_ctx *ec, __attribute__((unused)) int fd,
	    short revents, void *arg)
{
	short events = POLLIN;

	/* Handle output. */
	if (revents & POLLOUT)
		bfddp_write_event(arg);

	/* Handle input. */
	if (revents & POLLIN)
		bfddp_read_event(ec, arg);

	/* Ask for POLLOUT events if buffer is not empty yet. */
	if (bfddp_write_pending(arg))
		events |= POLLOUT;

	return events;
}

static void __attribute__((noreturn))
bfddp_terminate(struct bfddp_ctx *bctx)
{
	fprintf(stderr, "terminating\n");

	bfddp_free(bctx);

	exit(0);
}

static int64_t
bfddp_echo_request_event(struct events_ctx *ec, void *arg)
{
	struct bfddp_ctx *bctx = arg;

	/* Enqueue echo request. */
	bfddp_send_echo_request(bctx);

	/* Ask for POLLOUT. */
	events_ctx_add_fd(ec, bfddp_get_fd(bctx), POLLIN | POLLOUT, bfddp_event,
			  bctx);

	return -1;
}

static void
bfddp_handle_message(struct events_ctx *ec, struct bfddp_ctx *bctx)
{
	struct bfddp_message *msg;
	enum bfddp_message_type bmt;

	do {
		msg = bfddp_next_message(bctx);
		if (msg == NULL)
			return;

		bmt = ntohs(msg->header.type);
		switch (bmt) {
		case ECHO_REQUEST:
			printf("echo-request: sending echo reply\n");
			bfddp_send_echo_reply(bctx, msg->data.echo.bfdd_time);
			break;
		case ECHO_REPLY:
			bfddp_process_echo_time(&msg->data.echo);
			printf("Ask again in 5 seconds\n");
			events_ctx_add_timer(ec, 5000, bfddp_echo_request_event,
					     bctx);
			break;
		case DP_ADD_SESSION:
			printf("Received add-session message\n");
			/* TODO: implement software session (re)installation. */
			break;
		case DP_DELETE_SESSION:
			printf("Received delete-session message\n");
			/* TODO: implement software session removal. */
			break;
		case BFD_STATE_CHANGE:
			/* XXX: we are not supposed to receive this message. */
			printf("Received wrong state-change mesage\n");
			break;

		default:
			printf("Unhandled message type %d\n", bmt);
			break;
		}
	} while (msg != NULL);
}
