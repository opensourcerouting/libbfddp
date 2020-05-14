/*
 * BFD Data Plane sample daemon implementation.
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

#include <arpa/inet.h>
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
static void bfddp_handle_message(struct bfddp_ctx *bctx);

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

static void
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

static void
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

static void
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

static void __attribute__((noreturn))
bfddp_main(const struct sockaddr *sa, socklen_t salen)
{
	struct bfddp_ctx *bctx;
	struct pollfd pfs[1];
	ssize_t rv;

	/* Zero all descriptors. */
	memset(pfs, 0, sizeof(pfs));

	/* Allocate memory. */
	bctx = bfddp_new(0, 0);
	if (bctx == NULL)
		err(1, "%s: bfddp_new", __func__);

	/* Connect to BFD daemon. */
	if (bfddp_connect(bctx, sa, salen) == -1)
		err(1, "%s: bfddp_connect", __func__);

	/*
	 * `bfddp_connect` might be still running: if `bfddp_is_connected`
	 * returns `1` then we can't `poll()` for read events.
	 */
	rv = bfddp_is_connected(bctx);
	if (rv == -1)
		err(1, "%s: bfddp_is_connected", __func__);
	else if (rv == 0)
		pfs[0].events = POLLIN;
	else
		pfs[0].events = POLLOUT;

	/* Configure descriptor for `poll()`. */
	pfs[0].fd = bfddp_get_fd(bctx);

	/* Ask for echo on start and `poll()` for write events. */
	bfddp_send_echo_request(bctx);
	pfs[0].events |= POLLOUT;

	/* Main daemon loop. */
	do {
		rv = poll(pfs, 1, -1);

		/* Handle termination signals. */
		if (is_terminating) {
			bfddp_terminate(bctx);
			/* NOTREACHED */
		}

		/* Handle error values. */
		if (rv == -1) {
			/* Interruptions are not fatal. */
			if (errno == EINTR)
				continue;

			err(1, "%s: poll", __func__);
			/* NOTREACHED */
		}

		/* Handle timeouts. */
		if (rv == 0) {
			printf("%s: timed out\n", __func__);
			continue;
		}

		/* Handle descriptor write ready. */
		if (pfs[0].revents & POLLOUT) {
			/* Check if the socket is connected. */
			rv = bfddp_is_connected(bctx);
			if (rv != 0) {
				/* Unrecoverable error. */
				if (rv == -1)
					err(1, "%s: bfddp_is_connected",
					    __func__);

				printf("%s: bfddp_is_connecting: running",
				       __func__);
				/* We are still not connected. */
				continue;
			}

			/* Add read notifications (if not set already). */
			pfs[0].events |= POLLIN;

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

		/* Handle descriptor read ready. */
		if (pfs[0].revents & POLLIN) {
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
			bfddp_handle_message(bctx);
		}
	} while (true);

	exit(0);
}

static void __attribute__((noreturn))
bfddp_terminate(struct bfddp_ctx *bctx)
{
	fprintf(stderr, "terminating\n");

	bfddp_free(bctx);

	exit(0);
}

static void
bfddp_handle_message(struct bfddp_ctx *bctx)
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
			break;
		case DP_ADD_SESSION:
			printf("Received add-session message\n");
			/* TODO: implement hardware session (re)installation. */
			break;
		case DP_DELETE_SESSION:
			printf("Received delete-session message\n");
			/* TODO: implement hardware session removal. */
			break;
		case DP_SEND_SINGLE_PACKET:
			printf("Received send-single-packet message\n");
			/* TODO: implement hardware single packet send. */
			break;
		case DP_SEND_PACKET:
			printf("Received send-packet message\n");
			/* TODO: implement hardware repeated packet send. */
			break;
		case BFD_STATE_CHANGE:
			/* XXX: we are not supposed to receive this message. */
			printf("Received wrong state-change mesage\n");
			break;
		case BFD_CONTROL_PACKET:
			/* XXX: we are not supposed to receive this message. */
			printf("Received wrong control-packet message\n");
			break;

		default:
			printf("Unhandled message type %d\n", bmt);
			break;
		}
	} while (msg != NULL);
}
