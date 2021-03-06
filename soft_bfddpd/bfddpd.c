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
#include <sys/un.h>

#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
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

/**
 * Handle common read/write events.
 */
static void bfddp_event(struct events_ctx *ec, int fd, short revents,
			void *arg);

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
	char *sptr, *saux;
	size_t slen;
	char type[64];
	char addr[64];

	/* Basic parsing: find ':' to figure out type part and address part. */
	sptr = strchr(arg, ':');
	if (sptr == NULL) {
		fprintf(stderr, "Invalid address format: %s\n", arg);
		exit(1);
	}

	/* Calculate type string size. */
	slen = (size_t)(sptr - arg);

	/* Copy type string. */
	sptr++;

	/* Check if type is strangely long. */
	if (slen >= sizeof(type))
		bfddp_errx(1, "%s: type is too long: %zu characters", __func__, slen);

	memcpy(type, arg, slen);
	type[slen] = 0;

	/* Copy address part. */
	snprintf(addr, sizeof(addr), "%s", sptr);

	/* Reset SA values. */
	memset(sa, 0, *salen);

	/* Fill the address information. */
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
			sin->sin_port = htons(BFD_DATA_PLANE_DEFAULT_PORT);
		} else {
			*sptr = 0;
			sin->sin_port = htons(parse_port(sptr + 1));
		}

		inet_pton(AF_INET, addr, &sin->sin_addr);
	} else if (strcmp(type, "ipv6") == 0) {
		sin6 = (struct sockaddr_in6 *)sa;
		sin6->sin6_family = AF_INET6;
		*salen = sizeof(*sin6);

		/* Check for IPv6 enclosures '[]' */
		sptr = &addr[0];
		if (*sptr != '[')
			bfddp_errx(1, "%s: invalid IPv6 address: %s (try [::1])",
			           __func__, addr);

		saux = strrchr(addr, ']');
		if (saux == NULL)
			bfddp_errx(1, "%s: invalid IPv6 address: %s (try [::1])",
			           __func__, addr);

		/* Consume the '[]:' part. */
		slen = (size_t)(saux - sptr);
		memmove(addr, addr + 1, slen);
		addr[slen - 1] = 0;

		/* Parse port if any. */
		saux++;
		sptr = strrchr(saux, ':');
		if (sptr == NULL) {
			sin6->sin6_port = htons(BFD_DATA_PLANE_DEFAULT_PORT);
		} else {
			*sptr = 0;
			sin6->sin6_port = htons(parse_port(sptr + 1));
		}

		inet_pton(AF_INET6, addr, &sin6->sin6_addr);
	} else {
		fprintf(stderr, "invalid BFD data plane socket type: %s\n",
			type);
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
		bfddp_errx(1, "BFD HAL listening socket address missing");

	/* Parse address. */
	addrlen = sizeof(addr);
	parse_address(argv[1], (struct sockaddr *)&addr, &addrlen);

	/* Install signal handlers. */
	sa.sa_handler = sig_termination_handler;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	bfddp_log("start\n");

	/* Run main function. */
	bfddp_main(&addr.sa, addrlen);
	/* NOTREACHED */

	return 0;
}

/* Forward declaration. */
static void bfddp_connect_event(struct events_ctx *ec, int fd, short revents,
			        void *arg);
static int bfd_single_hop_socket(void);
static void bfd_single_hop_recv(struct events_ctx *ec, int sock, short revents,
			        void *arg);
static int bfd_single_hop_echo_socket(void);
static void bfd_single_hop_echo_recv(struct events_ctx *ec, int sock,
				     short revents, void *arg);

static void __attribute__((noreturn))
bfddp_main(const struct sockaddr *sa, socklen_t salen)
{
	struct bfddp_ctx *bctx;
	struct events_ctx *ec;
	int shbfd = bfd_single_hop_socket();
	int shebfd = bfd_single_hop_echo_socket();

	/* Create event handler. */
	ec = events_ctx_new(64);
	if (ec == NULL)
		bfddp_err(1, "%s: events_ctx_new", __func__);

	/* Allocate memory. */
	bctx = bfddp_new(0, 0);
	if (bctx == NULL)
		bfddp_err(1, "%s: bfddp_new", __func__);

	/* Initialize BFD sessions handler. */
	bfd_session_init();

	/* Connect to BFD daemon. */
	if (bfddp_connect(bctx, sa, salen) == -1)
		bfddp_err(1, "%s: bfddp_connect", __func__);

	/* Ask for events context to notify us. */
	events_ctx_add_fd(ec, bfddp_get_fd(bctx), POLLOUT, bfddp_connect_event,
			  bctx);

	/* Ask for events context to notify us of BFD control events. */
	events_ctx_add_fd(ec, shbfd, POLLIN, bfd_single_hop_recv, NULL);

	/* Ask for events context to notify us of BFD echo events. */
	events_ctx_add_fd(ec, shebfd, POLLIN, bfd_single_hop_echo_recv, NULL);

	/* Main daemon loop. */
	while (events_ctx_poll(ec) != -1) {
		/*
		 * Add our descriptor for read/write when there are writes
		 * pending.
		 */
		if (bfddp_write_pending(bctx))
			events_ctx_add_fd(ec, bfddp_get_fd(bctx),
					  POLLIN | POLLOUT, bfddp_event, bctx);

		/* Handle termination signals. */
		if (is_terminating) {
			/* Finish BFD session management resources. */
			bfd_session_finish();

			/* Free events context memory. */
			events_ctx_free(&ec);

			/* Close BFD socket. */
			close(shbfd);

			/* Free library memory. */
			bfddp_terminate(bctx);
			/* NOTREACHED */
		}
	}

	/* NOTREACHED */
	exit(0);
}

static void
bfddp_connect_event(struct events_ctx *ec, int fd, short revents, void *arg)
{
	int rv;

	/* Connection closed or failed. */
	if (revents & (POLLHUP | POLLERR | POLLNVAL))
		bfddp_errx(1, "%s: connection closed", __func__);

	rv = bfddp_is_connected(arg);
	/* Handle fatal file descriptor errors: exit. */
	if (rv == -1)
		bfddp_err(1, "%s: bfddp_is_connected", __func__);
	/* Handle interruptions: ask for more writes. */
	if (rv == 1) {
		events_ctx_add_fd(ec, fd, POLLOUT, bfddp_connect_event, arg);
		return;
	}

	/* Ask for echo. */
	bfddp_send_echo_request(arg);

	/* Add our descriptor for read/write with new callback. */
	events_ctx_add_fd(ec, fd, POLLIN | POLLOUT, bfddp_event, arg);
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
			bfddp_err(1, "%s: bfddp_write", __func__);

		/* Connection closed. */
		bfddp_log("%s: bfddp_write: closed connection\n",
		          __func__);
		is_terminating = true;
		return;
	}
	if (rv > 0)
		bfddp_log("=> Sent %zd bytes\n", rv);
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
			bfddp_err(1, "%s: bfddp_read", __func__);

		/* Connection closed. */
		bfddp_log("%s: bfddp_read: closed connection\n",
				  __func__);
		is_terminating = true;
		return;
	}
	if (rv > 0)
		bfddp_log("<= Received %zd bytes\n", rv);

	/* After reading the socket we process the messages. */
	bfddp_handle_message(ec, bctx);
}

static void
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

	events_ctx_add_fd(ec, fd, events, bfddp_event, arg);
}

static void __attribute__((noreturn))
bfddp_terminate(struct bfddp_ctx *bctx)
{
	fprintf(stderr, "terminating\n");

	bfddp_free(bctx);

	exit(0);
}

static void
bfddp_echo_request_event(__attribute__((unused)) struct events_ctx *ec,
			 void *arg)
{
	/* Enqueue echo request. */
	bfddp_send_echo_request(arg);

	/* Ask to send the echo request. */
	events_ctx_add_fd(ec, bfddp_get_fd(arg), POLLIN | POLLOUT, bfddp_event,
			  arg);
}

static void
bfddp_handle_message(struct events_ctx *ec, struct bfddp_ctx *bctx)
{
	struct bfd_session *bs;
	struct bfddp_message *msg;
	enum bfddp_message_type bmt;

	do {
		msg = bfddp_next_message(bctx);
		if (msg == NULL)
			return;

		bmt = ntohs(msg->header.type);
		switch (bmt) {
		case ECHO_REQUEST:
			bfddp_log("echo-request: sending echo reply\n");
			bfddp_send_echo_reply(bctx, msg->data.echo.bfdd_time);
			break;
		case ECHO_REPLY:
			bfddp_process_echo_time(&msg->data.echo);
			events_ctx_add_timer(ec, 5000, bfddp_echo_request_event,
					     bctx);
			break;
		case DP_ADD_SESSION:
			bs = bfd_session_lookup(ntohl(msg->data.session.lid));
			if (bs == NULL)
				bfddp_session_new(bctx, ec, &msg->data.session);
			else
				bfddp_session_update(bs, NULL,
						     &msg->data.session);
			break;
		case DP_DELETE_SESSION:
			bs = bfd_session_lookup(ntohl(msg->data.session.lid));
			bfddp_session_free(&bs, NULL);
			break;
		case DP_REQUEST_SESSION_COUNTERS:
			bs = bfd_session_lookup(
				ntohl(msg->data.counters_req.lid));
			bfddp_session_reply_counters(bctx, msg->header.id, bs);
			break;

		case BFD_SESSION_COUNTERS:
			/* FALLTHROUGH. */
		case BFD_STATE_CHANGE:
			/* XXX: we are not supposed to receive this message. */
			bfddp_log("Received wrong state-change mesage\n");
			break;

		default:
			bfddp_log("Unhandled message type %d\n", bmt);
			break;
		}
	} while (msg != NULL);

	/* We are done reading the messages, reorganize the buffer. */
	bfddp_read_finish(bctx);
}

static void
bfd_single_hop_recv(__attribute__((unused)) struct events_ctx *ec, int sock,
		    short revents, __attribute__((unused)) void *arg)
{
	if (revents & (POLLERR | POLLHUP | POLLNVAL))
		bfddp_errx(1, "poll returned bad value");

	/* Handle incoming packet. */
	bfd_recv_control_packet(sock);

	/* Always read more. */
	events_ctx_add_fd(ec, sock, POLLIN, bfd_single_hop_recv, arg);
}

static int
bfd_single_hop_socket(void)
{
	int rv, sock, value;
	struct sockaddr_in sin = {};

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1)
		bfddp_err(1, "%s: socket", __func__);

	/* Set packet TTL. */
	value = 255;
	rv = setsockopt(sock, IPPROTO_IP, IP_TTL, &value, sizeof(value));
	if (rv == -1)
		bfddp_err(1, "%s: setsockopt(IP_TTL)", __func__);

	/* Receive the packet TTL information from `recvmsg`. */
	value = 1;
	rv = setsockopt(sock, IPPROTO_IP, IP_RECVTTL, &value, sizeof(value));
	if (rv == -1)
		bfddp_err(1, "%s: setsockopt(IP_RECVTTL)", __func__);

	/* Receive the interface information from `recvmsg`. */
	value = 1;
	rv = setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &value, sizeof(value));
	if (rv == -1)
		bfddp_err(1, "%s: setsockopt(IP_PKTINFO)", __func__);

	/* Re use addr if someone else is using it. */
	value = 1;
	rv = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value));
	if (rv == -1)
		bfddp_err(1, "%s: setsockopt(SO_REUSEADDR)", __func__);

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(BFD_SINGLE_HOP_PORT);
	if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) == -1)
		bfddp_err(1, "%s: bind", __func__);

	return sock;
}

static void
bfd_single_hop_echo_recv(struct events_ctx *ec, int sock, short revents,
			 void *arg)
{
	if (revents & (POLLERR | POLLHUP | POLLNVAL))
		bfddp_errx(1, "poll returned bad value");

	/* Handle incoming packet. */
	bfd_recv_echo_packet(sock);

	/* Always read more. */
	events_ctx_add_fd(ec, sock, POLLIN, bfd_single_hop_echo_recv, arg);
}

static int
bfd_single_hop_echo_socket(void)
{
	int rv, sock, value;
	struct sockaddr_in sin;

	memset(&sin, 0, sizeof(sin));

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1)
		bfddp_err(1, "%s: socket", __func__);

	/* Set packet TTL. */
	value = 255;
	rv = setsockopt(sock, IPPROTO_IP, IP_TTL, &value, sizeof(value));
	if (rv == -1)
		bfddp_err(1, "%s: setsockopt(IP_TTL)", __func__);

	/* Receive the packet TTL information from `recvmsg`. */
	value = 1;
	rv = setsockopt(sock, IPPROTO_IP, IP_RECVTTL, &value, sizeof(value));
	if (rv == -1)
		bfddp_err(1, "%s: setsockopt(IP_RECVTTL)", __func__);

	/* Receive the interface information from `recvmsg`. */
	value = 1;
	rv = setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &value, sizeof(value));
	if (rv == -1)
		bfddp_err(1, "%s: setsockopt(IP_PKTINFO)", __func__);

	/* Re use addr if someone else is using it. */
	value = 1;
	rv = setsockopt(sock, IPPROTO_IP, SO_REUSEADDR, &value, sizeof(value));
	if (rv == -1)
		bfddp_err(1, "%s: setsockopt(SO_REUSEADDR)", __func__);

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(BFD_ECHO_PORT);
	if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) == -1)
		bfddp_err(1, "%s: bind", __func__);

	return sock;
}
