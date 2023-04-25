#include <assert.h>
#include <math.h>
#include <netdb.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/*
 * NTP offset measurement tool, see https://github.com/bsdphk/Ntimed
 */

/*-
 * Copyright (c) 2014 Poul-Henning Kamp
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#define AZ(foo)		do { assert((foo) == 0); } while (0)
#define AN(foo)		do { assert((foo) != 0); } while (0)

#define WRONG(foo)				\
	do {					\
		/*lint -save -e506 */		\
		assert(0 == (uintptr_t)foo);	\
		/*lint -restore */		\
	} while (0)

#define __match_proto__(xxx)		/*lint -e{818} */

#define NEEDLESS_RETURN(foo)	return(foo)

#define INIT_OBJ(to, type_magic)					\
	do {								\
		(void)memset(to, 0, sizeof *to);			\
		(to)->magic = (type_magic);				\
	} while (0)

#define ALLOC_OBJ(to, type_magic)					\
	do {								\
		(to) = calloc(1L, sizeof *(to));			\
		if ((to) != NULL)					\
			(to)->magic = (type_magic);			\
	} while (0)

#define FREE_OBJ(to)							\
	do {								\
		(to)->magic = (0);					\
		free(to);						\
	} while (0)

#define VALID_OBJ(ptr, type_magic)					\
	((ptr) != NULL && (ptr)->magic == (type_magic))

#define CHECK_OBJ(ptr, type_magic)					\
	do {								\
		assert((ptr)->magic == type_magic);			\
	} while (0)

#define CHECK_OBJ_NOTNULL(ptr, type_magic)				\
	do {								\
		assert((ptr) != NULL);					\
		assert((ptr)->magic == type_magic);			\
	} while (0)

#define CHECK_OBJ_ORNULL(ptr, type_magic)				\
	do {								\
		if ((ptr) != NULL)					\
			assert((ptr)->magic == type_magic);		\
	} while (0)

#define CAST_OBJ(to, from, type_magic)					\
	do {								\
		(to) = (from);						\
		if ((to) != NULL)					\
			CHECK_OBJ((to), (type_magic));			\
	} while (0)

#define CAST_OBJ_NOTNULL(to, from, type_magic)				\
	do {								\
		(to) = (from);						\
		assert((to) != NULL);					\
		CHECK_OBJ((to), (type_magic));				\
	} while (0)

#define NANO_FRAC	18446744074ULL		// 2^64 / 1e9

struct timestamp {
	unsigned	magic;
#define TIMESTAMP_MAGIC	0x344cd213
	uint64_t	sec;		// Really:  time_t
	uint64_t	frac;
};

static struct timestamp *
ts_fixstorage(struct timestamp *storage)
{
	if (storage == NULL) {
		ALLOC_OBJ(storage, TIMESTAMP_MAGIC);
		AN(storage);
	} else {
		AN(storage);
		memset(storage, 0, sizeof *storage);
		storage->magic = TIMESTAMP_MAGIC;
	}
	return (storage);
}

struct timestamp *
TS_Nanosec(struct timestamp *storage, int64_t sec, int64_t nsec)
{

	storage = ts_fixstorage(storage);

	assert(sec >= 0);
	assert(nsec >= 0);
	assert(nsec < 1000000000);
	storage->sec = (uint64_t)sec;
	storage->frac = (uint32_t)nsec * NANO_FRAC;
	return (storage);
}

double
TS_Diff(const struct timestamp *t1, const struct timestamp *t2)
{
	double d;

	CHECK_OBJ_NOTNULL(t1, TIMESTAMP_MAGIC);
	CHECK_OBJ_NOTNULL(t2, TIMESTAMP_MAGIC);
	d = ldexp((double)t1->frac - (double)t2->frac, -64);
	d += ((double)t1->sec - (double)t2->sec);

	return (d);
}

typedef struct timestamp *tb_now_f(struct timestamp *);

static struct timestamp * __match_proto__(tb_now_f)
kt_now(struct timestamp *storage)
{
	struct timeval tv;

	AZ(gettimeofday(&tv, NULL));
	return (TS_Nanosec(storage, tv.tv_sec, tv.tv_usec * 1000LL));
}

static tb_now_f *TB_Now = kt_now;

enum ntp_mode {
#define NTP_MODE(n, l, u)	NTP_MODE_##u = n,
NTP_MODE(0,	mode0, MODE0)
NTP_MODE(1,	symact, SYMACT)
NTP_MODE(2,	sympas, SYMPAS)
NTP_MODE(3,	client, CLIENT)
NTP_MODE(4,	server, SERVER)
NTP_MODE(5,	bcast, BCAST)
NTP_MODE(6,	ctrl, CTRL)
NTP_MODE(7,	mode7, MODE7)
#undef NTP_MODE
};

enum ntp_leap {
#define NTP_LEAP(n, l, u)	NTP_LEAP_##u = n,
NTP_LEAP(0,	none, NONE)
NTP_LEAP(1,	ins, INS)
NTP_LEAP(2,	del, DEL)
NTP_LEAP(3,	unknown, UNKNOWN)
#undef NTP_LEAP
};

struct ntp_packet {
	unsigned		magic;
#define NTP_PACKET_MAGIC	0x78b7f0be

	enum ntp_leap		ntp_leap;
	uint8_t			ntp_version;
	enum ntp_mode		ntp_mode;
	uint8_t			ntp_stratum;
	uint8_t			ntp_poll;
	int8_t			ntp_precision;
	struct timestamp	ntp_delay;
	struct timestamp	ntp_dispersion;
	uint8_t			ntp_refid[4];
	struct timestamp	ntp_reference;
	struct timestamp	ntp_origin;
	struct timestamp	ntp_receive;
	struct timestamp	ntp_transmit;

	struct timestamp	ts_rx;
};

static __inline uint16_t
Be16dec(const void *pp)
{
	uint8_t const *p = (uint8_t const *)pp;

	return ((p[0] << 8) | p[1]);
}

static __inline uint32_t
Be32dec(const void *pp)
{
	uint8_t const *p = (uint8_t const *)pp;

	return (((unsigned)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]);
}

static __inline void
Be16enc(void *pp, uint16_t u)
{
	uint8_t *p = (uint8_t *)pp;

	p[0] = (u >> 8) & 0xff;
	p[1] = u & 0xff;
}

static __inline void
Be32enc(void *pp, uint32_t u)
{
	uint8_t *p = (uint8_t *)pp;

	p[0] = (u >> 24) & 0xff;
	p[1] = (u >> 16) & 0xff;
	p[2] = (u >> 8) & 0xff;
	p[3] = u & 0xff;
}

/*
 * Seconds between 1900 (NTP epoch) and 1970 (UNIX epoch).
 * 17 is the number of leapdays.
 */
#define NTP_UNIX        (((1970U - 1900U) * 365U + 17U) * 24U * 60U * 60U)

static void
ntp64_2ts(struct timestamp *ts, const uint8_t *ptr)
{

	INIT_OBJ(ts, TIMESTAMP_MAGIC);
	ts->sec = Be32dec(ptr) - NTP_UNIX;
	ts->frac = (uint64_t)Be32dec(ptr + 4) << 32ULL;
}

static void
ntp32_2ts(struct timestamp *ts, const uint8_t *ptr)
{

	INIT_OBJ(ts, TIMESTAMP_MAGIC);
	ts->sec = Be16dec(ptr);
	ts->frac = (uint64_t)Be16dec(ptr + 2) << 48ULL;
}

struct ntp_packet *
NTP_Packet_Unpack(struct ntp_packet *np, void *ptr, ssize_t len)
{
	uint8_t *p = ptr;

	AN(ptr);
	if (len != 48) {
		/* XXX: Diagnostic */
		return (NULL);
	}

	if (np == NULL) {
		ALLOC_OBJ(np, NTP_PACKET_MAGIC);
		AN(np);
	} else {
		INIT_OBJ(np, NTP_PACKET_MAGIC);
	}

	np->ntp_leap = (enum ntp_leap)(p[0] >> 6);
	np->ntp_version = (p[0] >> 3) & 0x7;
	np->ntp_mode = (enum ntp_mode)(p[0] & 0x07);
	np->ntp_stratum = p[1];
	np->ntp_poll = p[2];
	np->ntp_precision = (int8_t)p[3];
	ntp32_2ts(&np->ntp_delay, p + 4);
	ntp32_2ts(&np->ntp_dispersion, p + 8);
	memcpy(np->ntp_refid, p + 12, 4L);
	ntp64_2ts(&np->ntp_reference, p + 16);
	ntp64_2ts(&np->ntp_origin, p + 24);
	ntp64_2ts(&np->ntp_receive, p + 32);
	ntp64_2ts(&np->ntp_transmit, p + 40);
	return (np);
}

static void
ts_2ntp32(uint8_t *dst, const struct timestamp *ts)
{

	CHECK_OBJ_NOTNULL(ts, TIMESTAMP_MAGIC);
	assert(ts->sec < 65536);
	Be16enc(dst, (uint16_t)ts->sec);
	Be16enc(dst + 2, ts->frac >> 48ULL);
}

static void
ts_2ntp64(uint8_t *dst, const struct timestamp *ts)
{

	CHECK_OBJ_NOTNULL(ts, TIMESTAMP_MAGIC);
	Be32enc(dst, ts->sec + NTP_UNIX);
	Be32enc(dst + 4, ts->frac >> 32ULL);
}

size_t
NTP_Packet_Pack(void *ptr, ssize_t len, struct ntp_packet *np)
{
	uint8_t *pbuf = ptr;

	AN(ptr);
	assert(len >= 48);
	CHECK_OBJ_NOTNULL(np, NTP_PACKET_MAGIC);
	assert(np->ntp_version < 8);
	assert(np->ntp_stratum < 15);

	pbuf[0] = (uint8_t)np->ntp_leap;
	pbuf[0] <<= 3;
	pbuf[0] |= np->ntp_version;
	pbuf[0] <<= 3;
	pbuf[0] |= (uint8_t)np->ntp_mode;
	pbuf[1] = np->ntp_stratum;
	pbuf[2] = np->ntp_poll;
	pbuf[3] = (uint8_t)np->ntp_precision;
	ts_2ntp32(pbuf + 4, &np->ntp_delay);
	ts_2ntp32(pbuf + 8, &np->ntp_dispersion);
	memcpy(pbuf + 12, np->ntp_refid, 4L);
	ts_2ntp64(pbuf + 16, &np->ntp_reference);
	ts_2ntp64(pbuf + 24, &np->ntp_origin);
	ts_2ntp64(pbuf + 32, &np->ntp_receive);

	TB_Now(&np->ntp_transmit);
	ts_2ntp64(pbuf + 40, &np->ntp_transmit);

	/* Reverse again, to avoid subsequent trouble from rounding. */
	ntp64_2ts(&np->ntp_transmit, pbuf + 40);

	return (48);
}

struct udp_socket {
	unsigned		magic;
#define UDP_SOCKET_MAGIC	0x302a563f

	int			fd4;
	int			fd6;
};

static int
udp_sock(int fam)
{
	int fd;
	int i;

	fd = socket(fam, SOCK_DGRAM, 0);
	if (fd < 0)
		return (fd);

#ifdef SO_TIMESTAMPNS
	i = 1;
	(void)setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPNS, &i, sizeof i);
#elif defined(SO_TIMESTAMP)
	i = 1;
	(void)setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &i, sizeof i);
#endif
	return (fd);
}

struct udp_socket *
UdpTimedSocket(void)
{
	struct udp_socket *usc;

	ALLOC_OBJ(usc, UDP_SOCKET_MAGIC);
	AN(usc);
	usc->fd4 = udp_sock(AF_INET);
	usc->fd6 = udp_sock(AF_INET6);
	if (usc->fd4 < 0 && usc->fd6 < 0) {
		fprintf(stderr, "socket(2) failed\n");
		exit(EXIT_FAILURE);
	}
	return (usc);
}

ssize_t
UdpTimedRx(const struct udp_socket *usc,
    sa_family_t fam,
    struct sockaddr_storage *ss, socklen_t *sl,
    struct timestamp *ts, void *buf, ssize_t len, double tmo)
{
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsg;
	u_char ctrl[1024];
	ssize_t rl;
	int i;
	int tmo_msec;
	struct pollfd pfd[1];

	CHECK_OBJ_NOTNULL(usc, UDP_SOCKET_MAGIC);
	AN(ss);
	AN(sl);
	AN(ts);
	AN(buf);
	assert(len > 0);

	if (fam == AF_INET)
		pfd[0].fd = usc->fd4;
	else if (fam == AF_INET6)
		pfd[0].fd = usc->fd6;
	else
		WRONG("Wrong family in UdpTimedRx");

	pfd[0].events = POLLIN;
	pfd[0].revents = 0;

	if (tmo == 0.0) {
		tmo_msec = -1;
	} else {
		tmo_msec = lround(1e3 * tmo);
		if (tmo_msec <= 0)
			tmo_msec = 0;
	}
	i = poll(pfd, 1, tmo_msec);

	if (i < 0) {
		fprintf(stderr,"poll(2) failed\n");
		exit(EXIT_FAILURE);
	}

	if (i == 0)
		return (0);

	/* Grab a timestamp in case none of the SCM_TIMESTAMP* works */
	TB_Now(ts);

	memset(&msg, 0, sizeof msg);
	msg.msg_name = (void*)ss;
	msg.msg_namelen = sizeof *ss;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = ctrl;
	msg.msg_controllen = sizeof ctrl;
	iov.iov_base = buf;
	iov.iov_len = (size_t)len;
	memset(ctrl, 0, sizeof ctrl);
	cmsg = (void*)ctrl;

	rl = recvmsg(pfd[0].fd, &msg, 0);
	if (rl <= 0)
		return (rl);

	*sl = msg.msg_namelen;

	if (msg.msg_flags != 0) {
		// Debug(ocx, "msg_flags = 0x%x", msg.msg_flags);
		return (-1);
	}

	for(;cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
#ifdef SCM_TIMESTAMPNS
		if (cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type == SCM_TIMESTAMPNS &&
		    cmsg->cmsg_len == CMSG_LEN(sizeof(struct timeval))) {
			struct timespec tsc;
			memcpy(&tsc, CMSG_DATA(cmsg), sizeof tsc);
			(void)TS_Nanosec(ts, tsc.tv_sec, tsc.tv_nsec);
			continue;
		}
#endif
#ifdef SCM_TIMESTAMP
		if (cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type == SCM_TIMESTAMP &&
		    cmsg->cmsg_len == CMSG_LEN(sizeof(struct timeval))) {
			struct timeval tv;
			memcpy(&tv, CMSG_DATA(cmsg), sizeof tv);
			(void)TS_Nanosec(ts, tv.tv_sec, tv.tv_usec * 1000LL);
			continue;
		}
#endif
		// Debug(ocx, "RX-msg: %d %d %u ",
		//     cmsg->cmsg_level, cmsg->cmsg_type, cmsg->cmsg_len);
		// DebugHex(ocx, CMSG_DATA(cmsg), cmsg->cmsg_len);
		// Debug(ocx, "\n");

	}
	return (rl);
}

ssize_t
Udp_Send(const struct udp_socket *usc,
	const void *ss, socklen_t sl, const void *buf, size_t len)
{
	const struct sockaddr *sa;

	CHECK_OBJ_NOTNULL(usc, UDP_SOCKET_MAGIC);
	AN(ss);
	AN(sl);
	AN(buf);
	AN(len);
	sa = ss;
	if (sa->sa_family == AF_INET)
		return (sendto(usc->fd4, buf, len, 0, ss, sl));
	if (sa->sa_family == AF_INET6)
		return (sendto(usc->fd6, buf, len, 0, ss, sl));

	WRONG("Wrong AF_");
	NEEDLESS_RETURN(0);
}

void
NTP_Tool_Client_Req(struct ntp_packet *np)
{
	AN(np);
	INIT_OBJ(np, NTP_PACKET_MAGIC);

	np->ntp_leap = NTP_LEAP_UNKNOWN;
	np->ntp_version = 4;
	np->ntp_mode = NTP_MODE_CLIENT;
	np->ntp_stratum = 0;
	np->ntp_poll = 4;
	np->ntp_precision = -6;
	INIT_OBJ(&np->ntp_delay, TIMESTAMP_MAGIC);
	np->ntp_delay.sec = 1;
	INIT_OBJ(&np->ntp_dispersion, TIMESTAMP_MAGIC);
	np->ntp_dispersion.sec = 1;
	INIT_OBJ(&np->ntp_reference, TIMESTAMP_MAGIC);
	INIT_OBJ(&np->ntp_origin, TIMESTAMP_MAGIC);
	INIT_OBJ(&np->ntp_receive, TIMESTAMP_MAGIC);
}

int
SA_Equal(const void *sa1, size_t sl1, const void *sa2, size_t sl2)
{
	const struct sockaddr *s1, *s2;
	const struct sockaddr_in *s41, *s42;
	const struct sockaddr_in6 *s61, *s62;

	AN(sa1);
	AN(sa2);
	assert(sl1 >= sizeof(struct sockaddr));
	assert(sl2 >= sizeof(struct sockaddr));

	s1 = sa1;
	s2 = sa2;
	if (s1->sa_family != s2->sa_family)
		return (0);

	if (s1->sa_family == AF_INET) {
		assert(sl1 >= sizeof(struct sockaddr_in));
		assert(sl2 >= sizeof(struct sockaddr_in));
		s41 = sa1;
		s42 = sa2;
		if (s41->sin_port != s42->sin_port)
			return (0);
		if (memcmp(&s41->sin_addr, &s42->sin_addr,
		      sizeof s41->sin_addr))
			return (0);
		return (1);
	}

	if (s1->sa_family == AF_INET6) {
		assert(sl1 >= sizeof(struct sockaddr_in6));
		assert(sl2 >= sizeof(struct sockaddr_in6));
		s61 = sa1;
		s62 = sa2;
		if (s61->sin6_port != s62->sin6_port)
			return (0);
		if (s61->sin6_scope_id != s62->sin6_scope_id)
			return (0);
		if (memcmp(&s61->sin6_addr, &s62->sin6_addr,
		    sizeof s61->sin6_addr))
			return (0);
		return (1);
	}
	return (0);
}


/**********************************************************************
 * Application logic
 */

int main(int argc, char *argv[]) {
	if (argc < 2) {
		exit(EXIT_FAILURE);
	}

	char *hostname = argv[1];

	struct addrinfo hints, *ai;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	int r = getaddrinfo(hostname, "ntp", &hints, &ai);
	if (r) {
		fprintf(stderr, "hostname '%s', port 'ntp': %s\n", hostname, gai_strerror(r));
		exit(EXIT_FAILURE);
	}

	struct ntp_packet *tx_pkt;
	ALLOC_OBJ(tx_pkt, NTP_PACKET_MAGIC);
	AN(tx_pkt);

	struct ntp_packet *rx_pkt;
	ALLOC_OBJ(rx_pkt, NTP_PACKET_MAGIC);
	AN(rx_pkt);

	struct udp_socket *udps = UdpTimedSocket();
	double tmo = 1.0;

	char buf[128];
	size_t len;
	struct sockaddr_storage rss;
	socklen_t rssl;
	ssize_t l;
	int i;
	struct timestamp t0, t1, t2;
	double d;

	NTP_Tool_Client_Req(tx_pkt);
	len = NTP_Packet_Pack(buf, sizeof buf, tx_pkt);

	l = Udp_Send(udps, ai->ai_addr, ai->ai_addrlen, buf, len);
	if (l != (ssize_t)len) {
		exit(EXIT_FAILURE);
	}

	(void)TB_Now(&t0);

	while (1) {
		(void)TB_Now(&t1);
		d = TS_Diff(&t1, &t0);

		i = UdpTimedRx(udps, ai->ai_addr->sa_family, &rss, &rssl, &t2,
		    buf, sizeof buf, tmo - d);
		if (i <= 0) {
			break;
		}
		if (i != 48) {
			continue;
		}

		if (!SA_Equal(ai->ai_addr, ai->ai_addrlen, &rss, rssl)) {
			continue;
		}

		AN(NTP_Packet_Unpack(rx_pkt, buf, i));
		rx_pkt->ts_rx = t2;

		/* Ignore packets which are not replies to our packet */
		if (TS_Diff(&tx_pkt->ntp_transmit, &rx_pkt->ntp_origin) != 0.0) {
			continue;
		}

		printf("%+.9lf, %+.9lf\n",
			((TS_Diff(&rx_pkt->ntp_receive, &rx_pkt->ntp_origin)
			+ TS_Diff(&rx_pkt->ntp_transmit, &rx_pkt->ts_rx)) / 2.0),
			(TS_Diff(&rx_pkt->ts_rx, &rx_pkt->ntp_origin)
			- TS_Diff(&rx_pkt->ntp_transmit, &rx_pkt->ntp_receive)));
		break;
	}

	freeaddrinfo(ai);
	exit(EXIT_SUCCESS);
}

