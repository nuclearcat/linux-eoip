/*
    file:   eoip.c
    Authors: Denys Fedoryshchenko aka NuclearCat <nuclearcat (at) nuclearcat.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.*
*/
/* Guarded so a build system that already passes -D_GNU_SOURCE is fine */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <linux/if_tun.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <poll.h>
#include <unistd.h>
#include <err.h>
#include <signal.h>
#include <assert.h>
#include <pthread.h>
#include <limits.h>
#include <libgen.h>
#include <asm/byteorder.h>
#include "minIni.h"
#include "config.h"

/* In theory maximum payload that can be handled is 65536, but if we use vectorized
   code with preallocated buffers - it is waste of space, especially for embedded setup.
   So if you want oversized packets - increase MAXPAYLOAD up to 65536 (or a bit less)
   If your choice performance - more vectors, to avoid expensive context switches
   TODO: readv, writev
*/

#define LINUX_THREAD_STACK_SIZE (PTHREAD_STACK_MIN * 2)

/* Sizing comes from the build, see the CMake cache variables */
#define MAXPAYLOAD  (EOIP_MAXPAYLOAD)
#define MAXRINGBUF  (RING_SLOTS)

/* Transmit batch depth. Each slot costs MAXPAYLOAD of buffer per tunnel,
   so it is usually smaller than MAXRINGBUF: most of the syscall saving
   arrives by 8-16 and the memory is per TX thread. */
#define TXBATCH (TX_BATCH)

#define sizearray(a)  (sizeof(a) / sizeof((a)[0]))

typedef struct {
    struct sockaddr_in	daddr;
    int			id;
    int			fd;
    struct ifreq	ifr;
    char		name[IFNAMSIZ];
    int			dynamic;
    int			warned;
    int			cpu;
}  Tunnel;

struct thr_rx {
    int 		raw_socket;
};

struct thr_tx {
    int			raw_socket;
    int			cpu;
    Tunnel		*tunnel;
};

struct gre_hdr {
    uint32_t		header;
    uint16_t		payload_size;
    uint16_t		tunnel_id;
} __attribute__ ((__packed__));

int numtunnels;
Tunnel *tunnels;
pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;

static void term_handler(int s)
{
  int		i;

  (void)s;
  /* Only async-signal-safe calls are allowed here: no perror(), and
     _exit() rather than exit(), which would run atexit handlers and
     flush stdio from a signal context */
  for(i=0; i<numtunnels; i++)
    close(tunnels[i].fd);

  _exit(0);
}

/* Two tunnels sharing an id cannot be told apart on the wire: the receive
   path matches whichever comes first in the array and the other never sees
   a packet. Startup only, so the quadratic walk costs nothing. */
static void check_unique_ids(void)
{
    int i, j;

    for (i = 1; i < numtunnels; i++) {
	for (j = 0; j < i; j++) {
	    if (tunnels[j].id == tunnels[i].id) {
		warnx("Tunnels %s and %s share id %d",
		      tunnels[j].name, tunnels[i].name, tunnels[i].id);
		exit(-1);
	    }
	}
    }
}

static int open_tun(Tunnel *tunnel) {
    int fd;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
      perror("socket() failed");
      return 1;
    }
    if ( (tunnel->fd = open("/dev/net/tun", O_RDWR)) < 0)
    {
	perror("open_tun: /dev/net/tun error");
	close(fd);
	return 1;
    }

    memset(&tunnel->ifr, 0x0, sizeof(tunnel->ifr));

    tunnel->ifr.ifr_flags = IFF_TAP|IFF_NO_PI;
    if (tunnel->name[0] != 0)
	snprintf(tunnel->ifr.ifr_name, IFNAMSIZ, "%s", tunnel->name);
    else
	snprintf(tunnel->ifr.ifr_name, IFNAMSIZ, "%s", "eoip%d");

    if (ioctl(tunnel->fd, TUNSETIFF, (void *)&tunnel->ifr) < 0) {
        perror("ioctl-1");
        close(tunnel->fd);
        close(fd);
        return 1;
    }

    tunnel->ifr.ifr_flags |= IFF_UP;
    tunnel->ifr.ifr_flags |= IFF_RUNNING;

    if (ioctl(fd, SIOCSIFFLAGS, (void *)&tunnel->ifr) < 0) {
        perror("ioctl-2");
        close(tunnel->fd);
        close(fd);
        return 1;
    }
    close(fd);
    return 0;
}

static void *thr_rx(void *threadid)
{
    struct sockaddr_in saddr[MAXRINGBUF];
    struct thr_rx *thr_rx_data = (struct thr_rx*)threadid;
    unsigned char *rxringbufptr[MAXRINGBUF];
    unsigned char *rxringbuffer;
    unsigned char *ptr;
    struct gre_hdr *ghdr;
    int i, ret, hlen, rxringbufused = 0, rxringbufconsumed, rxringpayload[MAXRINGBUF];
    int raw_socket = thr_rx_data->raw_socket;
#ifdef HAVE_RECVMMSG
    struct mmsghdr *msgs;
    struct iovec *iov;
#else
    socklen_t saddr_size;
#endif
    Tunnel *tunnel;
    fd_set rfds;

#ifdef HAVE_PTHREAD_SETAFFINITY_NP
    cpu_set_t cpuset;
    pthread_t thread = pthread_self();
    int cpu=0;

    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);

    ret = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
    if (ret)
	printf("Affinity error %d\n", ret);
    else
	printf("RX thread set to cpu %d\n", cpu);
#endif

    rxringbuffer = malloc(MAXPAYLOAD*MAXRINGBUF);
    if (!rxringbuffer) {
	perror("malloc()");
	exit(1);
    }
#ifdef HAVE_RECVMMSG
    /* Kept off the stack: this thread runs on LINUX_THREAD_STACK_SIZE */
    msgs = calloc(MAXRINGBUF, sizeof(*msgs));
    iov = calloc(MAXRINGBUF, sizeof(*iov));
    if (!msgs || !iov) {
	perror("calloc()");
	exit(1);
    }
#endif
    for (i=0;i<MAXRINGBUF;i++) {
	rxringbufptr[i] = rxringbuffer + (MAXPAYLOAD * i);
#ifdef HAVE_RECVMMSG
	iov[i].iov_base = rxringbufptr[i];
	iov[i].iov_len = MAXPAYLOAD;
	msgs[i].msg_hdr.msg_iov = &iov[i];
	msgs[i].msg_hdr.msg_iovlen = 1;
	msgs[i].msg_hdr.msg_name = &saddr[i];
#endif
    }

    while(1) {
	    FD_ZERO(&rfds);
	    FD_SET(raw_socket, &rfds);
	    ret = select(raw_socket+1, &rfds, NULL, NULL, NULL);
	    assert(rxringbufused == 0);
#ifdef HAVE_RECVMMSG
	    /* One syscall for the whole batch. msg_namelen is in/out, so it
	       has to be restored before every call. */
	    for (i = 0; i < MAXRINGBUF; i++)
		msgs[i].msg_hdr.msg_namelen = sizeof(saddr[0]);

	    ret = recvmmsg(raw_socket, msgs, MAXRINGBUF, MSG_DONTWAIT, NULL);
	    if (ret <= 0)
		continue;
	    rxringbufused = ret;
	    for (i = 0; i < rxringbufused; i++)
		rxringpayload[i] = msgs[i].msg_len;
#else
	    while (rxringbufused < MAXRINGBUF) {
		saddr_size = sizeof(saddr[0]);
		rxringpayload[rxringbufused] = recvfrom(raw_socket, rxringbufptr[rxringbufused], MAXPAYLOAD, 0,
						       (struct sockaddr *)&saddr[rxringbufused], &saddr_size);
		if (rxringpayload[rxringbufused] < 0)
		    break;
		rxringbufused++;
	    }

	    if (!rxringbufused)
		continue;
#endif

	    for (rxringbufconsumed = 0; rxringbufconsumed < rxringbufused; rxringbufconsumed++) {
		ptr = rxringbufptr[rxringbufconsumed];
		/* A raw socket hands up the IP header too, and its length is
		   not fixed at 20 once the sender or a router adds options */
		hlen = (ptr[0] & 0x0F) * 4;
		if (hlen < 20 ||
		    rxringpayload[rxringbufconsumed] < hlen + (int)sizeof(struct gre_hdr))
			continue;
		ghdr = (struct gre_hdr*)(ptr+hlen);
		/* Linear, and deliberately left that way. Measured with 400
		   tunnels and 200000 packets: targeting the id stored last in
		   the array cost the same 21 CPU ticks as targeting the id
		   stored first, so the scan depth was already free, and
		   replacing this with a hash table moved nothing. The array is
		   small, stays cache resident because every packet re-reads it,
		   and the branch predicts - a few hundred cycles against a per
		   packet budget dominated by the syscalls around it. If you are
		   chasing throughput, the per packet write() below is the cost,
		   not this loop. Measure before changing it. */
		for(i=0; i<numtunnels; i++)
		{
		    tunnel=tunnels + i;
		    if ((uint16_t)(__le16_to_cpu(ghdr->tunnel_id)) == (uint16_t) tunnel->id)
		    {
			/* This is a dynamic tunnel */
			if (tunnel->dynamic) {
			    if (saddr[rxringbufconsumed].sin_addr.s_addr != tunnel->daddr.sin_addr.s_addr) {
				/* Updating tunnel */
				pthread_mutex_lock(&mutex1);
				tunnel->daddr.sin_addr.s_addr = saddr[rxringbufconsumed].sin_addr.s_addr;
				pthread_mutex_unlock(&mutex1);
			    }
			} else if (saddr[rxringbufconsumed].sin_addr.s_addr != tunnel->daddr.sin_addr.s_addr) {
			    /* A static tunnel accepts only its configured peer */
			    if (!tunnel->warned) {
				tunnel->warned = 1;
				printf("Dropping packet for tunnel %s from a source other than dst\n",
				       tunnel->name);
			    }
			    break;
			}
			ret = write(tunnel->fd, ptr + hlen + sizeof(struct gre_hdr),
				    rxringpayload[rxringbufconsumed] - hlen - (int)sizeof(struct gre_hdr));
			/* Captured only because write() is warn_unused_result: a
			   full tap queue returns EAGAIN routinely under load, and
			   logging that would flood exactly when it hurts most. */
			(void)ret;
		        break;
		    }
		}
	    }
	    /* The consume loop above always drains the ring */
	    rxringbufused = 0;
    }
    return(NULL);
}

static void *thr_tx(void *threadid)
{
    struct thr_tx *thr_tx_data = (struct thr_tx*)threadid;
    Tunnel *tunnel = thr_tx_data->tunnel;
    int fd = tunnel->fd;
    int raw_socket = thr_tx_data->raw_socket;
    int payloadsz, i, n;
    unsigned char *slab;		/* TXBATCH payload buffers */
    struct gre_hdr *ghdrs;		/* one GRE header per slot */
    struct mmsghdr *msgs;
    struct iovec *iov;			/* two per slot: header, then payload */
    fd_set rfds;
#ifdef HAVE_PTHREAD_SETAFFINITY_NP
    int cpu = thr_tx_data->cpu;
    int ret;
    cpu_set_t cpuset;
    pthread_t thread = pthread_self();

    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);

    ret = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
    if (ret)
	printf("Affinity error %d\n", ret);
    else
	printf("TX thread(ID %d) set to cpu %d\n", tunnel->id, cpu);
#endif

    slab = malloc((size_t)MAXPAYLOAD * TXBATCH);
    ghdrs = calloc(TXBATCH, sizeof(*ghdrs));
    msgs = calloc(TXBATCH, sizeof(*msgs));
    iov = calloc((size_t)TXBATCH * 2, sizeof(*iov));
    if (!slab || !ghdrs || !msgs || !iov) {
	perror("malloc()");
	exit(1);
    }

    /* The header and the payload stay in separate buffers and are stitched
       together by the two iovecs, so nothing has to be copied to make them
       adjacent. Everything except payload_size is constant per tunnel. */
    for (i = 0; i < TXBATCH; i++) {
	ghdrs[i].header = __cpu_to_be32(0x20016400);
	ghdrs[i].tunnel_id = __cpu_to_le16((uint16_t)tunnel->id);

	iov[i*2].iov_base = &ghdrs[i];
	iov[i*2].iov_len = sizeof(ghdrs[i]);
	iov[i*2+1].iov_base = slab + (size_t)MAXPAYLOAD * i;

	msgs[i].msg_hdr.msg_iov = &iov[i*2];
	msgs[i].msg_hdr.msg_iovlen = 2;
	msgs[i].msg_hdr.msg_name = &tunnel->daddr;
	msgs[i].msg_hdr.msg_namelen = sizeof(tunnel->daddr);
    }

    while(1) {
	/* Drain whatever is already queued, up to a batch. The fd is
	   non-blocking, so this never waits: an idle tunnel simply gets a
	   batch of one and no latency is added. */
	for (n = 0; n < TXBATCH; n++) {
	    payloadsz = read(fd, iov[n*2+1].iov_base, MAXPAYLOAD);
	    if (payloadsz <= 0)
		break;
	    ghdrs[n].payload_size = __cpu_to_be16((uint16_t)payloadsz);
	    iov[n*2+1].iov_len = payloadsz;
	}

	if (!n) {
	    /* Only now is it worth a syscall to wait */
	    FD_ZERO(&rfds);
	    FD_SET(fd, &rfds);
	    select(fd+1, &rfds, NULL, NULL, NULL);
	    continue;
	}

	if (tunnel->dynamic)
	    pthread_mutex_lock(&mutex1);
#ifdef HAVE_SENDMMSG
	if (sendmmsg(raw_socket, msgs, n, 0) < 0)
	    perror("send() err");
#else
	for (i = 0; i < n; i++)
	    if (sendmsg(raw_socket, &msgs[i].msg_hdr, 0) < 0)
		perror("send() err");
#endif
	if (tunnel->dynamic)
	    pthread_mutex_unlock(&mutex1);
    }
    return(NULL);
}

int main(int argc, char **argv)
{
    struct thr_rx thr_rx_data;
    struct thr_tx *thr_tx_data;
    int i, sn, rc, optval = 262144;
    Tunnel *tunnel;
    struct sigaction sa;
    struct stat mystat;
    char section[64];
    char strbuf[256];
    char *configname;
    char defaultcfgname[] = "/etc/eoip.cfg";
    pthread_t *threads;
    pthread_attr_t attr;
    void *status;
    FILE *mfd;
    char *pidfile;
    char *cfgcopy;


    thr_rx_data.raw_socket = socket(PF_INET, SOCK_RAW, 47);
    if (thr_rx_data.raw_socket == -1) {

	if (errno == EPERM) {
	    printf("You need root privileges or CAP_NET_RAW capability to run this program\n");
	} else {
	    perror("raw socket()");
	}
	return(1);
    }
    if(setsockopt (thr_rx_data.raw_socket, SOL_SOCKET, SO_RCVBUF, &optval, sizeof (optval)))
	perror("setsockopt(RCVBUF)");
    if(setsockopt (thr_rx_data.raw_socket, SOL_SOCKET, SO_SNDBUF, &optval, sizeof (optval)))
	perror("setsockopt(SNDBUF)");

    if (argc == 3) {
	struct sockaddr_in serv_addr;
	serv_addr.sin_family = AF_INET;
	if (!inet_pton(AF_INET, argv[2], (struct in_addr *)&serv_addr.sin_addr.s_addr)) {
	    perror("bind address invalid");
	    exit(-1);
	}
	serv_addr.sin_port = 0;
	if (bind(thr_rx_data.raw_socket, (struct sockaddr *) &serv_addr,
		sizeof(serv_addr)) < 0)
	{
	    perror("bind error");
	    exit(-1);
	}
    }

    if (argc == 1)
	configname = defaultcfgname;
    else
	configname = argv[1];

    if (stat(configname, &mystat)) {
	    printf("Mikrotik-compatible EoIP %s\n",PACKAGE_VERSION);
	    printf("(c) Denys Fedoryshchenko <nuclearcat@nuclearcat.com>\n");
	    printf("%s [configfile [bindip]]\n",argv[0]);
	    exit(-1);
    }

    for (sn = 0; ini_getsection(sn, section, sizearray(section), configname) > 0; sn++) {
	numtunnels++;
     }

    if (numtunnels < 1) {
	warnx("No tunnel sections found in %s", configname);
	exit(-1);
    }

    tunnels = malloc(sizeof(Tunnel)*numtunnels);
    if (tunnels == NULL) {
	perror("malloc() failed");
	exit(-1);
    }
    memset(tunnels, 0x0, sizeof(Tunnel) * numtunnels);

    for (sn = 0; ini_getsection(sn, section, sizearray(section), configname) > 0; sn++) {
	tunnel = tunnels + sn;
	printf("Creating tunnel: %s num %d\n", section,sn);
	if (strlen(section) >= IFNAMSIZ) {
	    warnx("Tunnel name \"%s\" must be shorter than %d characters",
		  section, IFNAMSIZ);
	    exit(-1);
	}
	strncpy(tunnel->name, section, sizeof(tunnel->name) - 1);
	tunnel->daddr.sin_family = AF_INET;
	tunnel->daddr.sin_port = 0;
	tunnel->dynamic = 0;
	if (ini_gets(section, "dst", "0.0.0.0", strbuf, sizeof(strbuf), configname) < 1) {
	    printf("Destination for %s not correct\n", section);
	} else {
	    printf("Destination for %s: %s\n", section, strbuf);
	}

	if (!inet_pton(AF_INET, strbuf, (struct in_addr *)&tunnel->daddr.sin_addr.s_addr))
	{
	    warnx("Destination \"%s\" is not correct", strbuf);
	    exit(-1);
	}
	memset(tunnel->daddr.sin_zero, 0x0, sizeof(tunnel->daddr.sin_zero));
	tunnel->id = (int)ini_getl(section, "id", 0, configname);
	/* The id travels in a 16 bit field, so 65535 is the largest usable */
	if (tunnel->id == 0 || tunnel->id > 65535) {
	    warnx("ID of \"%d\" is not correct", tunnel->id);
	    exit(-1);
	}
	tunnel->dynamic = (int)ini_getl(section, "dynamic", 0, configname);
	/* A static tunnel only accepts its configured peer, so an unset dst
	   would drop every packet. A dynamic one learns dst as it goes. */
	if (!tunnel->dynamic && tunnel->daddr.sin_addr.s_addr == INADDR_ANY) {
	    warnx("Tunnel %s needs a dst, or dynamic=1 to learn one", section);
	    exit(-1);
	}
     }

    check_unique_ids();

    fcntl(thr_rx_data.raw_socket, F_SETFL, O_NONBLOCK);

    for(i=0;i<numtunnels;i++)
    {
      tunnel = tunnels + i;
      if (open_tun(tunnel)) {
        exit(-1);
      }
    }

    memset(&sa, 0x0, sizeof(sa));
    sa.sa_handler = term_handler;
    sigaction( SIGTERM , &sa, 0);
    sigaction( SIGINT , &sa, 0);
    threads = malloc(sizeof(pthread_t)*(numtunnels+1));
    if (threads == NULL) {
	perror("malloc() failed");
	exit(-1);
    }

    /* Fork after creating tunnels, useful for scripts */
    if (daemon(1, 1)) {
	perror("daemon() failed");
	exit(-1);
    }

    /* POSIX basename() may modify its argument, so hand it a copy */
    if ((cfgcopy = strdup(configname)) == NULL)
	exit(1);
    if (asprintf(&pidfile,"/var/run/eoip-%s",basename(cfgcopy)) == -1)
	exit(1);
    free(cfgcopy);

    mfd = fopen(pidfile, "w");
    if (mfd == NULL) {
	warn("cannot write pidfile %s", pidfile);
    } else {
	fprintf(mfd,"%d\n", getpid());
	fclose(mfd);
    }

    /* structure of Mikrotik EoIP:
	... IP header ...
	4 byte - GRE info
	2 byte - tunnel id
    */

    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, LINUX_THREAD_STACK_SIZE);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    rc = pthread_create(&threads[0], &attr, thr_rx, (void *)&thr_rx_data);
    if (rc) {
	errno = rc;
	perror("pthread_create() RX");
	exit(-1);
    }

    for(i=0;i<numtunnels;i++) {
	tunnel=tunnels + i;
	fcntl(tunnel->fd, F_SETFL, O_NONBLOCK);
	/* Allocate for each thread */
	thr_tx_data = malloc(sizeof(struct thr_tx));
	if (thr_tx_data == NULL) {
	    perror("malloc() failed");
	    exit(-1);
	}
	thr_tx_data->tunnel = tunnel;
	thr_tx_data->cpu = i+1;
	thr_tx_data->raw_socket = thr_rx_data.raw_socket;
	rc = pthread_create(&threads[i+1], &attr, thr_tx, (void *)thr_tx_data);
	if (rc) {
	    errno = rc;
	    perror("pthread_create() TX");
	    exit(-1);
	}
    }
    rc = pthread_join(threads[0], &status);
    return(0);
}
