/*
    file:   vip.c
    Authors: 
    Linux initial code: Denys Fedoryshchenko aka NuclearCat <nuclearcat (at) nuclearcat.com>

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
#include "config.h"
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
#include <sched.h>
#include "minIni.h"
#include <getopt.h>

#ifdef HAVE_LIBLZO2
#include <lzo/lzo1x.h>
#endif

//#ifdef GCRYPT
//#include <gcrypt.h>
//#define  ADDON 2
//#else
#define  ADDON 0
//#endif

const unsigned char xormask = 0x55; //3847611839 in hex.

/* In theory maximum payload that can be handled is 65536, but if we use vectorized
   code with preallocated buffers - it is waste of space, especially for embedded setup.
   So if you want oversized packets - increase MAXPAYLOAD up to 65536 (or a bit less)
   If you choice performance - more vectors, to avoid expensive context switches
*/

/* Sizing comes from the build, see the CMake cache variables */
#define MAXPAYLOAD (VIP_MAXPAYLOAD)
#define MAXRINGBUF (RING_SLOTS)

#define BIT_COMPRESSED 		(1 << 0)
#define BIT_PACKED 		(1 << 1)
#define BIT_SERVICE 		(1 << 2)

#define sizearray(a)  (sizeof(a) / sizeof((a)[0]))

#ifndef __cacheline_aligned
#define __cacheline_aligned \
__attribute__((__aligned__(SMP_CACHE_BYTES), \
__section__(".data.cacheline_aligned")))
#endif /* __cacheline_aligned */
#define __read_mostly __attribute__((__section__(".data.read_mostly")))

uint32_t verbose = 0;

typedef struct
{
   struct sockaddr_in   daddr[64];
   int			daddr_cnt;
   int                  id;
   int                  fd;
   struct ifreq		ifr;
   char 		name[IFNAMSIZ];
   struct thr_tx 	*thr_tx_data;
   int			warned;
}  Tunnel;

struct thr_rx
{
    int raw_socket;
};

struct thr_tx
{
    int 			raw_socket;
    Tunnel 			*tunnel;
    int 			cpu;
    unsigned int		packdelay;
    int				maxpacked;
    int				compression;
};

/*
struct snd_buf
{
    unsigned char		data[MAXPAYLOAD];
    unsigned int 		size;
    unsigned int		crc;
};
*/


static int numtunnels;
static Tunnel *tunnels;


/*
void error( const char* format, ...) {
    va_list args;
    va_start( args, format );
    vfprintf( stderr, format, args );
    va_end( args );
    fprintf( stderr, "\n" );
}
*/

static void xor (unsigned char *mem, unsigned int size) {
    unsigned int i;
    for (i = 0; i < size; i++) {
	*((unsigned char *)mem+i) ^= xormask;
    }
}

/* ---------------------------------------------------------------------------
 * CPU placement. The set a process may run on is not necessarily every CPU on
 * the box - a cpuset, taskset or systemd CPUAffinity can restrict it - so ask
 * for the affinity mask rather than the CPU count, and only ever pin to a CPU
 * that is actually in it.
 * ------------------------------------------------------------------------ */
#ifdef HAVE_PTHREAD_SETAFFINITY_NP
/* Probed on first use, so this cannot depend on being called early enough */
static int cpu_allowed_count(void)
{
    static int cpu_count;		/* CPUs we may use, 0 until probed */
    cpu_set_t set;

    if (!cpu_count && sched_getaffinity(0, sizeof(set), &set) == 0)
	cpu_count = CPU_COUNT(&set);
    return cpu_count;
}

/* The n-th CPU this process is allowed to use, or -1 if there is none */
static int allowed_cpu(int n)
{
    cpu_set_t set;
    int i;

    if (sched_getaffinity(0, sizeof(set), &set) != 0)
	return -1;
    for (i = 0; i < CPU_SETSIZE; i++)
	if (CPU_ISSET(i, &set) && n-- == 0)
	    return i;
    return -1;
}

/* The RX thread serves every tunnel, so it keeps the first CPU to itself when
   there is more than one to go around. The TX threads share what is left,
   round robin, so more tunnels than CPUs is normal rather than an error. */
static int rx_cpu(void)
{
    return allowed_cpu(0);
}

static int tx_cpu(int n)
{
    int count = cpu_allowed_count();

    if (count <= 1)
	return allowed_cpu(0);
    return allowed_cpu(1 + (n % (count - 1)));
}

/* Best effort: a failure is reported and the thread just stays unpinned */
static void pin_to_cpu(int cpu, const char *what, int id)
{
    cpu_set_t set;
    int ret;

    if (cpu < 0)
	return;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    ret = pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
    if (ret)
	printf("%s thread(ID %d) affinity error %d\n", what, id, ret);
    else
	printf("%s thread(ID %d) set to cpu %d\n", what, id, cpu);
}
#else
static int rx_cpu(void) { return -1; }
static int tx_cpu(int n) { (void)n; return -1; }
static void pin_to_cpu(int cpu, const char *what, int id)
{
    (void)cpu; (void)what; (void)id;
}
#endif

/* Only a configured peer may inject into a tunnel */
static int peer_allowed(const Tunnel *tunnel, in_addr_t src)
{
    int i;

    for (i = 0; i < tunnel->daddr_cnt; i++)
	if (tunnel->daddr[i].sin_addr.s_addr == src)
	    return 1;

    return 0;
}

static void term_handler(int s)
{
    int i;

    (void)s;
    /* Only async-signal-safe calls are allowed here */
    for (i = 0; i < numtunnels; i++)
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

static int open_tun(Tunnel *tunnel)
{
    int fd;
    
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
      perror("socket() failed");
      return 1;
    }
    if ( (tunnel->fd = open("/dev/net/tun",O_RDWR)) < 0)
    {
	perror("open_tun: /dev/net/tun error");
	close(fd);
	return 1;
    }

    memset(&tunnel->ifr, 0x0, sizeof(tunnel->ifr));

    tunnel->ifr.ifr_flags = IFF_TUN|IFF_NO_PI;
    if (tunnel->name[0] != 0)
	snprintf(tunnel->ifr.ifr_name, IFNAMSIZ, "%s", tunnel->name);
    else
	snprintf(tunnel->ifr.ifr_name, IFNAMSIZ, "%s", "vip%d");

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
    unsigned char *rxringbufptr[MAXRINGBUF];
    struct sockaddr_in saddr[MAXRINGBUF];
    int rxringpayload[MAXRINGBUF];
#ifdef HAVE_RECVMMSG
    struct mmsghdr *msgs;
    struct iovec *iov;
#else
    socklen_t saddr_size;
#endif
    unsigned char *rxringbuffer;
    int rxringbufused = 0, rxringconsumed;
    unsigned char *ptr;
    int i,ret,hlen,payoff;
    struct thr_rx *thr_rx_data = (struct thr_rx*)threadid;
    Tunnel *tunnel;
    int raw_socket = thr_rx_data->raw_socket;
#ifdef HAVE_LIBLZO2
    unsigned char *decompressed = NULL;
    lzo_uint decompressedsz;
#endif
    fd_set rfds;

#ifdef HAVE_LIBLZO2
    if (posix_memalign((void*)&decompressed, 64, MAXPAYLOAD)) {
	printf("memalign failed\n");
	pthread_exit(0);
    }
#endif
    
    pin_to_cpu(rx_cpu(), "RX", 0);
#ifdef HAVE_LIBLZO2
    ret = lzo_init();    
    if (ret != LZO_E_OK) {
	printf("LZO init failed\n");
	exit(1);
    }

#endif

    rxringbuffer = malloc(MAXPAYLOAD*MAXRINGBUF);

    if (!rxringbuffer) {
	perror("malloc()");
	exit(1);
    }
#ifdef HAVE_RECVMMSG
    msgs = calloc(MAXRINGBUF, sizeof(*msgs));
    iov = calloc(MAXRINGBUF, sizeof(*iov));
    if (!msgs || !iov) {
	perror("calloc()");
	exit(1);
    }
#endif
    for (i=0;i<MAXRINGBUF;i++) {
	rxringbufptr[i] = rxringbuffer+(MAXPAYLOAD*i);
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

	    for (rxringconsumed = 0; rxringconsumed < rxringbufused; rxringconsumed++) {
		ptr = rxringbufptr[rxringconsumed];
		/* A raw socket hands up the IP header too, and its length is
		   not fixed at 20 once the sender or a router adds options */
		hlen = (ptr[0] & 0x0F) * 4;
		payoff = hlen + 2;	/* first byte after the VIP header */
		if (hlen < 20 || rxringpayload[rxringconsumed] < payoff)
		    continue;
		/* TX only obfuscates from the VIP header on - the IP header is
		   built by the kernel - so unmask exactly that range */
		xor(ptr + hlen, rxringpayload[rxringconsumed] - hlen);
		ret = 0;
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
        	for(i=0;i<numtunnels;i++)
        	{
		    tunnel=tunnels + i;
		    if (ptr[hlen] == (unsigned char )(tunnel->id) )
		    {
			if (!peer_allowed(tunnel, saddr[rxringconsumed].sin_addr.s_addr)) {
			    if (!tunnel->warned) {
				tunnel->warned = 1;
				printf("Dropping packet for tunnel %s from a source other than dst\n",
				       tunnel->name);
			    }
			    break;
			}
#ifdef HAVE_LIBLZO2
			if (ptr[hlen+1] & BIT_COMPRESSED) {
			    /* Output is copied back to ptr+payoff inside a
			       MAXPAYLOAD slot, so it must not exceed the rest */
			    decompressedsz = MAXPAYLOAD - payoff;
			    if (lzo1x_decompress_safe(ptr+payoff,rxringpayload[rxringconsumed]-payoff,decompressed,&decompressedsz,NULL) == LZO_E_OK) {
				memcpy(ptr+payoff,decompressed,decompressedsz);
				rxringpayload[rxringconsumed] = decompressedsz + payoff;
			    } else {				
				perror("lzo feeling bad about your packet ");\
				break;
				//exit(1);
			    }
			}
			

#else

			if (ptr[hlen+1] & BIT_COMPRESSED) {
			    static int warned;
			    if (!warned) {
				warned = 1;
				printf("Compressed packet received but this build has no liblzo2, dropping\n");
			    }
			    break;
			}
#endif

			if ((ptr[hlen+1] & BIT_PACKED)) {
			    unsigned int offset = payoff; /* IP header + tunnel id and bitfield */
			    unsigned short total;

			    while(1) {
				uint8_t ihl;

				/* A whole IP header has to be there before its
				   length field can be trusted */
				if ((int)(offset+20) > rxringpayload[rxringconsumed]) {
				    printf("truncated packed header at %u of %d\n",offset,rxringpayload[rxringconsumed]);
				    break;
				}
				ihl = ptr[offset] & 0xF;
				if (ihl != 5) {
				    printf("Non-standard IHL %d\n", ihl);
				}
				/* Unaligned once a preceding packet had an odd size */
				memcpy(&total, ptr+offset+2, sizeof(total));
				total = ntohs(total);

				if (total < 20 || (int)(offset+total)>rxringpayload[rxringconsumed]) {
				    printf("invalid offset! %d > %d IP size %d\n",(offset+total),rxringpayload[rxringconsumed],total);
				    break;
				}
				ret = write(tunnel->fd,ptr+offset,total);
				if (ret<0) {
				    printf("invalid offset! %d > %d IP size %d\n",(offset+total),rxringpayload[rxringconsumed],total);
				    perror("tunnel write error #1: ");
				    break;
				}

				offset += total;
				
				/* This is correct, finished processing packed data */
				if ((int)offset == rxringpayload[rxringconsumed])
				    break;
			    }
			} else {
			    ret = write(tunnel->fd,ptr+payoff,rxringpayload[rxringconsumed]-payoff);
			    
			    if (ret<0)
			        printf("tunnel write error #2\n");
			}
		        break;
	    	    }
		}

	    }
	    /* The consume loop above always drains the ring */
	    rxringbufused = 0;

    }
    return(NULL);    
}


/* Reading from tun interface, processing and pushing to raw socket */
static void *thr_tx(void *threadid)
{
    struct thr_tx *thr_tx_data = (struct thr_tx*)threadid;
    Tunnel *tunnel = thr_tx_data->tunnel;
    int fd = tunnel->fd;
    int raw_socket = thr_tx_data->raw_socket;
    unsigned char *ip = malloc(MAXPAYLOAD+2); /* 2-byte header of VIP, rest is payload */
    unsigned char *payloadptr;
    unsigned char *prevptr = malloc(MAXPAYLOAD);
    int prevavail = 0;
    int daddr_num = 0;
#ifdef HAVE_LIBLZO2
    unsigned char *compressed = malloc(MAXPAYLOAD*2);
    lzo_voidp wrkmem;
    lzo_uint compressedsz;
    uint32_t counter = 0;
    uint32_t counter_total = 0;
    int compression = thr_tx_data->compression;
#endif
    int payloadsz;
    int ret;
    fd_set rfds;
    struct timeval timeout;
    unsigned int packdelay = thr_tx_data->packdelay;
    int maxpacked = thr_tx_data->maxpacked;
    int multiplier = 1;
    pin_to_cpu(thr_tx_data->cpu, "TX", tunnel->id);
    printf("TX thread(ID %d) packdelay %dms\n", tunnel->id, packdelay/1000);


#ifdef HAVE_LIBLZO2
    ret = lzo_init();
    if (ret != LZO_E_OK) {
	printf("LZO init failed\n");
	exit(1);
    }
    wrkmem = (lzo_voidp)malloc(LZO1X_1_MEM_COMPRESS);
    if (!compressed || !wrkmem) {
	perror("malloc()");
	exit(1);
    }
#endif

    if (!ip || !prevptr) {
	perror("malloc()");
	exit(1);
    }
    payloadptr = ip+2;

    memset(ip,0x0,20);

    while(1) {
	// tunnel id
	ip[0] = (unsigned char )(tunnel->id & 0xFF);
	ip[1] = 0; 

	if (!prevavail) {
	    /* Nothing carried over from the previous round, wait for traffic.
	       Do not wait when prevptr already holds a packet - it has to go
	       out now, not when the next unrelated packet happens to arrive. */
	    FD_ZERO(&rfds);
	    FD_SET(fd, &rfds);
	    ret = select(fd+1, &rfds, NULL, NULL, NULL);
	    if (ret <= 0)
		continue;

	    /* Read from tunnel */
	    payloadsz = read(fd, payloadptr, MAXPAYLOAD);

	    if (payloadsz < 0)
		continue;

	    /* Invalid IP packet? Only IPv4 carries a length field here, and
	       only once there are enough bytes to hold one. */
	    if (payloadsz >= 20 && (payloadptr[0] >> 4) == 4) {
		unsigned short total;

		memcpy(&total, payloadptr+2, sizeof(total));
		total = ntohs(total);
		if (total != payloadsz)
		    printf("t %d p %d\n",total,payloadsz);
	    }

	} else {
	    payloadsz = prevavail;
	    memcpy(payloadptr,prevptr,prevavail);
	    prevavail = 0;
	}

	/* If we are fragmented anyway, try to increase second packet size
	    so average packet size will be higher
	*/
	if (payloadsz > maxpacked)
	    multiplier = 2;
	else
	    multiplier = 1;

	timeout.tv_sec = 0;
	timeout.tv_usec = packdelay; /* ms*1000 */

	while(payloadsz < (maxpacked*multiplier) ) {
	    /* try to get next packet */
	    FD_ZERO(&rfds);
	    FD_SET(fd, &rfds);
	    ret = select(fd+1, &rfds, NULL, NULL, &timeout);
	    if (ret<=0) {
		break;
	    }

	    prevavail = read(fd,prevptr,MAXPAYLOAD);
	    /* TODO: unlikely */
	    if (prevavail < 0) {
		perror("Invalid situation ");
		prevavail = 0;
		continue;
		//break;
	    }

	    if (prevavail + payloadsz <= (maxpacked * multiplier)) {
		/* Still small, merge packets */
		ip[1] |= BIT_PACKED;
		memcpy(payloadptr+payloadsz,prevptr,prevavail);
		payloadsz += prevavail;
		prevavail = 0;
	    } else {
		/* This packet too big, send it alone */
		break;
	    }
	}

#ifdef HAVE_LIBLZO2
	if (compression) {
	    compressedsz = MAXPAYLOAD*2;
	    ret = lzo1x_1_compress(payloadptr, payloadsz, compressed, &compressedsz, wrkmem);
	    /* Adaptive compression */
	    if (compressedsz >= (lzo_uint)payloadsz || compressedsz > MAXPAYLOAD) {
		compressedsz = 0;
	    } else {
		if (verbose) {
		    counter += payloadsz - compressedsz;
		    counter_total += payloadsz;
		    if (counter_total > 1024*1024*50) {
			printf("Tunnel %d: total %u compresseddiff %u\n",
			       tunnel->id, counter_total, counter);
			counter_total = 0;
			counter = 0;
		    }
		}

		ip[1] |= BIT_COMPRESSED;
		memcpy(payloadptr,compressed,compressedsz);
		payloadsz = compressedsz;
	    }
	}
#endif
	xor(ip, payloadsz+2);

	/* Concurrent sendto() on a shared datagram socket is thread-safe:
	   each call emits one packet. daddr_num is this thread's own. */
	if(sendto(raw_socket, ip, payloadsz+2, 0,(struct sockaddr *)&tunnel->daddr[daddr_num], (socklen_t)sizeof(tunnel->daddr[0])) < 0)
		perror("send() err");
	daddr_num++;
	daddr_num %= tunnel->daddr_cnt;
    }
    return(NULL);
}

int main(int argc,char **argv)
{
    struct thr_rx thr_rx_data;
    int i, sn, rc, protocol = 50, c;
    Tunnel *tunnel;
    struct sigaction sa;
    struct stat mystat;
    char section[64];
    char strbuf[256];
    static const char *dstkeys[] = { "dst", "dst1", "dst2" };
    char *configname = NULL;
    char *bindaddr = NULL;
    char defaultcfgname[] = "/etc/vip.cfg";
    pthread_t *threads;
    pthread_attr_t attr;
    void *status;
    int optval=262144;


  while (1)
         {

	    static struct option long_options[] =
             {
               {"protocol",  required_argument, 0, 'p'},
               {"config",  required_argument, 0, 'c'},
               {"bind",  required_argument, 0, 'b'},
               {"verbose",  no_argument, 0, 'v'},
               {"help",  no_argument, 0, 'h'},
               {0, 0, 0, 0}
             };
           /* getopt_long stores the option index here. */
	    int option_index = 0;
     
	    c = getopt_long (argc, argv, "c:p:b:hv", long_options, &option_index);
          /* Detect the end of the options. */
           if (c == -1)
             break;
     
           switch (c)
             {
             case 'p':
		protocol = atoi(optarg);
               break;

             case 'v':
		verbose = 1;
               break;

             case 'b':
		bindaddr = strdup(optarg);
		if (bindaddr == NULL)
		    err(1, "strdup()");
               break;

             case 'c':
		configname = strdup(optarg);
		if (configname == NULL)
		    err(1, "strdup()");
               break;
     
             case 'h':
		printf("Available options:\n");
		printf("--protocol 		- Protocol \n");
		printf("--config 		- Config path\n");
		printf("--bind 			- Bind address\n");
		printf("--help			- Help\n");
//		printf("--triggeroutage		- Detect outage, missed packets/packets ok (0/0)\n");
               /* getopt_long already printed an error message. */
		exit(1);
               break;
     
             default:
               abort ();
             }
         }                            

//#ifdef HAVE_LIBLZO2
//    ret = lzo_init();    
//#endif

    printf("Virtual IP %s\n", PACKAGE_VERSION);
    printf("(c) Denys Fedoryshchenko <nuclearcat@nuclearcat.com>\n");

    thr_rx_data.raw_socket = socket(PF_INET, SOCK_RAW, protocol);
    if (thr_rx_data.raw_socket == -1) {
	if (errno == EPERM)
	    printf("You need root privileges or CAP_NET_RAW capability to run this program\n");
	else
	    perror("raw socket()");
	return(1);
    }
    if(setsockopt (thr_rx_data.raw_socket, SOL_SOCKET, SO_RCVBUF, &optval, sizeof (optval)))
	perror("setsockopt(RCVBUF)");
    if(setsockopt (thr_rx_data.raw_socket, SOL_SOCKET, SO_SNDBUF, &optval, sizeof (optval)))
	perror("setsockopt(SNDBUF)");

    if (bindaddr != NULL) {
	struct sockaddr_in serv_addr;
	serv_addr.sin_family = AF_INET;
	if (!inet_pton(AF_INET, bindaddr, (struct in_addr *)&serv_addr.sin_addr.s_addr)) {
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

    if (configname == NULL)
	configname = defaultcfgname;

    if (stat(configname,&mystat)) {
	    perror("config file error");
	    printf("Filename: %s\n",configname);

	    /* TODO: Check readability */
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
    memset(tunnels,0x0,sizeof(Tunnel)*numtunnels);

    for (sn = 0; ini_getsection(sn, section, sizearray(section), configname) > 0; sn++) {
	tunnel = tunnels + sn;
	printf("Creating tunnel: %s num %d\n", section,sn);

	if (strlen(section) >= IFNAMSIZ) {
	    warnx("Tunnel name \"%s\" must be shorter than %d characters",
		  section, IFNAMSIZ);
	    exit(-1);
	}
	strncpy(tunnel->name, section, sizeof(tunnel->name) - 1);


	/* dst, dst1 and dst2 are packed into daddr[] in order, so that a
	   configuration naming dst and dst2 but not dst1 does not leave an
	   unset 0.0.0.0 entry in the middle of the round-robin list. */
	tunnel->daddr_cnt = 0;
	for (i = 0; i < (int)sizearray(dstkeys); i++) {
	    if (ini_gets(section, dstkeys[i], "", strbuf, sizeof(strbuf), configname) < 1)
		continue;
	    if (!strcmp(strbuf, "0.0.0.0"))
		continue;
	    if (!inet_pton(AF_INET, strbuf, &tunnel->daddr[tunnel->daddr_cnt].sin_addr)) {
		warnx("Destination \"%s\" for %s is not correct", strbuf, section);
		exit(-1);
	    }
	    tunnel->daddr[tunnel->daddr_cnt].sin_family = AF_INET;
	    tunnel->daddr[tunnel->daddr_cnt].sin_port = 0;
	    printf("Destination[%d] for %s: %s\n", tunnel->daddr_cnt, section, strbuf);
	    tunnel->daddr_cnt++;
	}
	if (!tunnel->daddr_cnt) {
	    warnx("No usable destination for %s", section);
	    exit(-1);
	}

	tunnel->id = (int)ini_getl(section,"id",0,configname);
	if (tunnel->id == 0 || tunnel->id > 255) {
	    warnx("ID of \"%d\" is not correct", tunnel->id);
	    exit(-1);
	}
	/* Allocate for each thread */
	tunnel->thr_tx_data = malloc(sizeof(struct thr_tx));
	if (tunnel->thr_tx_data == NULL) {
	    perror("malloc() failed");
	    exit(-1);
	}
        tunnel->thr_tx_data->tunnel = tunnel;
	tunnel->thr_tx_data->cpu = tx_cpu(sn);
	tunnel->thr_tx_data->packdelay = (int)ini_getl(section, "delay", 1000, configname);
	tunnel->thr_tx_data->maxpacked = (int)ini_getl(section, "maxpacked", 1500, configname);
	tunnel->thr_tx_data->compression = (int)ini_getl(section, "compression", 0, configname);
        tunnel->thr_tx_data->raw_socket = thr_rx_data.raw_socket;
	if (tunnel->thr_tx_data->maxpacked < 1) {
	    warnx("maxpacked for %s must be positive", section);
	    exit(-1);
	}
	/* The packing loop accumulates up to maxpacked*2 bytes into a buffer
	   of MAXPAYLOAD, so anything above half of that overflows it */
	if (tunnel->thr_tx_data->maxpacked > MAXPAYLOAD/2) {
	    printf("Max packed data %d too large, clamped to %d\n",
		   tunnel->thr_tx_data->maxpacked, MAXPAYLOAD/2);
	    tunnel->thr_tx_data->maxpacked = MAXPAYLOAD/2;
	} else if (tunnel->thr_tx_data->maxpacked > 1500) {
	    printf("Max packed data not recommended > 1500\n");
	}
	printf("Name %s ID %d Delay %d maxpacked %d compression %d\n",tunnel->name,tunnel->id,tunnel->thr_tx_data->packdelay,tunnel->thr_tx_data->maxpacked,tunnel->thr_tx_data->compression);
     }

    check_unique_ids();

    fcntl(thr_rx_data.raw_socket, F_SETFL, O_NONBLOCK);

    for(i=0;i<numtunnels;i++)
    {
      tunnel = tunnels + i;

      if ( open_tun(tunnel) ) {
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
    if (daemon(1,1)) {
	perror("daemon() failed");
	exit(-1);
    }


    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    rc = pthread_create(&threads[0], &attr, thr_rx, (void *)&thr_rx_data);
    if (rc) {
	errno = rc;
	perror("pthread_create() RX");
	exit(-1);
    }

    for(i=0;i<numtunnels;i++)
    {
        tunnel=tunnels + i;
        fcntl(tunnel->fd, F_SETFL, O_NONBLOCK);
        rc = pthread_create(&threads[i+1], &attr, thr_tx, (void *)tunnel->thr_tx_data);
	if (rc) {
	    errno = rc;
	    perror("pthread_create() TX");
	    exit(-1);
	}
    }

    rc = pthread_join(threads[0], &status);

    return(0);
}
