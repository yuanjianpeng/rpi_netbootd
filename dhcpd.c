
#include <stdint.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/filter.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "dhcpd.h"

#define DHCP_SERVER_PORT		67
#define DHCP_CLIENT_PORT		68
#define DHCP_MAGIC              0x63825363
#define DHCP_OPTIONS_BUFSIZE    308
#define BOOTREQUEST             1
#define BOOTREPLY               2
#define DHCP_PADDING			0x00
#define DHCP_MESSAGE_TYPE       0x35
#define DHCP_PARAM_REQ          0x37
#define DHCP_MAX_SIZE           0x39
#define DHCP_TFTP_SERVER_NAME   0x42
#define DHCP_TFTP_SERVER_IP     0x36
#define DHCP_VENDOR_CLASS_ID    0x3c
#define DHCP_UUID_CLASS_ID      0x61
#define DHCP_VENDOR_INFO        0x2b
#define DHCP_END                0xff
#define DHCPDISCOVER            1
#define DHCPOFFER               2
#define BROADCAST_FLAG 			0x8000

#define VENDOR_ID       "PXEClient"

struct dhcp_packet {
	uint8_t op;
	uint8_t htype;
	uint8_t hlen;
	uint8_t hops;
	uint32_t xid;
	uint16_t secs;
	uint16_t flags;
	uint32_t ciaddr;
	uint32_t yiaddr;
	uint32_t siaddr_nip;
	uint32_t gateway_nip;
	uint8_t chaddr[16];
	uint8_t sname[64];
	uint8_t file[128];
	uint32_t cookie;
	uint8_t options[DHCP_OPTIONS_BUFSIZE];
} __attribute__((packed));

#define ETH_HDR_LEN		sizeof(struct ethhdr)
#define IP_HDR_LEN		sizeof(struct iphdr)
#define UDP_HDR_LEN		sizeof(struct udphdr)
#define DHCP_LEN		sizeof(struct dhcp_packet)

struct dhcp_raw_packet
{
	struct ethhdr eth_hdr;
	struct iphdr ip_hdr;
	struct udphdr udp_hdr;
	struct dhcp_packet dhcp_packet;
} __attribute__((packed));

#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define offsetof(type, member) ( (int ) & ((type*)0) -> member )

static
unsigned char vendor_info_data[] = {
    0x06, 0x01, 0x03,    /* PXE Dsicovery control */
    0x0a, 0x04, 0x00, 0x50, 0x58, 0x45,
    0x09, 0x14, 0x00, 0x00, 0x11, 0x52, 0x61,
                0x73, 0x70, 0x62, 0x65, 0x72,
                0x72, 0x79, 0x20, 0x50, 0x69,
                0x20, 0x42, 0x6f, 0x6f, 0x74,
};

static uint16_t inet_cksum(uint16_t *addr, int nleft)
{
	/*
	 * Our algorithm is simple, using a 32 bit accumulator,
	 * we add sequential 16 bit words to it, and at the end, fold
	 * back all the carry bits from the top 16 bits into the lower
	 * 16 bits.
	 */
	unsigned sum = 0;
	while (nleft > 1) {
		sum += *addr++;
		nleft -= 2;
	}

	/* Mop up an odd byte, if necessary */
	if (nleft == 1) {
		sum += *(uint8_t*)addr;
	}

	/* Add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
	sum += (sum >> 16);                     /* add carry */

	return (uint16_t)~sum;
}

static
int packet_set_filter(int sock, struct sock_filter *filter, int len)
{
	struct sock_fprog fprog;
	
	fprog.filter = filter;
	fprog.len = len;
	
	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, 
		&fprog, sizeof(fprog)) == -1) {
	    fprintf(stderr, "setsockopt() SO_ATTACH_FILTER failed: %s\n", strerror(errno));
	    return -1;
	}
	return 0;
}

static
int dhcp_set_filter(int sock)
{
	struct sock_filter dhcp_filter[] = {
		{ 0x28,  0,  0, 0x0000000c },
		{ 0x15,  0, 22, 0x00000800 },
		{ 0x30,  0,  0, 0x00000017 },
		{ 0x15,  0, 20, 0x00000011 },
		{ 0x30,  0,  0, 0x0000000e },
		{ 0x54,  0,  0, 0x0000000f },
		{ 0x24,  0,  0, 0x00000004 },
		{ 0x04,  0,  0, 0x0000000e },
		{ 0x02,  0,  0, 0000000000 },
		{ 0x07,  0,  0, 0000000000 },
		{ 0x48,  0,  0, 0000000000 },
		{ 0x15,  1,  0, 0x00000043 },
		{ 0x15,  5, 11, 0x00000044 },
		{ 0x60,  0,  0, 0000000000 },
		{ 0x07,  0,  0, 0000000000 },
		{ 0x48,  0,  0, 0x00000002 },
		{ 0x15,  6,  0, 0x00000044 },
		{ 0x06,  0,  0, 0000000000 },
		{ 0x60,  0,  0, 0000000000 },
		{ 0x07,  0,  0, 0000000000 },
		{ 0x48,  0,  0, 0x00000002 },
		{ 0x15,  1,  0, 0x00000043 },
		{ 0x06,  0,  0, 0000000000 },
		{ 0x06,  0,  0, 0xffffffff },
		{ 0x06,  0,  0, 0000000000 },
	};
	return packet_set_filter(sock, dhcp_filter, ARRAY_SIZE(dhcp_filter));
}

static
int process_rpi_dhcp(char *buf, int buflen, unsigned char *mac, 
    unsigned char *uuid, int *uuid_len)
{
	struct dhcp_raw_packet * packet = (struct dhcp_raw_packet *)buf;
	struct dhcp_packet *dhcp;
	int iplen, udplen;
	uint16_t check;
	unsigned char *opt;
    int i;
    int rpi_dhcp = 0;
	
	if (buflen < ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN) 
		return -1;

    memcpy(mac, packet->eth_hdr.h_source, 6);

	iplen = ntohs(packet->ip_hdr.tot_len);
	udplen = ntohs(packet->udp_hdr.len);
	
	if (iplen + ETH_HDR_LEN > buflen) 
		return -1;

	if (packet->ip_hdr.protocol != IPPROTO_UDP
		|| packet->ip_hdr.version != IPVERSION
		|| packet->ip_hdr.ihl != (IP_HDR_LEN >> 2)
		|| iplen != IP_HDR_LEN + udplen )
	{
		fprintf(stderr, "unrelated/bogus packet, ignoring\n");
		return -1;
	}
		
	check = packet->ip_hdr.check;
	packet->ip_hdr.check = 0;
	if (check != inet_cksum((uint16_t *)&packet->ip_hdr, IP_HDR_LEN)) {
		fprintf(stderr, "bad IP header checksum, ignoring\n");
		return -1;
	}
	
	/* verify UDP checksum. IP header has to be modified for this */
	memset(&packet->ip_hdr, 0, offsetof(struct iphdr, protocol));
	/* ip.xx fields which are not memset: protocol, check, saddr, daddr */
	packet->ip_hdr.tot_len = packet->udp_hdr.len; /* yes, this is needed */
	check = packet->udp_hdr.check;
	packet->udp_hdr.check = 0;
	if (check && check != inet_cksum((uint16_t *)&packet->ip_hdr, iplen)) {
		fprintf(stderr, "packet with bad UDP checksum received, ignoring\n");
		return -1;
	}

	if ( packet->udp_hdr.source != htons(DHCP_CLIENT_PORT)
		|| packet->udp_hdr.dest != htons(DHCP_SERVER_PORT)) 
		return -1;

	if (packet->dhcp_packet.cookie != htonl(DHCP_MAGIC)) {
		fprintf(stderr, "packet with bad magic, ignoring\n");
		return -1;
	}

	dhcp = &packet->dhcp_packet;
	if (dhcp->op != BOOTREQUEST)
		return -1;
		
	opt = dhcp->options;
	while (opt  < buf + buflen) {
		if (*opt == DHCP_END || *opt == 0)
            break;
		else if (*opt == DHCP_MESSAGE_TYPE) {
			if (*(opt + 2) != DHCPDISCOVER)
				return -1;
		}
        else if (*opt == DHCP_PARAM_REQ) {
            unsigned char len = *(opt + 1);
            for (i = 0; i < len; i++) {
                if (*(opt + 2 + i) == DHCP_TFTP_SERVER_NAME) {
                    rpi_dhcp |= 1;
                }
            }
        }
        else if (*opt == DHCP_UUID_CLASS_ID) {
            rpi_dhcp |= 2;
            *uuid_len = opt[1];
            memcpy(uuid, opt + 2, opt[1]);
        }
        opt += 2 + *(opt + 1);
	}

    if (rpi_dhcp == 3)
	    printf("recv a rpi dhcp discover packet\n");

	return (rpi_dhcp == 3) ? 0 : -1;
}

static
int construct_rpi_dhcp_offer(char *buf, int bufsize, 
	unsigned char *src_mac, unsigned char *dst_mac,
    uint32_t svr_ip, uint32_t rpi_ip,
    unsigned char *uuid, int uuid_len)
{
	struct dhcp_raw_packet *raw = (struct dhcp_raw_packet *)buf;
	struct dhcp_packet *packet = &raw->dhcp_packet;
	uint8_t *next_opt;
	int i;
	uint16_t d16;
	int dhcp_len;

	if (bufsize < sizeof(*raw)) 
		return -1;

	memset(buf, 0, sizeof(*raw));

	packet->op = BOOTREPLY; 
	packet->htype = 1;
	packet->hlen = 6;
    if (rpi_ip) {
        packet->yiaddr = rpi_ip;
        packet->siaddr_nip = svr_ip;
    }
	packet->cookie = htonl(DHCP_MAGIC);
	memcpy(packet->chaddr, dst_mac, 6);

	next_opt = packet->options;
	next_opt[0] = DHCP_MESSAGE_TYPE;
	next_opt[1] = 1;
	next_opt[2] = DHCPOFFER;
	next_opt += 3;
    
    next_opt[0] = DHCP_TFTP_SERVER_IP;
    next_opt[1] = 4;
    memcpy(&next_opt[2], &svr_ip, 4);
    next_opt += 6;
	
    next_opt[0] = DHCP_VENDOR_CLASS_ID;
    next_opt[1] = strlen(VENDOR_ID);
    strcpy(&next_opt[2], VENDOR_ID);
    next_opt += 2 + strlen(VENDOR_ID);

    next_opt[0] = DHCP_UUID_CLASS_ID;
    next_opt[1] = uuid_len;
    memcpy(&next_opt[2], uuid, uuid_len);
    next_opt += 2 + uuid_len;

    next_opt[0] = DHCP_VENDOR_INFO;
    next_opt[1] = sizeof(vendor_info_data);
    memcpy(&next_opt[2], vendor_info_data, sizeof(vendor_info_data));
    next_opt += 2 + sizeof(vendor_info_data);

	next_opt[0] = DHCP_END;
	
	dhcp_len = (1 + next_opt - (uint8_t *)packet);
	if (dhcp_len < 300)
		dhcp_len = 300;
	
	memcpy(raw->eth_hdr.h_dest, dst_mac, ETH_ALEN);
	memcpy(raw->eth_hdr.h_source, src_mac, ETH_ALEN);
	raw->eth_hdr.h_proto = htons(ETH_P_IP);

	raw->ip_hdr.protocol = IPPROTO_UDP;
	raw->ip_hdr.saddr = svr_ip;
	raw->ip_hdr.daddr = INADDR_BROADCAST;
	
	raw->udp_hdr.source = htons(DHCP_SERVER_PORT);
	raw->udp_hdr.dest = htons(DHCP_CLIENT_PORT);
	raw->udp_hdr.len = htons(UDP_HDR_LEN + dhcp_len);
	raw->ip_hdr.tot_len = raw->udp_hdr.len;
	raw->udp_hdr.check = inet_cksum((uint16_t *)&raw->ip_hdr, 
							IP_HDR_LEN+UDP_HDR_LEN+dhcp_len);

	raw->ip_hdr.tot_len = htons(IP_HDR_LEN+UDP_HDR_LEN+dhcp_len);
	raw->ip_hdr.ihl = IP_HDR_LEN >> 2;
	raw->ip_hdr.version = IPVERSION;
	raw->ip_hdr.ttl = IPDEFTTL;
	raw->ip_hdr.check = inet_cksum((uint16_t *)&raw->ip_hdr, IP_HDR_LEN);

	return (ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + dhcp_len); 
}


int dhcp_sock(int ifindex)
{
    int sock;
    struct sockaddr_ll sll;

    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (sock == -1) {
        fprintf(stderr, "socket() failed: %s\n", strerror(errno));
        return -1;
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_protocol = htons(ETH_P_IP);

    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        fprintf(stderr, "bind() failed: %s\n", strerror(errno));
        close(sock);
        return -1;
    }

	if (dhcp_set_filter(sock)) {
		fprintf(stderr, "set dhcp bpf failed\n");
		close(sock);
        return -1;
	}
    return sock;
}

void process_dhcp(int sock, uint8_t *mac, uint32_t myip, uint32_t rpiip)
{
    unsigned char rpi_mac[6];
    struct sockaddr_ll sll;
    int addrlen;
    unsigned char uuid[256];
    int uuid_len;
    char buf[1600];
    int ret;

    addrlen = sizeof(sll);
    ret = recvfrom(sock, buf, sizeof(buf), MSG_TRUNC, (struct sockaddr *)&sll, &addrlen);
    if (ret < 0) {
        if (errno == EINTR)
            return;
        fprintf(stderr, "recvfrom failed: %s\n", strerror(errno));
        return;
    }
    else if (ret == 0) {
        fprintf(stderr, "recvfrom ret 0\n");
        return;
    }

    if (sll.sll_pkttype == PACKET_OUTGOING)
        return;

    if (process_rpi_dhcp(buf, ret, rpi_mac, uuid, &uuid_len))
        return;

    ret = construct_rpi_dhcp_offer(buf, sizeof(buf),
        mac, rpi_mac, myip, rpiip, uuid, uuid_len);
    if (ret > 0) {
        ret = sendto(sock, buf, ret, 0, NULL, 0);
        if (ret <= 0) {
            fprintf(stderr, "sendto() failed: %s\n", strerror(errno));
        }
    }
}
