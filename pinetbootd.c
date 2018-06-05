/*
    Herbert Yuan <yuanjp@hust.edu.cn>
    2018/5/27
 */
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/filter.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pwd.h>
#include <fcntl.h>

#include "dhcpd.h"
#include "tftpd.h"

#define MAX_TFTP_CONN   32
static struct tftp_conn conn[MAX_TFTP_CONN];

static void usage(char *cmd)
{
    fprintf(stderr, "%s <interface> [-c rpi_ip] [-C tftproot] [-u username] [-d]\n", cmd);
    fprintf(stderr, "<interface>, listen on this interface,\n"
                    "             and use the ip address of this interface \n"
                    "             as the tftp server address\n");
    fprintf(stderr, "-d,          daemon mode\n");
    fprintf(stderr, "-c ip,       allocate this ip to rpi,\n"
                    "             if you has dhcp server in your LAN ENV,\n"
                    "             you can omit this option\n");
    fprintf(stderr, "-C dir,      change tftp root dir\n");
    fprintf(stderr, "-u user,     change user\n");
    exit(EXIT_FAILURE);
}

static
int get_ifhwaddr(char *ifname, unsigned char *mac)
{
    struct ifreq ifr;
    int sock;

    if (strlen(ifname) >= sizeof(ifr.ifr_name)) {
        fprintf(stderr, "ifname is too long\n");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, ifname);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        fprintf(stderr, "socket() for %s failed: %s\n",
            __FUNCTION__, strerror(errno));
        return -1;
    }

    if (-1 == ioctl(sock, SIOCGIFHWADDR, &ifr)) {
        fprintf(stderr, "ioctl() for %s failed: %s\n",
            __FUNCTION__, strerror(errno));
        close(sock);
        return -1;
    }

    memcpy(mac, ifr.ifr_addr.sa_data, 6);
    close(sock);
    return 0;
}

static
int get_ifaddr(char *ifname, struct in_addr *ipv4)
{
    struct ifreq ifr;
    int sock;

    if (strlen(ifname) >= sizeof(ifr.ifr_name)) {
        fprintf(stderr, "ifname is too long\n");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, ifname);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        fprintf(stderr, "socket() for %s failed: %s\n",
            __FUNCTION__, strerror(errno));
        return -1;
    }

    if (-1 == ioctl(sock, SIOCGIFADDR, &ifr)) {
        fprintf(stderr, "ioctl() for %s failed: %s\n",
            __FUNCTION__, strerror(errno));
        close(sock);
        return -1;
    }

    *ipv4 = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
    close(sock);
    return 0;
}



static int if_param(char *ifname, int *ifindex, uint8_t *mac, struct in_addr *ifip)
{
    if ((*ifindex = if_nametoindex(ifname)) == 0) {
        fprintf(stderr, "get ifindex failed: %s\n", strerror(errno));
        return -1;
    }   

    if (-1 == get_ifhwaddr(ifname, mac))
        return -1;

    if (-1 == get_ifaddr(ifname, ifip))
        return -1;

    printf("hw addr of %s: %02x:%02x:%02x:%02x:%02x:%02x\n",
        ifname, mac[0], mac[1], mac[2],
        mac[3], mac[4], mac[5]);
    printf("ip addr of %s: %s\n", ifname, inet_ntoa(*ifip));
    return 0;
}

int main(int argc, char **argv)
{
    char *ifname = NULL;
    struct in_addr ifip;
    struct in_addr client_ip = {0};
    unsigned char mac[6];
    int opt;
    int daemon = 0;
    int ifindex;
    int ret;
    char *user = NULL;
    int uid = 0;
    char *rootdir = NULL;
    struct passwd *pwd;

    int sock_dhcp;
    int sock_tftp;

    int i;
    int maxfd;
    struct timeval tv;
    fd_set rfds;

    if (argc < 2 || !strcmp("-h", argv[1]))
        usage(argv[0]);

    ifname = argv[1];
    optind = 2;
    while ((opt = getopt(argc, argv, "hdc:u:C:")) != -1)
    {
        switch(opt) {
        case 'd':
            daemon = 1;
            break;
        case 'c':
            if (0 == inet_aton(optarg, &client_ip)) {
                fprintf(stderr, "Invalid rpi ip\n");
                return -1;
            }
            break;
        case 'u':
            user = optarg;
            break;
        case 'C':
            rootdir = optarg;
            break;
        case 'h':
        default:
            usage(argv[0]);
        }
    }

    if (-1 == if_param(ifname, &ifindex, mac, &ifip))
        return 1;

    printf("ip addr allocated to rpi: %s\n", inet_ntoa(client_ip));

    if ((sock_dhcp = dhcp_sock(ifindex)) == -1)
        return 1;

    if ((sock_tftp = tftp_init(ifip.s_addr, conn, MAX_TFTP_CONN)) == -1)
        return 1;


    if (rootdir) {
        if (chdir(rootdir) == -1) {
            fprintf(stderr, "change root failed: %s\n", strerror(errno));
            return -1;
        }
    }
    
    if (user) {
        errno = 0;
        pwd = getpwnam(user);
        if (pwd == NULL) {
            fprintf(stderr, "get user uid failed\n");
            return 1;
        }
        if (-1 == setuid(pwd->pw_uid)) {
            fprintf(stderr, "set user failed: %s\n", strerror(errno));
            return 1;
        }
    }

    if (daemon) {
        int pid = fork();
        if (pid < 0) {
            fprintf(stderr, "fork failed: %s\n", strerror(errno));
            return 1;
        }
        if (pid > 0)
            exit(0);
        else {
            int fd = open("/dev/null", O_RDWR);
            if (fd > 0) {
                dup2(fd, STDOUT_FILENO);
                dup2(fd, STDERR_FILENO);
                close(fd);
            }
        }
    }

    while (1) {
        FD_ZERO(&rfds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        FD_SET(sock_dhcp, &rfds);
        maxfd = sock_dhcp;
        
        FD_SET(sock_tftp, &rfds);
        if (sock_tftp > maxfd) maxfd = sock_tftp;

        for (i = 0; i < MAX_TFTP_CONN; i++) {
            if (conn[i].sock != -1) {
                FD_SET(conn[i].sock, &rfds);
                if (conn[i].sock > maxfd) maxfd = conn[i].sock;
            }
        }

        ret = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (ret < 0) {
            if (errno != EINTR) {
                fprintf(stderr, "select() failed: %s\n", strerror(errno));
                break;
            }
            continue;
        }

        else if (ret == 0) {
            int ts = monotonic_ts();
            for (i = 0; i < MAX_TFTP_CONN; i++) {
                if (conn[i].sock == -1)
                    continue;
                process_tftp_timeout(&conn[i], ts);
            }
            continue;
        }

        if (FD_ISSET(sock_dhcp, &rfds)) 
            process_dhcp(sock_dhcp, mac, ifip.s_addr, client_ip.s_addr);

        for (i = 0; i < MAX_TFTP_CONN; i++) {
            if (conn[i].sock != -1 && FD_ISSET(conn[i].sock, &rfds))
                process_tftp_conn(&conn[i]);
        }
        
        if (FD_ISSET(sock_tftp, &rfds))
           process_tftp_req(sock_tftp, ifip.s_addr, conn, MAX_TFTP_CONN); 
    }

    return 0;
}
