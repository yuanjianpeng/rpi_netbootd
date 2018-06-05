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

#include "tftpd.h"

/* netascii mode
    LF -> CR, LF
    CR -> CR, NUL
*/

static int safe_read(int fd, char *buf, int buflen, int convert, int *remain)
{
    int i, ret;
    int readed = 0;
    int ioreaded = 0;
    int ioused = 0;
    char tmp[1600];
    int saved_errno;

    if (buflen > sizeof(tmp)) {
        fprintf(stderr, "too long\n");
        return -1;
    }

    readed = 0;

    if (convert && *remain != TFTP_REMAIN_CHAR_INVALID) {
        buf[0] = *remain;
        readed = 1;
        *remain = TFTP_REMAIN_CHAR_INVALID;
    }

    ioreaded = 0;
    do
    {
        ret = read(fd, tmp + ioreaded, buflen - readed - ioreaded);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            saved_errno = errno;
            fprintf(stderr, "read failed: %s\n", strerror(errno));
            errno = saved_errno;
            return -1;
        }
        if (ret == 0)
            break;
        ioreaded += ret;
    } while (ioreaded < buflen - readed);

    if (convert) {
        ioused = 0;
        for (i = 0; readed < buflen && i < ioreaded; i++) {
            /* the boundary problem
                here \r or \n are escaped to two chars
                but if we are on the boundary that the buf
                can hold only one char
                we should buffer the second char for the next use
             */
            ioused++;
            if (tmp[i] == '\n') {
                buf[readed++] = '\r';
                if (readed >= buflen) {
                    *remain = '\n';
                    break;
                }
                buf[readed++] = '\n';
            }
            else if (tmp[i] == '\r') {
                buf[readed++] = '\r';
                if (readed >= buflen) {
                    *remain = '\0';
                    break;
                }
                buf[readed++] = '\0';
            }
            else {
                buf[readed++] = tmp[i];
            }
        }
        if (ioused != ioreaded) {
            if (-1 == lseek(fd, ioused - ioreaded, SEEK_CUR)) {
                saved_errno = errno;
                fprintf(stderr, "lseek failed: %s\n", strerror(errno));
                errno = saved_errno;
                return -1;
            }
        }
    }
    else {
        memcpy(buf, tmp, ioreaded);
        readed = ioreaded;
    }

    return readed;
}

static int safe_write(int fd, char *buf, int buflen, int convert, int *remain)
{
    int i, ret, done = 0;
    char tmp[1600];
    int towrite = 0;
    char *buftowrite;
    int saved_errno;

    if (buflen + 1 > sizeof(tmp)) {
        fprintf(stderr, "too long\n");
        return -1;
    }

    if (convert) {
        buftowrite = tmp;
        i = 0;
        if (*remain != TFTP_REMAIN_CHAR_INVALID) {
            if (buf[0] == '\n')
                tmp[towrite++] = '\n';
            else    /* if (buf[i] == '\0') */
                tmp[towrite++] = '\r';
            if (buf[0] == '\n' || buf[i] == '\0')
                i++;
            *remain = TFTP_REMAIN_CHAR_INVALID;
        }
        while (i < buflen) {
            if (i < buflen - 1 && buf[i] == '\r' && buf[i+1] == '\n') {
                i+=2;
                tmp[towrite++] = '\n';
                continue;
            }
            if (i < buflen - 1 && buf[i]  == '\r' && buf[i+1] == '\0') {
                i+=2;
                tmp[towrite++] = '\r';
                continue;
            }
            if (i == buflen - 1) {
                if (buf[i] == '\r') {
                    *remain = '\r';
                    break;
                }
            }
            tmp[towrite++] = buf[i++]; 
        }
    }
    else {
        towrite = buflen;
        buftowrite = buf;
    }

    do
    {
        ret = write(fd, buftowrite + done, towrite - done);
        if (ret <= 0) {
            if (ret < 0 && errno == EINTR)
                continue;
            saved_errno = errno;
            fprintf(stderr, "write failed: %s\n", strerror(errno));
            errno = saved_errno;
            return -1;
        }
        done += ret;
    } while (done < towrite);

    return done;
}

int monotonic_ts()
{
    struct timespec ts;
    if (-1 == clock_gettime(CLOCK_MONOTONIC, &ts)) {
        return 0;
    }
    return ts.tv_sec;
}

unsigned int ts_ms()
{
    struct timespec ts;
    if (-1 == clock_gettime(CLOCK_MONOTONIC, &ts)) {
        return 0;
    }
    return (unsigned int)(1000 * ts.tv_sec + ts.tv_nsec / 1000000);
}

int tftp_init(uint32_t ip, struct tftp_conn *conn, int num)
{
    struct sockaddr_in addr;
    int i, sock;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        fprintf(stderr, "socket() failed: %s\n", strerror(errno));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TFTP_PORT);
    addr.sin_addr.s_addr = ip;

    if (-1 == bind(sock, (struct sockaddr *)&addr, sizeof(addr))) {
        fprintf(stderr, "bind tftp socket failed: %s\n", strerror(errno));
        close(sock);
        return -1;
    }

    for (i = 0; i < num; i++) {
        memset(conn + i, 0, sizeof(struct tftp_conn));
        conn[i].sock = -1;
        conn[i].fd = -1;
        conn[i].remain_char = TFTP_REMAIN_CHAR_INVALID;
    }

    return sock;
}

void tftp_conn_release(struct tftp_conn *conn)
{
    unsigned int now = ts_ms();
    unsigned int used = now - conn->start_ts;
    unsigned int speed = (conn->total_sent * 1000ULL) / (used ? used : 1); 
    char buf[128];
    if (speed > 1024 * 1024)
        sprintf(buf, "%.2f MiB/s", speed / 1024.0 / 1024.0);
    else if (speed > 1024)
        sprintf(buf, "%.2f KiB/s", speed/1024.0);
    else
        sprintf(buf, "buf, %u B/s", speed);
    
    if (conn->sock != -1)
        close(conn->sock);
    if (conn->fd != -1)
        close(conn->fd);
    memset(conn, 0, sizeof(struct tftp_conn));
    conn->sock = -1;
    conn->fd = -1;
    conn->remain_char = TFTP_REMAIN_CHAR_INVALID;
    printf("conn closed, %s\n", buf);
}

void tftp_do(struct tftp_conn *conn)
{
    char res_buf[600];
    int res_len = 0;
    struct sockaddr_in addr;
    int ret;
    char *tosent;
    int cloing = 0;
    
    switch(conn->opcode) {
        /* reply error */
    case TFTP_OP_DO_ERR:
        conn->state = TFTP_STATE_ERROR;    
        *(unsigned short *)res_buf = htons(TFTP_OP_ERR);
        *(unsigned short *)(res_buf + 2) = htons(0);
        memcpy(res_buf + 4, conn->buf, conn->buflen);
        res_len = 4 + conn->buflen;
        printf("tftp error %s\n", conn->buf);
        break;

        /* reply data */
    case TFTP_OP_RRQ:
        conn->block = 0;
        conn->data = 0;
        /* fall through */
    case TFTP_OP_ACK:
        if (conn->data == conn->block) {
            if (conn->opcode == TFTP_OP_ACK &&
                conn->state == TFTP_STATE_LAST_DATA) {
                tftp_conn_release(conn);
                return;
            }
            conn->block++;
            ret = safe_read(conn->fd, res_buf + 4, 512, conn->convert, &conn->remain_char);
            if (ret < 0) {
                conn->opcode = TFTP_OP_DO_ERR;
                conn->buf = res_buf;
                conn->buflen = sprintf(conn->buf, "read failed: %s", strerror(errno));
                conn->buf[conn->buflen -1] = '\0';
                tftp_do(conn);
                return;
            }
            if (ret < 512) {
                conn->state = TFTP_STATE_LAST_DATA;
            }
            *(unsigned short *)res_buf = htons(TFTP_OP_DATA);
            *(unsigned short *)(res_buf + 2) = htons(conn->block);
            res_len = 4 + ret;
            conn->total_sent += ret;
        }
        break;

        /* reply an ACK */
    case TFTP_OP_DATA:
        if (conn->data != conn->block) {
            fprintf(stderr, "unwanted data block %d, expect %d\n", 
                conn->data, conn->block);
            return;
        }
        if (conn->buflen > 0 && safe_write(conn->fd, conn->buf, conn->buflen, 
            conn->convert, &conn->remain_char) == -1) {
            conn->opcode = TFTP_OP_DO_ERR;
            conn->buf = res_buf;
            conn->buflen = sprintf(conn->buf, "write failed: %s", strerror(errno));
            conn->buf[conn->buflen -1] = '\0';
            tftp_do(conn);
            return;
        }
        if (conn->buflen < 512)
            conn->state = TFTP_STATE_CLOSING;
        conn->block++;
        /* fall through */
    case TFTP_OP_WRQ:
        if (conn->opcode == TFTP_OP_WRQ) {
            conn->block = 1;
            conn->data = 0;
        }
        /* fall through */
    case TFTP_OP_ERR:
        if (conn->opcode == TFTP_OP_ERR) {
            conn->data = conn->block;
            conn->state = TFTP_STATE_ERROR;
        }
        /* fall through */
    case TFTP_OP_DO_ACK:
        *(unsigned short *)res_buf = htons(TFTP_OP_ACK);
        *(unsigned short *)(res_buf + 2) = htons(conn->data);
        res_len = 4;
        break;
    case TFTP_OP_DO_TIMEOUT:
        res_len = conn->resent_buflen;
        break;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = conn->client_port; 
    addr.sin_addr.s_addr = conn->client_ip;

    if (conn->opcode == TFTP_OP_DO_TIMEOUT) {
        tosent = conn->resent_buf;    
    }
    else
    {
        tosent = res_buf;
        conn->resent_buflen = res_len;
        memcpy(conn->resent_buf, res_buf, res_len);
        conn->try_times = 0;
    }

    if (sendto(conn->sock, tosent, res_len, 0, (struct sockaddr *)&addr, sizeof(addr)) <= 0) {
        fprintf(stderr, "sendto failed: %s\n", strerror(errno));
    }

    if (conn->opcode == TFTP_OP_DO_TIMEOUT) {
        conn->try_times++;
        if (conn->try_times >= TFTP_MAX_TRIES) {
            tftp_conn_release(conn);
        }
    }

    if (conn->state == TFTP_STATE_CLOSING ||
        conn->state == TFTP_STATE_ERROR)
        tftp_conn_release(conn);

    conn->ts = monotonic_ts();
}

void process_tftp_req(int sock, uint32_t srvip, struct tftp_conn *conn, int num)
{
    char buf[1600];
    int ret;
    struct sockaddr_in addr;
    struct sockaddr_in srvaddr;
    int addrlen = sizeof(addr);
    unsigned short type;
    char *name;
    char *mode = NULL;
    int convert = 0;
    int i;
    int sock_conn;
    int fd;

    ret = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&addr, &addrlen);
    if (ret <= 0) {
        fprintf(stderr, "recvfrom failed: %s\n", strerror(errno));
        return;
    }
    if (ret <= 6)
        return;

    type = ntohs(*(unsigned short *)buf);
    if (type != TFTP_OP_RRQ && type != TFTP_OP_WRQ) {
        fprintf(stderr, "unsupported type\n");
        return;
    }
    name = buf + 2;
    for (i = 2; i < ret; i++)
        if (buf[i] == '\0') {
            mode = buf + i + 1;
            break;
        }
    if (mode == NULL || mode >= buf + ret
        || mode + strlen(mode) + 1 > buf + ret)
        return;
    if (!strcasecmp(mode, TFTP_MODE_RAW)) 
        convert = 0;
    else if (!strcasecmp(mode, TFTP_MODE_ASCII))
        convert = 1;
    else {
        fprintf(stderr, "unsupported mode\n");
        return;
    }

    printf("tftp request %s %s, mode %s\n",
        (type == TFTP_OP_RRQ) ? "read" : "write", 
        name, mode);

    /* find a empty connection */
    for (i = 0; i < num; i++)
        if (conn[i].sock == -1)
            break;
    if (i >= num) {
        fprintf(stderr, "no idle connection\n");
        return;
    }

    sock_conn = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_conn < 0) {
        fprintf(stderr, "socket() failed: %s\n", strerror(errno));
        return;
    }

    memset(&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sin_family = AF_INET;
    srvaddr.sin_port = 0;      /* let system select an idle port */
    srvaddr.sin_addr.s_addr = srvip;

    if (bind(sock_conn, (struct sockaddr *)&srvaddr, sizeof(srvaddr)) == -1) {
        fprintf(stderr, "bind failed: %s\n", strerror(errno));
        close(sock_conn);
        return;
    }

    if (type == TFTP_OP_RRQ)
        fd = open(name, O_RDONLY);
    else
        fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0664);

    conn[i].client_ip = addr.sin_addr.s_addr;
    conn[i].client_port = addr.sin_port;
    conn[i].sock = sock_conn;
    conn[i].type = type;
    conn[i].convert = convert;
    conn[i].fd = fd;
    conn[i].start_ts = ts_ms();
    conn[i].total_sent = 0;

    if (fd < 0) {
        conn[i].opcode = TFTP_OP_DO_ERR;
        conn[i].buf = buf;
        conn[i].buflen = 1 + sprintf(buf, "open failed: %s", strerror(errno));
    }
    else {
        conn[i].opcode = type;
    }

    tftp_do(&conn[i]);
    return;
}

void process_tftp_conn(struct tftp_conn *conn)
{
    char buf[1600];
    int ret;
    struct sockaddr_in addr;
    int addrlen = sizeof(addr);
    unsigned short opcode;
    unsigned short data;

    ret = recvfrom(conn->sock, buf, sizeof(buf), 0, 
        (struct sockaddr *)&addr, &addrlen);
    if (ret < 4)
        return;
    if (addr.sin_addr.s_addr != conn->client_ip
        || addr.sin_port != conn->client_port) {
        fprintf(stderr, "other peoples packet\n");
        return;
    }

    opcode = ntohs(*(unsigned short *)buf);
    data = ntohs(*(unsigned short *)(buf + 2));
    
    switch(opcode) {
    case TFTP_OP_DATA:
        if (conn->type != TFTP_OP_WRQ)
            return;
        /* fall through */
    case TFTP_OP_ERR:
        conn->buf = buf + 4;
        conn->buflen = ret - 4;
        break;
    case TFTP_OP_ACK:
        if (conn->type != TFTP_OP_RRQ)
            return;
        break;
    default:
        return;
    }
    
    conn->opcode = opcode;
    conn->data = data;
    tftp_do(conn);
}

void process_tftp_timeout(struct tftp_conn *conn, int ts)
{
    if (ts > conn->ts + TFTP_TIMEOUT) {
        printf("timeout\n");
        conn->opcode = TFTP_OP_DO_TIMEOUT;
        tftp_do(conn);
    }
}

