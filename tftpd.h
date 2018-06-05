#ifndef TFTPD_H_
#define TFTPD_H_

#define TFTP_PORT       69
#define TFTP_TIMEOUT    3
#define TFTP_BUF_SIZE   1600
#define TFTP_MAX_TRIES  5

#define TFTP_MODE_ASCII     "NETASCII"
#define TFTP_MODE_RAW       "OCTET"

#define TFTP_OP_RRQ     1
#define TFTP_OP_WRQ     2
#define TFTP_OP_DATA    3
#define TFTP_OP_ACK     4
#define TFTP_OP_ERR     5

#define TFTP_OP_DO_ACK  10
#define TFTP_OP_DO_DATA 11
#define TFTP_OP_DO_ERR  12
#define TFTP_OP_DO_TIMEOUT  13

#define TFTP_REMAIN_CHAR_INVALID    0x12345

enum TFTP_STATE
{
    TFTP_STATE_PROCESSING = 0,
    TFTP_STATE_ERROR,
    TFTP_STATE_LAST_DATA,
    TFTP_STATE_CLOSING,
};

struct tftp_conn
{
    int type; 
    int convert;    /* 0: octet, 1 netascii */
    int sock;
    uint32_t client_ip;
    uint16_t client_port;
    uint16_t block;
    int fd;

    int state;
    int opcode;
    unsigned short data;    /* error code or block */
    char *buf;
    int buflen;
    unsigned int start_ts;
    int ts;
    int total_sent;
    int try_times;
    int remain_char;
    char resent_buf[TFTP_BUF_SIZE];
    int resent_buflen;
};

int monotonic_ts();
int tftp_init(uint32_t ip, struct tftp_conn *conn, int num);
void tftp_conn_release(struct tftp_conn *conn);
void tftp_do(struct tftp_conn *conn);
void process_tftp_req(int sock, uint32_t srvip, struct tftp_conn *conn, int num);
void process_tftp_conn(struct tftp_conn *conn);
void process_tftp_timeout(struct tftp_conn *conn, int timeout);

#endif
