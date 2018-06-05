#ifndef DHCPD_H_
#define DHCPD_H_

int dhcp_sock(int ifindex);
void process_dhcp(int sock, uint8_t *mac, uint32_t myip, uint32_t rpiip);

#endif
