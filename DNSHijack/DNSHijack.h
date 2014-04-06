#ifndef __DNSHIJACK__
#define __DNSHIJACK__


#define VERSION "0.2"
#define MAX_BUF_SIZE 1024
#define MAX_PACKET_SIZE 512
#define MAX_MAC_LEN 17
#define MAX_IP_LEN 15
#define BIN_MAC_LEN 6
#define BIN_IP_LEN 4

#define snprintf _snprintf

#define PCAP_READTIMEOUT 30

#define DEBUG_LEVEL 0

#define DBG_OFF    0
#define DBG_INFO   1
#define DBG_LOW    2
#define DBG_MEDIUM 3
#define DBG_HIGH   4
#define DBG_ALERT  5
#define DBG_ERROR  5

#define DBG_LOGFILE "debug.log"
#define HOSTS_FILE "hosts.txt"

#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IP 0x0800

#endif
