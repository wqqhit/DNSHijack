
#ifndef __NETPROTOCOLS__
#define __NETPROTOCOLS__

#define IP_PROTO_UDP 17
#define IP_PROTO_TCP 6
#define IP_PROTO_ICMP 1


/*
 *
 *
 */
typedef struct ethern_hdr
{
  unsigned char ether_dhost[6];  // dest Ethernet address
  unsigned char ether_shost[6];  // source Ethernet address
  unsigned short ether_type;     // protocol (16-bit)
} ETHDR, *PETHDR;



/*
 *
 *
 */
typedef struct ipaddress
{
  unsigned char byte1;
  unsigned char byte2;
  unsigned char byte3;
  unsigned char byte4;
} IPADDRESS, *PIPADDRESS;




/*
 *
 *
 */
typedef struct iphdr
{
  unsigned char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
  unsigned char  tos;            // Type of service 
  unsigned short tlen;           // Total length 
  unsigned short identification; // Identification
  unsigned short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
  unsigned char  ttl;            // Time to live
  unsigned char  proto;          // Protocol
  unsigned short crc;            // Header checksum
  IPADDRESS      saddr;      // Source address
  IPADDRESS      daddr;      // Destination address
//  unsigned int   opt;        // Option + padding
} IPHDR, *PIPHDR;



/*
 *
 *
 */
typedef struct tcphdr 
{
  unsigned short sport;  
  unsigned short dport;
  unsigned int   seq; 
  unsigned int   ack_seq; 
  unsigned short res1:4, 
                 doff:4,
                 fin:1,
                 syn:1,  
                 rst:1,  
                 psh:1,  
                 ack:1,  
                 urg:1, 
                 res2:2; 
  unsigned short window;
  unsigned short check;  
  unsigned short urg_ptr;
} TCPHDR, *PTCPHDR; 



/*
 *
 *
 */
typedef struct udphdr 
{
  unsigned short sport;/*Source port */
  unsigned short dport;/*Destination port */
  unsigned short ulen;/*UDP length */
  unsigned short sum; /*UDP checksum */
} UDPHDR, *PUDPHDR;



/*
 *
 *
 */
typedef struct icmpheader
{
  unsigned char  type;
  unsigned char  code;
  unsigned short checksum;
  unsigned short id;
  unsigned short sequence; 
  unsigned	short data;
} ICMPHDR, *PICMPHDR;  


/*
 *
 *
 */
typedef struct arphdr   
{   
  unsigned short  htype;   // format of hardware address 
  unsigned short  ptype;   // format of protocol address
  unsigned char   hlen;   // length of hardware address
  unsigned char   plen;    // length of protocol address 
  unsigned short  opcode;    // ARP/RARP operation
  unsigned char   sha[6];  // sender hardware address (MAC)
  unsigned char   spa[4];     // sender protocol address (IP)
  unsigned char   tha[6];  // target hardware address (MAC)
  unsigned char   tpa[4];      // target protocol address (IP)
} ARPHDR, *PARPHDR; 






typedef struct _DNS_HEADER 
{
	unsigned short id;       // identification number 
	unsigned char rd :1;     // recursion desired 
	unsigned char tc :1;     // truncated message 
	unsigned char aa :1;     // authoritive answer 
	unsigned char opcode :4; // purpose of message 
	unsigned char qr :1;     // query/response flag 
	unsigned char rcode :4;  // response code 
	unsigned char cd :1;     // checking disabled 
	unsigned char ad :1;     // authenticated data 
	unsigned char z :1;      // its z! reserved 
	unsigned char ra :1;     // recursion available 
	unsigned short q_count;  // number of question enties
	unsigned short ans_count; // number of answer entries 
	unsigned short auth_count; // number of authority entries
	unsigned short add_count; // number of resource entries
} DNSHDR, *PDNSHDR;


typedef struct DNS_ANSWER_
{	
  unsigned short a_url;	// URL in question
  unsigned short a_type;	// type of query
  unsigned short a_class;// class of query
  unsigned short a_ttl1;	// time to live
  unsigned short a_ttl2;	// time to live
  unsigned short a_len;  // length
  struct in_addr a_ip; // IP returned
} DNS_ANSWER, *PDNS_ANSWER;


//DNS main packet
typedef struct DNS_BASIC_
{
  unsigned short trans_id;	// transaction ID
  unsigned short flags;		// u16_flags
  unsigned short ques;		// no of queries
  unsigned short ans;		// no of answers
  unsigned short auth;		// no of authoritive
  unsigned short add;		// no of additional
} DNS_BASIC, *PDNS_BASIC;

//DNS query packet
typedef struct DNS_QUERY_
{	
  unsigned short q_type;		// Type A query taken
  unsigned short q_class;	// class
} DNS_QUERY, *PDNS_QUERY;
#endif