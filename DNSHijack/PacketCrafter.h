#ifndef __PACKETCRAFTER__
#define __PACKETCRAFTER__

#include <Windows.h>
#include "NetProtocols.h"

void GenerateEtherPacket(unsigned char * pPacket, unsigned char * pDest, unsigned char * pSource);
void InjectDNSPacket(unsigned char * in_pPacket, pcap_t* device_descriptor, char *pSpoofedIP, char *pSourceIP, char *pDestIP);
void GenerateUDPPacket(unsigned char * pPacket, unsigned short pUDPPacketLength, unsigned short pSPort, unsigned short pDPort);
void GenerateDNSPacket(unsigned char * pPacket, unsigned short pDNSHdrLength, unsigned char * pDNSURLA, unsigned short lTransactionID, char *pSpoofedIP);
void GenerateIPPacket(unsigned char *pPacket, unsigned char pIPProtocol, IPADDRESS pSaddr, IPADDRESS pDaddr, unsigned short pDNSPacketSize);
unsigned short in_cksum(unsigned short * pAddr,int iLen);


#endif