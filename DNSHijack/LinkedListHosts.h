
#ifndef __LINKEDLIST__
#define __LINKEDLIST__

#include "DNSHijack.h"

#define  MAX_NODE_COUNT 1024

/*
 * Type declarations.
 *
 */

typedef struct HOSTDATA 
{
  unsigned char HostName[MAX_BUF_SIZE + 1];
  unsigned char SpoofedIP[MAX_BUF_SIZE + 1];
} HOSTDATA;


typedef struct HOSTNODE 
{
  HOSTDATA sData;

  int first;
  struct HOSTNODE *prev;
  struct HOSTNODE *next;
} HOSTNODE, *PHOSTNODE, **PPHOSTNODE;




/*
 * Function forward declarations.
 */
PHOSTNODE InitSystemList();
void AddToList(PPHOSTNODE pHostNodes, unsigned char *pHostName, unsigned char *pSpoofedIP);
PHOSTNODE GetNodeByHostname(PHOSTNODE pSysNodes, unsigned char pIPBin[BIN_IP_LEN]);
void EnumListNodes(PHOSTNODE pSysNodes);

#endif