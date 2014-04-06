#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "DNSHijack.h"
#include "LinkedListHosts.h"








/*
 *
 *
 */
PHOSTNODE InitSystemList()
{
  PHOSTNODE lFirsHostNode = NULL;


  if ((lFirsHostNode = (PHOSTNODE) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HOSTNODE))) != NULL)
  {
    lFirsHostNode->first = 1;
    lFirsHostNode->next = NULL;
   	lFirsHostNode->prev = NULL;
  } // if (tmp = ma...


  return(lFirsHostNode);
}
 


/*
 *
 *
 */
void AddToList(PPHOSTNODE pHostNodes, unsigned char *pHostName, unsigned char *pSpoofedIP)
{
  PHOSTNODE lTmpNode = NULL;


   if ((lTmpNode = (PHOSTNODE) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HOSTNODE))) != NULL)
   {
printf("AddToList(1) :  /%s/%s/\n", pHostName, pSpoofedIP);

    CopyMemory(lTmpNode->sData.HostName, pHostName, sizeof(lTmpNode->sData.HostName)-1);
	   CopyMemory(lTmpNode->sData.SpoofedIP, pSpoofedIP, sizeof(lTmpNode->sData.SpoofedIP)-1);

    lTmpNode->prev = NULL;
    lTmpNode->first = 0;
    lTmpNode->next = *pHostNodes;
    ((PHOSTNODE) *pHostNodes)->prev = lTmpNode;
    *pHostNodes = lTmpNode;
  } // if (pSysMAC != NUL...

}
 


/*
 *
 *
 */
PHOSTNODE GetNodeByHostname(PHOSTNODE pSysNodes, unsigned char *pHostname)
{
  PHOSTNODE lRetVal = NULL;
  PHOSTNODE lTmpSys;
  int lCount = 0;

  if ((lTmpSys = pSysNodes) != NULL)
  {

    /*
     * Go to the end of the list
     */
    for (lCount = 0; lCount < MAX_NODE_COUNT; lCount++)
    {
      if (lTmpSys != NULL)
      {
        if (! strncmp((char *)lTmpSys->sData.HostName, (char *) pHostname,  sizeof(lTmpSys->sData.HostName)-1))
	      	{
          lRetVal = lTmpSys;
          break;
        } // if (strncmp(l..
      } // if (lTmp...

      if((lTmpSys = lTmpSys->next) == NULL)
        break;

    } // for (lCount = ...
  } // if (pMAC != ...

  return(lRetVal);
}



/*
 *
 *
 */
void EnumListNodes(PHOSTNODE pSysNodes)
{
  char lTemp[MAX_BUF_SIZE + 1];
  printf("EnumListNodes() : Start\n");

  if (pSysNodes != NULL)
  {
    while(pSysNodes != NULL)
    {
      snprintf(lTemp, sizeof(lTemp) - 1, "%s/%s", pSysNodes->sData.HostName, pSysNodes->sData.SpoofedIP);

      printf("%s\n", pSysNodes);
      pSysNodes = pSysNodes->next;
    } // while(pSysNodes != N...
  } // if (pSysNodes ...


}




/*
 *
 *
 */
int CountNodes(PHOSTNODE pSysNodes)
{   
  int lRetVal = 0;

  while(pSysNodes != NULL)
  {
    pSysNodes = pSysNodes->next;
    lRetVal++;

  } // while(pSysNodes !...

  return(lRetVal);
}