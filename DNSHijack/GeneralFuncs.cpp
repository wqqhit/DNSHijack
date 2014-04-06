//
#include "DNSHijack.h"
#include "GeneralFuncs.h"
#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <iphlpapi.h>
#include <Shlwapi.h>

#include "LinkedListHosts.h"


extern PHOSTNODE gHostsList;


/*
 *
 *
 */

int ListIFCDetails()
{
  int lRetVal = 0;
  PIP_ADAPTER_INFO lAdapterInfoPtr = NULL;
  PIP_ADAPTER_INFO lAdapter = NULL;
  DWORD lFuncRetVal = 0;
  UINT lCounter;
  struct tm lTimeStamp;
  char lTemp[MAX_BUF_SIZE +1 ];
  errno_t error;
  ULONG lOutBufLen = sizeof (IP_ADAPTER_INFO);



  if ((lAdapterInfoPtr = (IP_ADAPTER_INFO *) HeapAlloc(GetProcessHeap(), 0, sizeof (IP_ADAPTER_INFO))) == NULL)
  {
    LogMsg(DBG_ERROR, "listIFCDetails() : Error allocating memory needed to call GetAdaptersinfo");
    lRetVal = 1;
    goto END;
  } // if ((lAdapter...


  if (GetAdaptersInfo(lAdapterInfoPtr, &lOutBufLen) == ERROR_BUFFER_OVERFLOW) 
  {
    HeapFree(GetProcessHeap(), 0, lAdapterInfoPtr);
    if ((lAdapterInfoPtr = (IP_ADAPTER_INFO *) HeapAlloc(GetProcessHeap(), 0, lOutBufLen)) == NULL)
    {
      LogMsg(DBG_ERROR, "listIFCDetails() : Error allocating memory needed to call GetAdaptersinfo");
      lRetVal = 2;

      goto END;
    } // if ((lAdapte...
  } // if (GetA...



  if ((lFuncRetVal = GetAdaptersInfo(lAdapterInfoPtr, &lOutBufLen)) == NO_ERROR) 
  {
    for (lAdapter = lAdapterInfoPtr; lAdapter; lAdapter = lAdapter->Next)
    {
      printf("\n\nIfc no : %d\n", lAdapter->ComboIndex);
      printf("\tAdapter Name: \t%s\n", lAdapter->AdapterName);
      printf("\tAdapter Desc: \t%s\n", lAdapter->Description);
      printf("\tAdapter Addr: \t");

      for (lCounter = 0; lCounter < lAdapter->AddressLength; lCounter++) 
      {
        if (lCounter == (lAdapter->AddressLength - 1))
          printf("%.2X\n", (int) lAdapter->Address[lCounter]);
        else
          printf("%.2X-", (int) lAdapter->Address[lCounter]);
      }

      printf("\tIndex: \t%d\n", lAdapter->Index);
      printf("\tType: \t");

      switch (lAdapter->Type) 
      {
         case MIB_IF_TYPE_OTHER:
              printf("Other\n");
              break;
         case MIB_IF_TYPE_ETHERNET:
              printf("Ethernet\n");
              break;
         case MIB_IF_TYPE_TOKENRING:
              printf("Token Ring\n");
              break;
         case MIB_IF_TYPE_FDDI:
              printf("FDDI\n");
              break;
         case MIB_IF_TYPE_PPP:
              printf("PPP\n");
              break;
         case MIB_IF_TYPE_LOOPBACK:
              printf("Lookback\n");
              break;
         case MIB_IF_TYPE_SLIP:
              printf("Slip\n");
              break;
         default:
              printf("Unknown type %ld\n", lAdapter->Type);
              break;
      }

      printf("\tIP Address: \t%s\n", lAdapter->IpAddressList.IpAddress.String);
      printf("\tIP Mask: \t%s\n", lAdapter->IpAddressList.IpMask.String);
      printf("\tGateway: \t%s\n", lAdapter->GatewayList.IpAddress.String);

      if (lAdapter->DhcpEnabled) 
      {
        printf("\tDHCP Enabled: Yes\n");
        printf("\t  DHCP Server: \t%s\n", lAdapter->DhcpServer.IpAddress.String);
        printf("\t  Lease Obtained: ");

        if (error = _localtime32_s(&lTimeStamp, (__time32_t*) &lAdapter->LeaseObtained))
          printf("Invalid Argument to _localtime32_s\n");
        else {
          if (error = asctime_s(lTemp, sizeof(lTemp), &lTimeStamp))
            printf("Invalid Argument to asctime_s\n");
          else
            printf("%s", lTemp);
        }

        printf("\t  Lease Expires:  ");

        if (error = _localtime32_s(&lTimeStamp, (__time32_t*) &lAdapter->LeaseExpires))
          printf("Invalid Argument to _localtime32_s\n");
        else {
          // Convert to an ASCII representation 
          if (error = asctime_s(lTemp, sizeof(lTemp), &lTimeStamp))
            printf("Invalid Argument to asctime_s\n");
          else
            printf("%s", lTemp);
        }
      } else
        printf("\tDHCP Enabled: No\n");

      if (lAdapter->HaveWins) 
      {
        printf("\tHave Wins: Yes\n");
        printf("\t  Primary Wins Server:    %s\n", lAdapter->PrimaryWinsServer.IpAddress.String);
        printf("\t  Secondary Wins Server:  %s\n", lAdapter->SecondaryWinsServer.IpAddress.String);
      } else
         printf("\tHave Wins: No\n");
    }
  }
  else
    LogMsg(DBG_ERROR, "listIFCDetails() : GetAdaptersInfo failed with error: %d\n", lFuncRetVal);


END:
  if (lAdapterInfoPtr)
    HeapFree(GetProcessHeap(), 0, lAdapterInfoPtr);

  return(lRetVal);
}




/*
 *
 */
void LogMsg(int pPriority, char *pMsg, ...)
{
  HANDLE lFH = INVALID_HANDLE_VALUE;
  OVERLAPPED lOverl = { 0 };
  char lDateStamp[MAX_BUF_SIZE + 1];
  char lTimeStamp[MAX_BUF_SIZE + 1];
  char lTime[MAX_BUF_SIZE + 1];
  char lTemp[MAX_BUF_SIZE + 1];
  char lLogMsg[MAX_BUF_SIZE + 1];
  DWORD lBytedWritten = 0;
  va_list lArgs;



  if (pPriority >= DEBUG_LEVEL && DEBUG_LEVEL != DBG_OFF)
  { 
    if ((lFH = CreateFile(DBG_LOGFILE, GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0)) != INVALID_HANDLE_VALUE)
    {
      ZeroMemory(&lOverl, sizeof(lOverl));

      if (LockFileEx(lFH, LOCKFILE_EXCLUSIVE_LOCK, 0, 0, 0, &lOverl) == TRUE)
      {
        ZeroMemory(lTime, sizeof(lTime));
        ZeroMemory(lTimeStamp, sizeof(lTimeStamp));
        ZeroMemory(lDateStamp, sizeof(lDateStamp));

        _strtime(lTimeStamp);
        _strdate(lDateStamp);
        snprintf(lTime, sizeof(lTime) - 1, "%s %s", lDateStamp, lTimeStamp);


        ZeroMemory(lTemp, sizeof(lTemp));
        ZeroMemory(lLogMsg, sizeof(lLogMsg));
        va_start (lArgs, pMsg);
        vsprintf(lTemp, pMsg, lArgs);
        va_end(lArgs);
      		snprintf(lLogMsg, sizeof(lLogMsg) - 1, "%s : %s\n", lTime, lTemp);


        SetFilePointer(lFH, 0, NULL, FILE_END);
        WriteFile(lFH, lLogMsg, strnlen(lLogMsg, sizeof(lLogMsg) - 1), &lBytedWritten, NULL);
printf(lLogMsg);
        UnlockFileEx(lFH, 0, 0, 0, &lOverl);
	  } // if (LockFileEx(lF...
      CloseHandle(lFH);
    } // if ((lFH = CreateF...
  } // if (pPriori...
}






/*
 *
 *
 */
void MAC2String(unsigned char pMAC[6], unsigned char *pOutput, int pOutputLen)
{
  if (pOutput && pOutputLen > 0)
    snprintf((char *) pOutput, pOutputLen, "%02X-%02X-%02X-%02X-%02X-%02X", pMAC[0], pMAC[1], pMAC[2], pMAC[3], pMAC[4], pMAC[5]);
}

void IP2String(unsigned char pIP[BIN_IP_LEN], unsigned char *pOutput, int pOutputLen)
{
  if (pOutput && pOutputLen > 0)
    snprintf((char *) pOutput, pOutputLen, "%d.%d.%d.%d", pIP[0], pIP[1], pIP[2], pIP[3]);

}



void String2MAC(unsigned char pMAC[6], unsigned char *pInput, int pInputLen)
{
  if (pInput != NULL && pInputLen > 0)
    sscanf((char *) pInput, "%02x:%02x:%02x:%02x:%02x:%02x", &pMAC[0], &pMAC[1], &pMAC[2], &pMAC[3], &pMAC[4], &pMAC[5]);
}

int String2IP(unsigned char pIP[4], unsigned char *pInput, int pInputLen)
{
  int lRetVal = 1;
  unsigned char lIP[4];


  if (pInput != NULL && pInputLen > 0)
    if (sscanf((char *) pInput, "%d.%d.%d.%d", &pIP[0], &pIP[1], &pIP[2], &pIP[3]) == 4)
      if ((lIP[0] | lIP[1] | lIP[2] | lIP[3]) < 255)
        if (strspn((char *) pInput, "0123456789.") == strlen((char *) pInput))
          lRetVal = 0;

  return(lRetVal);
}






/*
 *
 *
 */
void ParseConfigFile(char *pConfigFile)
{
  FILE *lFH = NULL;
  char lLine[MAX_BUF_SIZE + 1];
  unsigned char lHostname[MAX_BUF_SIZE + 1];
  unsigned char lSpoofedIP[MAX_BUF_SIZE + 1];
  
  if (pConfigFile != NULL && (lFH = fopen(pConfigFile,"r")) != NULL)
  {
    ZeroMemory(lLine, sizeof(lLine));
   	ZeroMemory(lHostname, sizeof(lHostname));
   	ZeroMemory(lSpoofedIP, sizeof(lSpoofedIP));

    while(fgets(lLine, sizeof(lLine), lFH) != NULL)
    {
      while (lLine[strlen(lLine)-1] == '\r' || lLine[strlen(lLine)-1] == '\n')
        lLine[strlen(lLine)-1] = '\0';

      // parse values and add them to the list.
      sscanf(lLine, "%[^:]:%s", lHostname, lSpoofedIP);
      AddToList(&gHostsList, lHostname, lSpoofedIP);


      ZeroMemory(lLine, sizeof(lLine));
      ZeroMemory(lHostname, sizeof(lHostname));
      ZeroMemory(lSpoofedIP, sizeof(lSpoofedIP));
   	} // while(fgets(l...

    fclose(lFH);
  }
}



/*
 *
 *
 */

int GetIPFromIFC(char *pIFCName, char *pOutBuf, int pOutBufLen)
{
  int lRetVal = 0;
  PIP_ADAPTER_INFO lAdapterInfo;
  PIP_ADAPTER_INFO lAdapter = NULL;
  ULONG lOutBufLen = sizeof(IP_ADAPTER_INFO);
	
  if (pIFCName != NULL && pOutBuf != NULL && pOutBufLen > 0)
  {
    if ((lAdapterInfo = (IP_ADAPTER_INFO *) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (sizeof (IP_ADAPTER_INFO)))) != NULL) 
    {
      if (GetAdaptersInfo(lAdapterInfo, &lOutBufLen) == ERROR_BUFFER_OVERFLOW) 
	  {
        HeapFree(GetProcessHeap(), 0, lAdapterInfo);
        if ((lAdapterInfo = (IP_ADAPTER_INFO *) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, lOutBufLen)) == NULL) 
        {
          lRetVal = 1;
          goto END;
        } // if ((lAdapt...
      } // if (GetAd...



      if (GetAdaptersInfo(lAdapterInfo, &lOutBufLen) == NO_ERROR) 
	  {
        for (lAdapter = lAdapterInfo; lAdapter; lAdapter = lAdapter->Next) 
        {
          if (StrStrI(lAdapter->AdapterName, pIFCName))
		  {
            strncpy(pOutBuf, lAdapter->IpAddressList.IpAddress.String, pOutBufLen);
            break;
          } // if (StrSt...
        } // for (pAdapter...
      } // if (GetAdapte...
    } // if ((lAdapterInfo...
  } //if (pIFCNam


END:

  if (lAdapterInfo)
    HeapFree(GetProcessHeap(), 0, lAdapterInfo);

  return(0);
}