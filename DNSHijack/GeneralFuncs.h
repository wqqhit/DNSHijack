#ifndef __GENERALFUNC__
#define __GENERALFUNC__

#include "DNSHijack.h"

int ListIFCDetails();
void LogMsg(int pPriority, char *pMsg, ...);
void MAC2String(unsigned char pMAC[BIN_MAC_LEN], unsigned char *pOutput, int pOutputLen);
void IP2String(unsigned char pIP[BIN_IP_LEN], unsigned char *pOutput, int pOutputLen);
int String2IP(unsigned char pIP[BIN_IP_LEN], unsigned char *pInput, int pInputLen);
void String2MAC(unsigned char pMAC[BIN_MAC_LEN], unsigned char *pInput, int pInputLen);
void ParseConfigFile(char *pConfigFile);
int GetIPFromIFC(char *pIFCName, char *pOutBuf, int pOutBufLen);

#endif