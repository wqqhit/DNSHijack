#include <windows.h>
#include <stdio.h>
#include "GeneralFuncs.h"
#include "DNSSniffer.h"
#include "LinkedListHosts.h"


#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Ws2_32.lib")



PHOSTNODE gHostsList = NULL;




/*
 * Program entry point
 */
int main(int argc, char *argv[])
{
  int lRetVal = 0;


  /*
   * List all interfaces
   */
  if (argc == 2 && ! strcmp(argv[1], "-l"))
  {
    ListIFCDetails();  




  /*
   * Start DNS spoofing 
   */
  }
  else if (argc == 2)
  {
    gHostsList = InitSystemList();
    ParseConfigFile(HOSTS_FILE);
    DNSSniffer(argv[1]);



  /*
   * Help menu
   */
  }
  else
  {
    printf("\nDNSHijack   Version %s\n", VERSION);
   	printf("-----------------------\n\n");
    printf("Web\t http://www.megapanzer.com/\n");
    printf("Mail\t megapanzer@gmail.com\n\n\n");
   	printf("List interfaces  :  %s -l\n", argv[0]);
   	printf("Start poisoning  :  %s IFC-Name\n", argv[0]);
  }


  return(lRetVal);
}

