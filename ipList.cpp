#include <stdio.h>
#include <pcap/pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if_dl.h>

const char *ntoa(sockaddr *addr) {
  sockaddr_in *inAddr = (struct sockaddr_in *) addr;
  return inet_ntoa(inAddr->sin_addr);
}
int main(int argc, char *argv[])
{
  char *dev, errbuf[PCAP_ERRBUF_SIZE];
  int findAllReturnValue = 8;
  pcap_if_t *allDevs = NULL;
  pcap_findalldevs(&allDevs, errbuf);
  if (allDevs != NULL) {
    while (allDevs != NULL) {
      pcap_addr *pcapAddr = allDevs->addresses;
      while (pcapAddr != NULL) {
        sockaddr *addr = pcapAddr->addr;
        if (addr->sa_family == AF_INET) {
          const char *ntoaAddress = ntoa(addr);
          printf ("%s : %s\n", allDevs->name, ntoaAddress);
        }
        pcapAddr = pcapAddr->next;
      }
      allDevs = allDevs->next;
    }
  }
}
