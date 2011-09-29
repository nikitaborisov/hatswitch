#ifndef TOR_APP_CLIENT_H_
#define TOR_APP_CLIENT_H_

#include <sys/types.h>
#include <unistd.h>
#include <pcap.h>

#define MAX_BUFFER_SIZE 4096

void* pcapThreadFunction(void* arg);
void got_packet(unsigned char* args, const struct pcap_pkthdr* header, const unsigned char* packet);

void* tpgpMonitorThreadFunction(void* arg);

void signalHandler(int sig);

#endif /* TOR_APP_CLIENT_H_ */
