#ifndef TOR_NODE_THROUGHPUT_CALC_H_
#define TOR_NODE_THROUGHPUT_CALC_H_

#include <sys/types.h>
#include <unistd.h>
#include <string>
#include <pcap.h>

using namespace std;

#define MAX_BUFFER_SIZE 4096

#define SOCKS_SERVER_IP_ADDRESS "127.0.0.1"
#define SOCKS_SERVER_PORT 9050

#define TOR_CONTROL_IP_ADDRESS "127.0.0.1"
#define TOR_CONTROL_PORT 9051

#define CIRCUIT_CREATION_COUNT 1
#define CIRCUIT_SETUP_DELAY 10 // in seconds

int createTorCircuit();
int verifyTorCircuit();
int sendTorCommand(int torControlSocket, const string& command, char* recvBuffer);
void measureTPandGP();

void* pcapThreadFunction(void* arg);
void got_packet(unsigned char* args, const struct pcap_pkthdr* header, const unsigned char* packet);

void* recvThreadFunction(void* arg);

void signalHandler(int sig);

#endif /* TOR_NODE_THROUGHPUT_CALC_H_ */
