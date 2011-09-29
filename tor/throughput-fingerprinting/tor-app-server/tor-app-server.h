#ifndef TOR_APP_SERVER_H_
#define TOR_APP_SERVER_H_

#define BACKLOG 10
#define MAX_BUFFER_SIZE 4096
#define SLEEP_INTERVAL 1

#include <sys/types.h>
#include <unistd.h>
#include "../myutil/net.h"

struct TCPConnectionArg
{
	int clientSocket;
	struct sockaddr_in clientAddress;
	unsigned short int endHostID;	// in network byte order
	unsigned int bytesReceived;
	char c;
};

void handleTCPConnection(TCPConnectionArg tArg);

void* garbageCollectorThreadFunction(void* arg);

void signalHandler(int sig);

#endif /* TOR_APP_SERVER_H_ */
