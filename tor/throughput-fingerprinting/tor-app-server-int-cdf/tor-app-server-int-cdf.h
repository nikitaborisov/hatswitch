#ifndef TOR_APP_SERVER_INT_CDF_H_
#define TOR_APP_SERVER_INT_CDF_H_

#define BACKLOG 10
#define MAX_BUFFER_SIZE 4096
#define SLEEP_INTERVAL 1

#include <sys/types.h>
#include <unistd.h>
#include <vector>
#include "../myutil/net.h"

using namespace std;

struct TCPConnectionArg
{
	int clientSocket;
	struct sockaddr_in clientAddress;
	unsigned short int endHostID;	// in network byte order
	unsigned int bytesReceived;
	char c;
};

struct point
{
	double x;
	double y;
};

void handleTCPConnection(TCPConnectionArg tArg);

double getSample(vector<point>& vCDF);

void* garbageCollectorThreadFunction(void* arg);

void signalHandler(int sig);

#endif /* TOR_APP_SERVER_INT_CDF_H_ */
