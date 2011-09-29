//============================================================================
// Name        : tor-app-server-int-cdf.cpp
// Author      : Ahmed Khurshid
// Version     :
// Copyright   :
// Description : A simple Tor application server (interactive and takes sample from CDF)
//============================================================================

#include <sys/types.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <signal.h>
#include <sys/wait.h>
#include "../myutil/net.h"
#include "../myutil/thread.h"
#include "../myutil/StringTokenizer.h"
#include "tor-app-server-int-cdf.h"

using namespace std;

static int tcpServerSocket;

static string burstSizeCDFFileName = "";
static string gapSizeCDFFileName = "";

static vector<point> vBurstSizeCDF;
static vector<point> vGapSizeCDF;

int main(int argc, char** argv)
{
	if(argc < 4)
	{
		fprintf(stderr, "USAGE: %s <port> <burst size CDF file name> <gap size CDF file name>\n", argv[0]);
		exit(1);
	}

	tcpServerSocket = createSocket(SOCK_STREAM);

	burstSizeCDFFileName = argv[2];
	gapSizeCDFFileName = argv[3];

	point p;

	// Read and parse data from burst size CDF file
	FILE *burstSizeCDFFile = fopen(burstSizeCDFFileName.c_str(), "r");
	if(burstSizeCDFFile == NULL)
	{
		fprintf(stderr, "[TOR-APP-SERVER-INT-CDF] Cannot open file %s for input. Terminating process.\n", burstSizeCDFFileName.c_str());
		exit(1);
	}

	char buffer[MAX_BUFFER_SIZE];

	memset(buffer, 0, MAX_BUFFER_SIZE);

	while(!feof(burstSizeCDFFile))
	{
		char *s;

		do
		{
			s = fgets(buffer, MAX_BUFFER_SIZE, burstSizeCDFFile);
			if(s == NULL)
			{
				break;
			}

			if(strchr(buffer, '\r') != NULL)
			{
				*(strchr(buffer, '\r')) = '\0';
			}

			if(strchr(buffer, '\n') != NULL)
			{
				*(strchr(buffer, '\n')) = '\0';
			}
		}while(strlen(buffer) == 0);

		if(s == NULL)
		{
			if(feof(burstSizeCDFFile) != 0)
			{
				break;
			}
			else if(ferror(burstSizeCDFFile) != 0)
			{
				fprintf(stderr, "[TOR-APP-SERVER-INT-CDF] Error in reading input file %s. Terminating process.\n", burstSizeCDFFileName.c_str());
				exit(1);
			}
			else
			{
				fprintf(stderr, "[TOR-APP-SERVER-INT-CDF] Unknown error in reading input file %s. Terminating process.\n", burstSizeCDFFileName.c_str());
				exit(1);
			}
		}

		StringTokenizer st(buffer, " \r\n");
		if(st.countTokens() < 2)
		{
			fprintf(stderr, "[TOR-APP-SERVER-INT-CDF] Bad data format at input file %s. Terminating process.\n", burstSizeCDFFileName.c_str());
			exit(1);
		}

		p.x = atof(st.nextToken().c_str());
		p.y = atof(st.nextToken().c_str());

		vBurstSizeCDF.push_back(p);
	}

	fclose(burstSizeCDFFile);

	if(p.y != 1)
	{
		p.y = 1;
		vBurstSizeCDF.push_back(p);
	}

	// Read and parse data from gap size CDF file
	FILE *gapSizeCDFFile = fopen(gapSizeCDFFileName.c_str(), "r");
	if(gapSizeCDFFile == NULL)
	{
		fprintf(stderr, "[TOR-APP-SERVER-INT-CDF] Cannot open file %s for input. Terminating process.\n", gapSizeCDFFileName.c_str());
		exit(1);
	}

	memset(buffer, 0, MAX_BUFFER_SIZE);

	while(!feof(gapSizeCDFFile))
	{
		char *s;

		do
		{
			s = fgets(buffer, MAX_BUFFER_SIZE, gapSizeCDFFile);
			if(s == NULL)
			{
				break;
			}

			if(strchr(buffer, '\r') != NULL)
			{
				*(strchr(buffer, '\r')) = '\0';
			}

			if(strchr(buffer, '\n') != NULL)
			{
				*(strchr(buffer, '\n')) = '\0';
			}
		}while(strlen(buffer) == 0);

		if(s == NULL)
		{
			if(feof(gapSizeCDFFile) != 0)
			{
				break;
			}
			else if(ferror(gapSizeCDFFile) != 0)
			{
				fprintf(stderr, "[TOR-APP-SERVER-INT-CDF] Error in reading input file %s. Terminating process.\n", gapSizeCDFFileName.c_str());
				exit(1);
			}
			else
			{
				fprintf(stderr, "[TOR-APP-SERVER-INT-CDF] Unknown error in reading input file %s. Terminating process.\n", gapSizeCDFFileName.c_str());
				exit(1);
			}
		}

		StringTokenizer st(buffer, " \r\n");
		if(st.countTokens() < 2)
		{
			fprintf(stderr, "[TOR-APP-SERVER-INT-CDF] Bad data format at input file %s. Terminating process.\n", gapSizeCDFFileName.c_str());
			exit(1);
		}

		p.x = atof(st.nextToken().c_str());
		p.y = atof(st.nextToken().c_str());

		vGapSizeCDF.push_back(p);
	}

	fclose(gapSizeCDFFile);

	if(p.y != 1)
	{
		p.y = 1;
		vGapSizeCDF.push_back(p);
	}
	// End of reading input files

	struct sigaction act;
	act.sa_handler = signalHandler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGINT, &act, NULL);

	srand(time(NULL));

	int optval = 1;

	setsockopt(tcpServerSocket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

	bindSocket(tcpServerSocket, NULL, (unsigned short int)atoi(argv[1]));
	listenSocket(tcpServerSocket, BACKLOG);

	pthread_t garbageCollectorThread;
	createThread(&garbageCollectorThread, garbageCollectorThreadFunction, NULL, PTHREAD_CREATE_DETACHED);

	unsigned int i = 0;

	while(1)
	{
		++i;

		struct sockaddr_in clientAddress;
		socklen_t clientAddressLength = sizeof(clientAddress);
		int clientSocket;

		fprintf(stdout, "[TOR-APP-SERVER-INT-CDF] [%u] Waiting for new connection ...\n", i);
		clientSocket = accept(tcpServerSocket, (struct sockaddr*)&clientAddress, &clientAddressLength);
		fprintf(stdout, "[TOR-APP-SERVER-INT-CDF] [%u] Accepted new connection from %s\n", i, getIPAddress(clientAddress));

		// create worker/child process
		if (!fork()) // this is the child process
		{
			close(tcpServerSocket); // child doesn't need the listener

			TCPConnectionArg tArg;
			tArg.clientSocket = clientSocket;
			tArg.clientAddress = clientAddress;
			tArg.endHostID = 0;
			tArg.bytesReceived = 0;
			tArg.c = '.';

			handleTCPConnection(tArg);

			exit(0);
		}

		close(clientSocket); // parent doesn't need this
	}

	return EXIT_SUCCESS;
}

void handleTCPConnection(TCPConnectionArg tArg)
{
	int res = 0;

	// read end host ID sent by the client
	res = recv(tArg.clientSocket, (void*)&tArg.endHostID, sizeof(tArg.endHostID), 0);
	if(res == -1)
	{
		fprintf(stderr, "[TOR-APP-WORKER-INT-CDF] Cannot read end host ID from client. Terminating worker process.\n");
		close(tArg.clientSocket);

		exit(1);
	}

	tArg.endHostID = ntohs(tArg.endHostID);

	// read data sent by the client
	res = recv(tArg.clientSocket, (void*)&tArg.c, sizeof(tArg.c), 0);
	if(res == -1)
	{
		fprintf(stderr, "[TOR-APP-WORKER-INT-CDF] Cannot read data from client. Terminating worker process.\n");
		close(tArg.clientSocket);

		exit(1);
	}

	char data[MAX_BUFFER_SIZE];

	for(int i = 0; i < MAX_BUFFER_SIZE; i++)
	{
		data[i] = tArg.c;

		if((i > 0) && ((i % 40) == 0))
		{
			data[i] = '\n';
		}
	}

	int burstSize;
	double gapSize;

	// send data to client in bursts
	while(1)
	{
		burstSize = (int)getSample(vBurstSizeCDF);
		gapSize = getSample(vGapSizeCDF);

		fprintf(stdout, "[handleTCPConnection] burstSize = %d, gapSize = %f\n", burstSize, gapSize);

		int n = 0;
		while(n != burstSize)
		{
			res = send(tArg.clientSocket, data, min(burstSize - n, MAX_BUFFER_SIZE), 0);
			if(res == -1)
			{
				fprintf(stdout, "---------- [TOR-APP-WORKER-INT-CDF] Oopsss. Error in sending data.\n");
				perror("");
				break;
			}
			else
			{
				n += res;
			}
		}

		fprintf(stdout, "[TOR-APP-WORKER-INT-CDF] Sent burst of size %d bytes. Going to sleep for %f seconds.\n", n, gapSize);

		if(gapSize > 0)
		{
			sleep(gapSize);
		}

		unsigned long usecGap = (unsigned long)((gapSize - (unsigned long)gapSize) * 1000000);
		if(usecGap != 0)
		{
			usleep(usecGap);
		}
	}

	close(tArg.clientSocket);
}

double getSample(vector<point>& vCDF)
{
	double x, y = (double)rand()/RAND_MAX;
	double x1 = 0, y1 = 0, x2 = 1, y2 = 1;

	for(unsigned int i = 0; i < (vCDF.size() - 1); i++)
	{
		x1 = vCDF[i].x;
		y1 = vCDF[i].y;

		x2 = vCDF[i + 1].x;
		y2 = vCDF[i + 1].y;

		if((y >= y1) && (y <= y2))
		{
			break;
		}
	}

	x = x1 + ((x2 - x1)/(y2 - y1))*(y - y1);

	fprintf(stdout, "[getSample] y = %f, x = %f\n", y, x);

	return x;
}

void* garbageCollectorThreadFunction(void* arg)
{
	while(1)
	{
		sleep(SLEEP_INTERVAL);

		waitpid(-1, (int*)0, WNOHANG);
	}

	pthread_exit(NULL);
}

void signalHandler(int sig)
{
	close(tcpServerSocket);
	exit(0);
}
