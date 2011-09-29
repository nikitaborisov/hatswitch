//============================================================================
// Name        : tor-app-server.cpp
// Author      : Ahmed Khurshid
// Version     :
// Copyright   : 
// Description : A simple Tor application server
//============================================================================

#include <sys/types.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <signal.h>
#include <sys/wait.h>
#include "../myutil/net.h"
#include "../myutil/thread.h"
#include "tor-app-server.h"

using namespace std;

static int tcpServerSocket;

int main(int argc, char** argv)
{
	if(argc < 2)
	{
		fprintf(stderr, "USAGE: %s <port>\n", argv[0]);
		exit(1);
	}

	tcpServerSocket = createSocket(SOCK_STREAM);

	struct sigaction act;
	act.sa_handler = signalHandler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGINT, &act, NULL);

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

		fprintf(stdout, "[TOR-APP-SERVER] [%u] Waiting for new connection ...\n", i);
		clientSocket = accept(tcpServerSocket, (struct sockaddr*)&clientAddress, &clientAddressLength);
		fprintf(stdout, "[TOR-APP-SERVER] [%u] Accepted new connection from %s\n", i, getIPAddress(clientAddress));

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
		fprintf(stderr, "[TOR-APP-WORKER] Cannot read end host ID from client. Terminating worker process.\n");
		close(tArg.clientSocket);

		exit(1);
	}

	tArg.endHostID = ntohs(tArg.endHostID);

	// read data sent by the client
	res = recv(tArg.clientSocket, (void*)&tArg.c, sizeof(tArg.c), 0);
	if(res == -1)
	{
		fprintf(stderr, "[TOR-APP-WORKER] Cannot read data from client. Terminating worker process.\n");
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

	// send data to client
	while((res = send(tArg.clientSocket, data, MAX_BUFFER_SIZE, 0)) != -1)
	{
		// do nothing here
	}

	close(tArg.clientSocket);
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
