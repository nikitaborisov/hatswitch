//============================================================================
// Name        : tor-app-client.cpp
// Author      : Ahmed Khurshid
// Version     :
// Copyright   :
// Description : A simple Tor application client (uses pcap)
//============================================================================

#include <sys/types.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <signal.h>
#include <pcap.h>
#include "../myutil/net.h"
#include "../myutil/thread.h"
#include "../myutil/socks.h"
#include "../myutil/Packet.h"
#include "tor-app-client.h"

using namespace std;

static int tcpSocket = -1;

static double duration = 0;
static double secCounter = 0;
static double measurementInterval = 0;
static double measurementOffset = 0;

static double pcapBytesReceived = 0;
static double tcpBytesReceived = 0;

static pthread_mutex_t pcapMutex;
static pthread_mutex_t tcpMutex;
static pthread_mutex_t fileMutex;

static FILE* outFile = NULL;

static string guardNodeIPAddress = "";
static string guardNodePort = "";

static pcap_t* handle;			/* Session handle */
static struct bpf_program fp;	/* The compiled filter */

static bool exitFlag = false;

int main(int argc, char** argv)
{
	if(argc < 12)
	{
		fprintf(stderr, "USAGE: %s <SOCKS IP address> <SOCKS port> <server IP address> <server port> <end host ID> <character> <duration (>= 0) (in seconds)> <measurement interval (> 0) (in seconds)> <measurement offset (>= 0) (in seconds)> <guard node IP address> <guard node port>\n", argv[0]);
		exit(1);
	}

	duration = atof(argv[7]);
	if(duration < 0)
	{
		fprintf(stderr, "[TOR-APP-CLIENT] Invalid duration. Must be >= 0. Terminating process.\n");
		exit(1);
	}

	measurementInterval = atof(argv[8]);
	if(measurementInterval <= 0)
	{
		fprintf(stderr, "[TOR-APP-CLIENT] Invalid measurement interval. Must be > 0. Terminating process.\n");
		exit(1);
	}

	measurementOffset = atof(argv[9]);
	if(measurementOffset < 0)
	{
		fprintf(stderr, "[TOR-APP-CLIENT] Invalid measurement offset. Must be >= 0. Terminating process.\n");
		exit(1);
	}

	guardNodeIPAddress = argv[10];
	guardNodePort = argv[11];

	createMutex(&pcapMutex);
	createMutex(&tcpMutex);
	createMutex(&fileMutex);

	tcpSocket = createSocket(SOCK_STREAM);

	struct sigaction act;
	act.sa_handler = signalHandler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGINT, &act, NULL);

	struct sockaddr_in socksServerAddress = createSocketAddress(argv[1], (unsigned short int)atoi(argv[2]));
	int res;

	res = connect(tcpSocket, (struct sockaddr*)&socksServerAddress, sizeof(socksServerAddress));
	if(res == -1)
	{
		fprintf(stderr, "[TOR-APP-CLIENT] Cannot connect to SOCKS server. Terminating process.\n");
		close(tcpSocket);
		exit(1);
	}
	fprintf(stdout, "[TOR-APP-CLIENT] Connected to SOCKS server.\n");

	string serverIPAddress = argv[3];
	unsigned short int serverPort = (unsigned short int)atoi(argv[4]);

	// perform handshake with the SOCKS server

	SocksAuthMethodRequest samReq = createSocksAuthMethodRequest(0x05, 1, SOCKS_AUTH_METHOD_NONE);
	res = send(tcpSocket, (void*)&samReq, sizeof(samReq), 0);
	if(res == -1)
	{
		fprintf(stderr, "[TOR-APP-CLIENT] Failed to send SOCKS authentication method request. Terminating process.\n");
		close(tcpSocket);
		exit(1);
	}
	fprintf(stdout, "[TOR-APP-CLIENT] Sent authentication method request to SOCKS server.\n");

	SocksAuthMethodResponse samRes;
	res = recv(tcpSocket, (void*)&samRes, sizeof(samRes), 0);
	if(res == -1)
	{
		fprintf(stderr, "[TOR-APP-CLIENT] Failed to receive SOCKS authentication method response. Terminating process.\n");
		close(tcpSocket);
		exit(1);
	}
	else
	{
		fprintf(stdout, "[TOR-APP-CLIENT] Received authentication method response from SOCKS server.\n");

		if(samRes.method == SOCKS_AUTH_METHOD_UNACCEPTABLE)
		{
			fprintf(stderr, "[TOR-APP-CLIENT] SOCKS authentication method unacceptable. Terminating process.\n");
			close(tcpSocket);
			exit(1);
		}
	}
	fprintf(stdout, "[TOR-APP-CLIENT] Authentication completed.\n");

	SocksConnRequest scReq = createSocksConnRequest(0x05, SOCKS_CMD_TCP_CONN, SOCKS_ADDR_TYPE_IPV4, serverIPAddress.c_str(), serverPort);
	res = send(tcpSocket, (void*)&scReq, sizeof(scReq), 0);
	if(res == -1)
	{
		fprintf(stderr, "[TOR-APP-CLIENT] Failed to send SOCKS connection request. Terminating process.\n");
		close(tcpSocket);
		exit(1);
	}
	fprintf(stdout, "[TOR-APP-CLIENT] Sent connection request to SOCKS server.\n");

	SocksConnResponse scRes;
	res = recv(tcpSocket, (void*)&scRes, sizeof(scRes), 0);
	if(res == -1)
	{
		fprintf(stderr, "[TOR-APP-CLIENT] Failed to receive SOCKS connection response. Terminating process.\n");
		close(tcpSocket);
		exit(1);
	}
	else
	{
		fprintf(stdout, "[TOR-APP-CLIENT] Received connection response from SOCKS server.\n");

		if(scRes.status != SOCKS_STATUS_REQUEST_GRANTED)
		{
			fprintf(stderr, "[TOR-APP-CLIENT] SOCKS connection error (status = %x). Terminating process.\n", scRes.status);
			close(tcpSocket);
			exit(1);
		}
	}
	fprintf(stdout, "[TOR-APP-CLIENT] Connection successful.\n");

	// handshake done; now send and recv data
	unsigned short int endHostID = htons((unsigned short int)atoi(argv[5]));
	res = send(tcpSocket, (void*)&endHostID, sizeof(endHostID), 0);
	if(res == -1)
	{
		fprintf(stderr, "[TOR-APP-CLIENT] Failed to send end host ID. Terminating process.\n");
		close(tcpSocket);
		exit(1);
	}
	fprintf(stdout, "[TOR-APP-CLIENT] Sent end host ID to server.\n");

//	usleep(500000); // sleep for 0.5 sec to let the monitor threads to initialize

	char c = argv[6][0];
	res = send(tcpSocket, (void*)&c, sizeof(c), 0);
	if(res == -1)
	{
		fprintf(stderr, "[TOR-APP-CLIENT] Failed to send client character. Terminating process.\n");
		close(tcpSocket);
		exit(1);
	}
	fprintf(stdout, "[TOR-APP-CLIENT] Sent client character to server.\n");

	char fileName[MAX_BUFFER_SIZE];
	snprintf(fileName, MAX_BUFFER_SIZE - 1, "client-%d-%s.txt", atoi(argv[5]), argv[6]);

	outFile = fopen(fileName, "w");
	if(outFile == NULL)
	{
		fprintf(stderr, "[TOR-APP-CLIENT] Cannot open output file. Terminating process.\n");
		exit(1);
	}

	pthread_t pcapThread;
	createThread(&pcapThread, pcapThreadFunction, NULL, PTHREAD_CREATE_DETACHED);

	pthread_t tpgpMonitorThread;
	createThread(&tpgpMonitorThread, tpgpMonitorThreadFunction, NULL, PTHREAD_CREATE_DETACHED);

	char data[MAX_BUFFER_SIZE];

	while(exitFlag == false)
	{
		res = recv(tcpSocket, data, MAX_BUFFER_SIZE, 0);
		if(res == -1)
		{
			fprintf(stderr, "[TOR-APP-CLIENT] TCP recv failure. Terminating process.\n");
			exitFlag = true;
			break;
		}
		else
		{
			if((duration != 0) && (secCounter >= duration))
			{
				exitFlag = true;
				break;
			}

			pthread_mutex_lock(&tcpMutex);
			tcpBytesReceived += res;
			pthread_mutex_unlock(&tcpMutex);

			// data[res - 1] = '\0';
			// fprintf(stdout, "%s", data);
		}
	}

	close(tcpSocket);

	pthread_mutex_lock(&fileMutex);
	if(outFile != NULL)
	{
		fclose(outFile);
		outFile = NULL;
	}
	pthread_mutex_unlock(&fileMutex);

	return EXIT_SUCCESS;
}

void* pcapThreadFunction(void* arg)
{
	char* dev;						/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	bpf_u_int32 mask;				/* Our netmask */
	bpf_u_int32 net;				/* Our IP */

	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL)
	{
		fprintf(stderr, "[pcapThreadFunction] Couldn't find default device: %s. Terminating process.\n", errbuf);
		exit(1);
	}

	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
	{
		fprintf(stderr, "[pcapThreadFunction] Couldn't get netmask for device %s: %s. Terminating process.\n", dev, errbuf);
		exit(1);
	}

	/* Open the session in non-promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "[pcapThreadFunction] Couldn't open device %s: %s. Terminating process.\n", dev, errbuf);
		exit(1);
	}

	// char filter_exp[] = "host 128.174.240.149 and src port 22";	/* The filter expression */
	string filter_exp = "host ";
	filter_exp += guardNodeIPAddress;
	filter_exp += " and src port ";
	filter_exp += guardNodePort;

	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, (char*)filter_exp.c_str(), 0, net) == -1)
	{
		fprintf(stderr, "[pcapThreadFunction] Couldn't parse filter %s: %s. Terminating process.\n", filter_exp.c_str(), pcap_geterr(handle));
		exit(1);
	}

	if (pcap_setfilter(handle, &fp) == -1)
	{
		fprintf(stderr, "[pcapThreadFunction] Couldn't install filter %s: %s. Terminating process.\n", filter_exp.c_str(), pcap_geterr(handle));
		exit(1);
	}

	/* Start packet capture */

	pcap_loop(handle, -1, got_packet, NULL);

	/* And close the session */
	pcap_freecode(&fp);
	pcap_close(handle);

	pthread_exit(NULL);
}

void got_packet(unsigned char* args, const struct pcap_pkthdr* header, const unsigned char* packet)
{
	if(exitFlag == true)
	{
		pcap_freecode(&fp);
		pcap_close(handle);

		pthread_exit(NULL);
	}
	else
	{
		Packet p(packet, header->len);

		//	fprintf(stdout, "Got packet, length: %d\n", p.getPayloadLength());

		pthread_mutex_lock(&pcapMutex);
		pcapBytesReceived += p.getPayloadLength();
		pthread_mutex_unlock(&pcapMutex);
	}
}

void* tpgpMonitorThreadFunction(void* arg)
{
	while(1)
	{
		if(exitFlag == true)
		{
			break;
		}

		if((duration != 0) && (secCounter >= duration))
		{
			exitFlag = true;
			break;
		}

		unsigned int n = 0;

		if((unsigned int)measurementInterval != 0)
		{
			n = sleep((unsigned int)measurementInterval);
		}

		if(((unsigned int)measurementInterval != 0) && (n == (unsigned int)measurementInterval))
		{
			fprintf(stdout, "---------- [tpgpMonitorThreadFunction] Interrupted while sleeping.\n");

			pthread_mutex_lock(&pcapMutex);
			pcapBytesReceived = 0;
			pthread_mutex_unlock(&pcapMutex);

			pthread_mutex_lock(&tcpMutex);
			tcpBytesReceived = 0;
			pthread_mutex_unlock(&tcpMutex);

			continue;
		}
		else
		{
			// fprintf(stdout, "++++++++++ [tpgpMonitorThreadFunction] Had a good sleep.\n");
		}

		secCounter += ((unsigned int)measurementInterval - n);

		unsigned long usecInterval = (unsigned long)((measurementInterval - (unsigned int)measurementInterval) * 1000000);

		if((usecInterval == 0) && ((unsigned int)measurementInterval == 0))
		{
			usecInterval = 1;
			measurementInterval = 1.0 / 1000000.0; // set it to 1 us
		}

		if(usecInterval != 0)
		{
			usleep(usecInterval);
			secCounter += (measurementInterval - (unsigned int)measurementInterval);
		}

		pthread_mutex_lock(&pcapMutex);
		double tp = ((pcapBytesReceived / (measurementInterval - n)) * 1) / 1024; // KBps
		pcapBytesReceived = 0;
		pthread_mutex_unlock(&pcapMutex);

		pthread_mutex_lock(&tcpMutex);
		double gp = ((tcpBytesReceived / (measurementInterval - n)) * 1) / 1024; // KBps
		tcpBytesReceived = 0;
		pthread_mutex_unlock(&tcpMutex);

		fprintf(stdout, "Time %f Throughput(KBps) %f Goodput(KBps) %f\n", (secCounter + measurementOffset), tp, gp);

		pthread_mutex_lock(&fileMutex);
		if(outFile != NULL)
		{
			fprintf(outFile, "Time %f Throughput(KBps) %f Goodput(KBps) %f\n", (secCounter + measurementOffset), tp, gp);
			// fflush(outFile);
		}
		pthread_mutex_unlock(&fileMutex);
	}

	if(tcpSocket != -1)
	{
		close(tcpSocket);
	}

	pthread_mutex_lock(&fileMutex);
	if(outFile != NULL)
	{
		fclose(outFile);
		outFile = NULL;
	}
	pthread_mutex_unlock(&fileMutex);

	exit(0);

	pthread_exit(NULL); // program will never reach here
}

void signalHandler(int sig)
{
	close(tcpSocket);

	if(outFile != NULL)
	{
		fclose(outFile);
		outFile = NULL;
	}

	exit(0);
}
