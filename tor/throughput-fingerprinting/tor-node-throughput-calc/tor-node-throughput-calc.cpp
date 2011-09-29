//============================================================================
// Name        : tor-node-throughput-calc.cpp
// Author      : Ahmed Khurshid
// Version     :
// Copyright   : 
// Description : A simple Tor node throughput and goodput calculator
//============================================================================

#include <sys/types.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <signal.h>
#include <sys/wait.h>
#include <pcap.h>
#include "../myutil/net.h"
#include "../myutil/thread.h"
#include "../myutil/socks.h"
#include "../myutil/StringTokenizer.h"
#include "../myutil/Packet.h"
#include "tor-node-throughput-calc.h"

using namespace std;

static int torControlSocket = -1;
static int clientSocket = -1;

static double duration = 0;
static double secCounter = 0;
static double measurementInterval = 0;

static double pcapBytesReceived = 0;
static double tcpBytesReceived = 0;

static pthread_mutex_t pcapMutex;
static pthread_mutex_t tcpMutex;
static pthread_mutex_t fileMutex;

static FILE *allDataFile = NULL;
static FILE *tpgpFile = NULL;

static string serverIPAddress = "";
static unsigned short int serverPort = 0;

static string guardNodeName = "";
static string guardNodeFingerprint = "";

static string exitNodeName = "";
static string exitNodeFingerprint = "";

static string torNodeInfoFileName = "";

static string middlemanNodeName = "";
static string middlemanNodeIPAddress = "";
static unsigned short int middlemanNodePort = 0;
static string middlemanNodeFingerprint = "";

static pcap_t* handle;			// Session handle
static struct bpf_program fp;	// The compiled filter

static bool exitFlag = false;

static int circuitId = 0;

#define BASIC_TOR_COMMAND_COUNT 8

static const string basicTorCommand[BASIC_TOR_COMMAND_COUNT] = {
						"authenticate \"\"\n",
						"setconf __DisablePredictedCircuits=1\n",
						"setconf MaxOnionsPending=0\n",
						"setconf newcircuitperiod=999999999\n",
						"setconf maxcircuitdirtiness=999999999\n",
						"setconf EnforceDistinctSubnets=0\n",
						"setconf UseEntryGuards=0\n",
						"setconf __LeaveStreamsUnattached=1\n"
};

int main(int argc, char** argv)
{
	if(argc < 10)
	{
		fprintf(stderr, "USAGE: %s <server IP address> <server port> <duration (> 0) (in seconds)> <measurement interval (> 0) (in seconds)> <guard node name> <guard node fingerprint> <exit node name> <exit node fingerprint> <tor node info file name>\n", argv[0]);
		exit(1);
	}

	struct sigaction act;
	act.sa_handler = signalHandler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGINT, &act, NULL);

	duration = atof(argv[3]);
	if(duration <= 0)
	{
		fprintf(stderr, "[TOR-NODE-TP-GP-CALC] Invalid duration. Must be > 0. Terminating process.\n");
		exit(1);
	}

	measurementInterval = atof(argv[4]);
	if(measurementInterval <= 0)
	{
		fprintf(stderr, "[TOR-NODE-TP-GP-CALC] Invalid measurement interval. Must be > 0. Terminating process.\n");
		exit(1);
	}

	string allDataFileName = "./Output/all-tp-gp-data.txt";
	allDataFile = fopen(allDataFileName.c_str(), "w");
	if(allDataFile == NULL)
	{
		fprintf(stderr, "[TOR-NODE-TP-GP-CALC] Cannot open file %s for output. Terminating process.\n", allDataFileName.c_str());
		exit(1);
	}

	string tpgpFileName = "./Output/node-tp-gp.txt";
	tpgpFile = fopen(tpgpFileName.c_str(), "w");
	if(tpgpFile == NULL)
	{
		fprintf(stderr, "[TOR-NODE-TP-GP-CALC] Cannot open file %s for output. Terminating process.\n", tpgpFileName.c_str());
		exit(1);
	}

	serverIPAddress = argv[1];
	serverPort = (unsigned short int)atoi(argv[2]);
	guardNodeName = argv[5];
	guardNodeFingerprint = argv[6];
	exitNodeName = argv[7];
	exitNodeFingerprint = argv[8];
	torNodeInfoFileName = argv[9];

	createMutex(&pcapMutex);
	createMutex(&tcpMutex);
	createMutex(&fileMutex);

	// Read and parse data from input file
	FILE *inFile = fopen(torNodeInfoFileName.c_str(), "r");
	if(inFile == NULL)
	{
		fprintf(stderr, "[TOR-NODE-TP-GP-CALC] Cannot open file %s for input. Terminating process.\n", torNodeInfoFileName.c_str());
		exit(1);
	}

	char buffer[MAX_BUFFER_SIZE];
	vector<string> vNodeInfo;

	memset(buffer, 0, MAX_BUFFER_SIZE);

	while(!feof(inFile))
	{
		char *s;

		do
		{
			s = fgets(buffer, MAX_BUFFER_SIZE, inFile);
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
			if(feof(inFile) != 0)
			{
				break;
			}
			else if(ferror(inFile) != 0)
			{
				fprintf(stderr, "[TOR-NODE-TP-GP-CALC] Error in reading input file %s. Terminating process.\n", torNodeInfoFileName.c_str());
				exit(1);
			}
			else
			{
				fprintf(stderr, "[TOR-NODE-TP-GP-CALC] Unknown error in reading input file %s. Terminating process.\n", torNodeInfoFileName.c_str());
				exit(1);
			}
		}

		string strNodeInfo = buffer;
		vNodeInfo.push_back(strNodeInfo);
	}

	fclose(inFile);

	fprintf(stdout, "[TOR-NODE-TP-GP-CALC] Completed reading input file %s.\n\n", torNodeInfoFileName.c_str());

	// Create connection with the Tor control server
	torControlSocket = createSocket(SOCK_STREAM);

	struct sockaddr_in serverAddress = createSocketAddress(TOR_CONTROL_IP_ADDRESS, TOR_CONTROL_PORT);
	int res;

	res = connect(torControlSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress));
	if(res == -1)
	{
		fprintf(stderr, "[TOR-NODE-TP-GP-CALC] Cannot connect to Tor control server. Terminating process.\n");
		exit(1);
	}
	fprintf(stdout, "[TOR-NODE-TP-GP-CALC] Connected to Tor control server.\n");

	char recvBuffer[MAX_BUFFER_SIZE];

	// Send the basic commands first
	for(int i = 0; i < BASIC_TOR_COMMAND_COUNT; i++)
	{
		res = sendTorCommand(torControlSocket, basicTorCommand[i], recvBuffer);
		if(res == -1)
		{
			fprintf(stderr, "[TOR-NODE-TP-GP-CALC] Failed to send command [%s] to Tor control server. Terminating process.\n", basicTorCommand[i].c_str());
			exit(1);
		}
		else
		{
			fprintf(stdout, "[TOR-NODE-TP-GP-CALC] Sent command [%s] to Tor control server.\n", basicTorCommand[i].c_str());
		}
	}
	fprintf(stdout, "[TOR-NODE-TP-GP-CALC] Sent all the basic commands to Tor control server.\n");

	// Measure throughput of each Tor node
	for(unsigned int i = 1; i <= vNodeInfo.size(); i++)
	{
		string strNodeInfo = vNodeInfo[i - 1];
		StringTokenizer st(strNodeInfo, " \r\n");
		if(st.countTokens() < 9)
		{
			fprintf(stderr, "[TOR-NODE-TP-GP-CALC] Unknown data format at input file %s. Terminating process.\n", torNodeInfoFileName.c_str());
			exit(1);
		}

		middlemanNodeName = st.nextToken(); // 1st token (nickname)
		middlemanNodeIPAddress = st.nextToken(); // 2nd token (IP address)
		middlemanNodePort = (unsigned short int)atoi(st.nextToken().c_str()); // 3rd token (ORPort)

		st.nextToken(); // Skip the 4th token (SOCKSPort)
		st.nextToken(); // Skip the 5th token (DirPort)

		middlemanNodeFingerprint = st.nextToken(); // 6th token (fingerprint);

		if(middlemanNodeName.compare(exitNodeName) == 0)
		{
			fprintf(stdout, "[TOR-NODE-TP-GP-CALC] [%u] Skipping the middleman node that is also the exit node. [Middleman: %s] [Exit: %s]\n\n", i, middlemanNodeName.c_str(), exitNodeName.c_str());
			continue;
		}
/*
		if(middlemanNodeName.compare("Unnamed") == 0)
		{
			fprintf(stdout, "[TOR-NODE-TP-GP-CALC] [%u] Skipping Unnamed middleman node. [Middleman: %s] [Exit: %s]\n\n", i, middlemanNodeName.c_str(), exitNodeName.c_str());
			continue;
		}
*/
		fprintf(stdout, "[TOR-NODE-TP-GP-CALC] [%u] Testing new circuit. [Middleman: %s] [Exit: %s]\n", i, middlemanNodeName.c_str(), exitNodeName.c_str());

		int res = createTorCircuit();
		if(res == 0) // No circuit was created
		{
			fprintf(stderr, "[TOR-NODE-TP-GP-CALC] Circuit creation error. Skipping this circuit. [Middleman: %s] [Exit: %s]\n", middlemanNodeName.c_str(), exitNodeName.c_str());
			fprintf(stdout, "[TOR-NODE-TP-GP-CALC] [%u] Circuit skipped. [Middleman: %s] [Exit: %s]\n\n", i, middlemanNodeName.c_str(), exitNodeName.c_str());

			pthread_mutex_lock(&fileMutex);
			fprintf(allDataFile, "[TOR-NODE-TP-GP-CALC] Circuit creation error. Skipping this circuit. [Middleman: %s] [Exit: %s]\n", middlemanNodeName.c_str(), exitNodeName.c_str());
			fflush(allDataFile);
			fprintf(tpgpFile, "[TOR-NODE-TP-GP-CALC] Circuit creation error. Skipping this circuit. [Middleman: %s] [Exit: %s]\n", middlemanNodeName.c_str(), exitNodeName.c_str());
			fflush(tpgpFile);
			pthread_mutex_unlock(&fileMutex);

			continue;
		}
		else
		{
			fprintf(stdout, "[TOR-NODE-TP-GP-CALC] [%u] Circuit creation successful. [Middleman: %s] [Exit: %s]\n", i, middlemanNodeName.c_str(), exitNodeName.c_str());
		}

		// Wait for the circuit to set up completely
		fprintf(stdout, "[TOR-NODE-TP-GP-CALC] [%u] Waiting for the circuit to set up completely ...\n", i);
		sleep(CIRCUIT_SETUP_DELAY);

		// Create child process
		pid_t childProcessId = fork();
		if(childProcessId == 0) // This is the child process
		{
			measureTPandGP();
			exit(0);
		}
		else // This is the parent process
		{
			// Wait for the child process to finish its job and terminate
			pid_t id = wait((int*)0);
			if(id != childProcessId)
			{
				fprintf(stderr, "[TOR-NODE-TP-GP-CALC] [%u] Child process management error. [Found: %d] [Expected: %d]. Terminating process.\n", i, id, childProcessId);
				exit(1);
			}
		}

		fprintf(stdout, "[TOR-NODE-TP-GP-CALC] [%u] Circuit test completed. [Middleman: %s] [Exit: %s]\n\n", i, middlemanNodeName.c_str(), exitNodeName.c_str());
	}

	// Clean up and exit from program
	pthread_mutex_lock(&fileMutex);
	if(allDataFile != NULL)
	{
		fclose(allDataFile);
		allDataFile = NULL;
	}

	if(tpgpFile != NULL)
	{
		fclose(tpgpFile);
		tpgpFile = NULL;
	}
	pthread_mutex_unlock(&fileMutex);

	// Terminate Tor control session
	fprintf(stdout, "[TOR-NODE-TP-GP-CALC] Terminating Tor control session ...\n");

	res = sendTorCommand(torControlSocket, "quit\n", recvBuffer);
	if(res == -1)
	{
		fprintf(stderr, "[TOR-NODE-TP-GP-CALC] Failed to send command [%s] to Tor control server. Terminating process.\n", "quit\n");
		exit(1);
	}

	close(torControlSocket);

	fprintf(stdout, "[TOR-NODE-TP-GP-CALC] Terminated Tor control session.\n");

	return EXIT_SUCCESS;
}

int createTorCircuit()
{
	char recvBuffer[MAX_BUFFER_SIZE];
	int retVal = 0;
	int res;

	// Close all the existing circuits
	res = sendTorCommand(torControlSocket, "getinfo circuit-status\n", recvBuffer);
	if(res == -1)
	{
		fprintf(stderr, "[createTorCircuit] Failed to send command [%s] to Tor control server. Terminating process.\n", "getinfo circuit-status\n");
		exit(1);
	}

	StringTokenizer st1(recvBuffer, "\r\n");
	while(st1.hasMoreTokens() == true)
	{
		string line = st1.nextToken();
		if(line.compare("250 OK") == 0)
		{
			continue;
		}

		StringTokenizer st2(line, " ");
		string circuitId = st2.nextToken();
		if(circuitId.find("250-circuit-status=") != string::npos)
		{
			StringTokenizer st3(circuitId, "=");
			if(st3.countTokens() > 1)
			{
				st3.nextToken(); // Ignore the 1st token (250-circuit-status)
			}
			circuitId = st3.nextToken();
		}

		string command = "closecircuit ";
		command += circuitId;
		command += "\n";

		res = sendTorCommand(torControlSocket, command, recvBuffer);
		if(res == -1)
		{
			fprintf(stderr, "[createTorCircuit] Failed to send command [%s] to Tor control server. Terminating process.\n", command.c_str());
			exit(1);
		}
	}
	fprintf(stdout, "[createTorCircuit] Closed all existing circuits.\n");

	// Create/extend the new circuit (CIRCUIT_CREATION_COUNT times)
	for(int i = 0; i < CIRCUIT_CREATION_COUNT; i++)
	{
		string command = "extendcircuit 0 ";
		command += guardNodeName;
		// command += guardNodeFingerprint;
		command += ",";
		command += middlemanNodeFingerprint;
		command += ",";
		command += exitNodeName;
		// command += exitNodeFingerprint;
		command += "\n";

		res = sendTorCommand(torControlSocket, command, recvBuffer);
		if(res == -1)
		{
			fprintf(stderr, "[createTorCircuit] Failed to send command [%s] to Tor control server. Terminating process.\n", command.c_str());
			exit(1);
		}

		if(strstr(recvBuffer, "250 EXTENDED") == NULL)
		{
			fprintf(stderr, "[createTorCircuit] Failed to create circuit. [Middleman: %s] [Exit: %s]\n", middlemanNodeName.c_str(), exitNodeName.c_str());
		}
		else
		{
			fprintf(stdout, "[createTorCircuit] Circuit created. [Middleman: %s] [Exit: %s]\n", middlemanNodeName.c_str(), exitNodeName.c_str());
			++retVal;
		}

		StringTokenizer st(recvBuffer, " \r\n");
		if(st.countTokens() < 3)
		{
			fprintf(stderr, "[createTorCircuit] Bad response from Tor control server. Failed to read circuit ID. Terminating process. [Middleman: %s] [Exit: %s]\n", middlemanNodeName.c_str(), exitNodeName.c_str());
			exit(1);
		}
		else
		{
			st.nextToken(); // Skip the 1st token ("250")
			st.nextToken(); // Skip the 2nd token ("EXTENDED")
			circuitId = atoi(st.nextToken().c_str());
		}
	}

	return retVal;
}

int verifyTorCircuit()
{
	char recvBuffer[MAX_BUFFER_SIZE];
	int retVal = 0;
	int res;

	res = sendTorCommand(torControlSocket, "getinfo circuit-status\n", recvBuffer);
	if(res == -1)
	{
		fprintf(stderr, "[verifyTorCircuit] Failed to send command [%s] to Tor control server. Terminating process.\n", "getinfo circuit-status\n");
		exit(1);
	}

	string str1 = "BUILT ";
	str1 += guardNodeName;
	str1 += ",";
	str1 += middlemanNodeName;
	str1 += ",";
	str1 += exitNodeName;
	str1 += " PURPOSE=GENERAL";

	string str2 = "BUILT ";
	str2 += guardNodeFingerprint;
	str2 += ",";
	str2 += middlemanNodeName;
	str2 += ",";
	str2 += exitNodeName;
	str2 += " PURPOSE=GENERAL";

	string str3 = "BUILT ";
	str3 += guardNodeName;
	str3 += ",";
	str3 += middlemanNodeName;
	str3 += ",";
	str3 += exitNodeFingerprint;
	str3 += " PURPOSE=GENERAL";

	string str4 = "BUILT ";
	str4 += guardNodeFingerprint;
	str4 += ",";
	str4 += middlemanNodeName;
	str4 += ",";
	str4 += exitNodeFingerprint;
	str4 += " PURPOSE=GENERAL";

	string str5 = "BUILT ";
	str5 += guardNodeName;
	str5 += ",";
	str5 += middlemanNodeFingerprint;
	str5 += ",";
	str5 += exitNodeName;
	str5 += " PURPOSE=GENERAL";

	string str6 = "BUILT ";
	str6 += guardNodeFingerprint;
	str6 += ",";
	str6 += middlemanNodeFingerprint;
	str6 += ",";
	str6 += exitNodeName;
	str6 += " PURPOSE=GENERAL";

	string str7 = "BUILT ";
	str7 += guardNodeName;
	str7 += ",";
	str7 += middlemanNodeFingerprint;
	str7 += ",";
	str7 += exitNodeFingerprint;
	str7 += " PURPOSE=GENERAL";

	string str8 = "BUILT ";
	str8 += guardNodeFingerprint;
	str8 += ",";
	str8 += middlemanNodeFingerprint;
	str8 += ",";
	str8 += exitNodeFingerprint;
	str8 += " PURPOSE=GENERAL";

	if((strstr(recvBuffer, str1.c_str()) == NULL)
			&& (strstr(recvBuffer, str2.c_str()) == NULL)
			&& (strstr(recvBuffer, str3.c_str()) == NULL)
			&& (strstr(recvBuffer, str4.c_str()) == NULL)
			&& (strstr(recvBuffer, str5.c_str()) == NULL)
			&& (strstr(recvBuffer, str6.c_str()) == NULL)
			&& (strstr(recvBuffer, str7.c_str()) == NULL)
			&& (strstr(recvBuffer, str8.c_str()) == NULL))
	{
		retVal = -1;
	}
	else if(strstr(recvBuffer, ".") != NULL)
	{
		retVal = -1;
	}

	return retVal;
}

int sendTorCommand(int torControlSocket, const string& command, char* recvBuffer)
{
	fprintf(stdout, "[sendTorCommand] Command: %s\n", command.c_str());

	int res = send(torControlSocket, command.c_str(), command.size(), 0);
	if(res == -1)
	{
		return res;
	}

	memset(recvBuffer, 0, MAX_BUFFER_SIZE);
	int n = 0; // Total bytes read

	do
	{
		res = recv(torControlSocket, &recvBuffer[n], MAX_BUFFER_SIZE - n, 0);
		if(res == -1)
		{
			fprintf(stderr, "[sendTorCommand] Failed to receive response from Tor control server.\n");
			return res;
		}

		fprintf(stdout, "[sendTorCommand] Response: %s\n", recvBuffer);

		n += res;
	}while((strstr(recvBuffer, "250 OK") == NULL)
				&& (strstr(recvBuffer, "250 EXTENDED") == NULL)
				&& (strstr(recvBuffer, "250 closing connection") == NULL)
				&& (strstr(recvBuffer, "510 Unrecognized command") == NULL)
				&& (strstr(recvBuffer, "551") == NULL)
				&& (strstr(recvBuffer, "552 No such router") == NULL)
				&& (strstr(recvBuffer, "552 Unknown circuit") == NULL));

	return n;
}

void measureTPandGP()
{
	char recvBuffer[MAX_BUFFER_SIZE];
	int res;

	// Turn on "setevents stream"
	res = sendTorCommand(torControlSocket, "setevents stream\n", recvBuffer);
	if(res == -1)
	{
		fprintf(stderr, "[measureTPandGP] Failed to send command [%s] to Tor control server. Terminating process.\n", "setevents stream\n");
		exit(1);
	}

	clientSocket = createSocket(SOCK_STREAM);

	struct sockaddr_in socksServerAddress = createSocketAddress(SOCKS_SERVER_IP_ADDRESS, SOCKS_SERVER_PORT);

	res = connect(clientSocket, (struct sockaddr*)&socksServerAddress, sizeof(socksServerAddress));
	if(res == -1)
	{
		fprintf(stderr, "[measureTPandGP] Cannot connect to SOCKS server. Terminating process.\n");
		exit(1);
	}
	fprintf(stdout, "[measureTPandGP] Connected to SOCKS server.\n");

	// Perform handshake with the SOCKS server
	SocksAuthMethodRequest samReq = createSocksAuthMethodRequest(0x05, 1, SOCKS_AUTH_METHOD_NONE);
	res = send(clientSocket, (void*)&samReq, sizeof(samReq), 0);
	if(res == -1)
	{
		fprintf(stderr, "[measureTPandGP] Failed to send SOCKS authentication method request. Terminating process.\n");
		exit(1);
	}
	fprintf(stdout, "[measureTPandGP] Sent authentication method request to SOCKS server.\n");

	SocksAuthMethodResponse samRes;
	res = recv(clientSocket, (void*)&samRes, sizeof(samRes), 0);
	if(res == -1)
	{
		fprintf(stderr, "[measureTPandGP] Failed to receive SOCKS authentication method response. Terminating process.\n");
		exit(1);
	}
	else
	{
		fprintf(stdout, "[measureTPandGP] Received authentication method response from SOCKS server.\n");

		if(samRes.method == SOCKS_AUTH_METHOD_UNACCEPTABLE)
		{
			fprintf(stderr, "[measureTPandGP] SOCKS authentication method unacceptable. Terminating process.\n");
			exit(1);
		}
	}
	fprintf(stdout, "[measureTPandGP] Authentication completed with SOCKS server.\n");

	SocksConnRequest scReq = createSocksConnRequest(0x05, SOCKS_CMD_TCP_CONN, SOCKS_ADDR_TYPE_IPV4, serverIPAddress.c_str(), serverPort);
	res = send(clientSocket, (void*)&scReq, sizeof(scReq), 0);
	if(res == -1)
	{
		fprintf(stderr, "[measureTPandGP] Failed to send SOCKS connection request. Terminating process.\n");
		exit(1);
	}
	fprintf(stdout, "[measureTPandGP] Sent connection request to SOCKS server.\n");

	// Read stream ID and attach the stream to the circuit
	memset(recvBuffer, 0, MAX_BUFFER_SIZE);
	int n = 0; // Total bytes read

	do
	{
		res = recv(torControlSocket, &recvBuffer[n], MAX_BUFFER_SIZE - n, 0);
		if(res == -1)
		{
			fprintf(stderr, "[measureTPandGP] Failed to receive response from Tor control server. Terminating process.\n");
			exit(1);
		}

		fprintf(stdout, "[measureTPandGP] %s\n", recvBuffer);

		n += res;
	}while((strstr(recvBuffer, "250 OK") == NULL)
				&& (strstr(recvBuffer, "250 EXTENDED") == NULL)
				&& (strstr(recvBuffer, "250 closing connection") == NULL)
				&& (strstr(recvBuffer, "510 Unrecognized command") == NULL)
				&& (strstr(recvBuffer, "552 No such router") == NULL)
				&& (strstr(recvBuffer, "552 Unknown circuit") == NULL)
				&& (strstr(recvBuffer, "650 STREAM") == NULL));

	StringTokenizer st(recvBuffer, " \r\n");
	if(st.countTokens() < 6)
	{
		fprintf(stderr, "[measureTPandGP] Bad response from Tor control server. Failed to read stream ID. Terminating process.\n");
		exit(1);
	}
	else
	{
		st.nextToken(); // Skip the 1st token ("650")
		st.nextToken(); // Skip the 2nd token ("STREAM")
		int streamId = atoi(st.nextToken().c_str());

		// Turn off "setevents stream"
		res = sendTorCommand(torControlSocket, "setevents\n", recvBuffer);
		if(res == -1)
		{
			fprintf(stderr, "[measureTPandGP] Failed to send command [%s] to Tor control server. Terminating process.\n", "setevents\n");
			exit(1);
		}

		// Attach the stream to the circuit
		char buffer[MAX_BUFFER_SIZE];
		snprintf(buffer, MAX_BUFFER_SIZE - 1, "attachstream %d %d\n", streamId, circuitId);
		string command = buffer;
		res = sendTorCommand(torControlSocket, command, recvBuffer);
		if(res == -1)
		{
			fprintf(stderr, "[measureTPandGP] Failed to send command [%s] to Tor control server. Terminating process.\n", command.c_str());
			exit(1);
		}

		if(strstr(recvBuffer, "250 OK") == NULL)
		{
			fprintf(stderr, "[measureTPandGP] Bad response from Tor control server. Circuit is unknown. Failed to attach stream to circuit. Terminating process.\n");
			exit(1);
		}
		else
		{
			fprintf(stdout, "[measureTPandGP] Successfully attached stream %d to circuit %d.\n", streamId, circuitId);
		}
	}

	SocksConnResponse scRes;
	res = recv(clientSocket, (void*)&scRes, sizeof(scRes), 0);
	if(res == -1)
	{
		fprintf(stderr, "[measureTPandGP] Failed to receive SOCKS connection response. Terminating process.\n");
		exit(1);
	}
	else
	{
		fprintf(stdout, "[measureTPandGP] Received connection response from SOCKS server.\n");

		if(scRes.status != SOCKS_STATUS_REQUEST_GRANTED)
		{
			fprintf(stderr, "[measureTPandGP] SOCKS connection error (status = %x). Skipping this circuit. [Middleman: %s] [Exit: %s]\n", scRes.status, middlemanNodeName.c_str(), exitNodeName.c_str());

			pthread_mutex_lock(&fileMutex);
			fprintf(allDataFile, "[measureTPandGP] SOCKS connection error (status = %x). Skipping this circuit. [Middleman: %s] [Exit: %s]\n", scRes.status, middlemanNodeName.c_str(), exitNodeName.c_str());
			fflush(allDataFile);
			fprintf(tpgpFile, "[measureTPandGP] SOCKS connection error (status = %x). Skipping this circuit. [Middleman: %s] [Exit: %s]\n", scRes.status, middlemanNodeName.c_str(), exitNodeName.c_str());
			fflush(tpgpFile);
			pthread_mutex_unlock(&fileMutex);

			close(clientSocket);
			return;
		}
	}
	fprintf(stdout, "[measureTPandGP] Connection successful.\n");

	// Verify whether we are using the right circuit or not
	res = verifyTorCircuit();
	if(res != 0)
	{
		fprintf(stdout, "[measureTPandGP] Tor is not using the right circuit. Skipping this circuit. [Middleman: %s] [Exit: %s]\n", middlemanNodeName.c_str(), exitNodeName.c_str());

		pthread_mutex_lock(&fileMutex);
		fprintf(allDataFile, "[measureTPandGP] Tor is not using the right circuit. Skipping this circuit. [Middleman: %s] [Exit: %s]\n", middlemanNodeName.c_str(), exitNodeName.c_str());
		fflush(allDataFile);
		fprintf(tpgpFile, "[measureTPandGP] Tor is not using the right circuit. Skipping this circuit. [Middleman: %s] [Exit: %s]\n", middlemanNodeName.c_str(), exitNodeName.c_str());
		fflush(tpgpFile);
		pthread_mutex_unlock(&fileMutex);

		close(clientSocket);
		return;
	}
	else
	{
		fprintf(stdout, "[measureTPandGP] Tor is probably using the right circuit. [Middleman: %s] [Exit: %s]\n", middlemanNodeName.c_str(), exitNodeName.c_str());

		pthread_mutex_lock(&fileMutex);
		fprintf(allDataFile, "[measureTPandGP] Tor is probably using the right circuit. [Middleman: %s] [Exit: %s]\n", middlemanNodeName.c_str(), exitNodeName.c_str());
		fflush(allDataFile);
		fprintf(tpgpFile, "[measureTPandGP] Tor is probably using the right circuit. [Middleman: %s] [Exit: %s]\n", middlemanNodeName.c_str(), exitNodeName.c_str());
		fflush(tpgpFile);
		pthread_mutex_unlock(&fileMutex);
	}

	// Now send and recv data
	unsigned short int endHostID = htons(1);
	res = send(clientSocket, (void*)&endHostID, sizeof(endHostID), 0);
	if(res == -1)
	{
		fprintf(stderr, "[measureTPandGP] Failed to send end host ID. Skipping this circuit. [Middleman: %s] [Exit: %s]\n", middlemanNodeName.c_str(), exitNodeName.c_str());
		close(clientSocket);
		return;
	}
	fprintf(stdout, "[measureTPandGP] Sent end host ID to server.\n");

	// Get ready to measure throughput and goodput
	pcapBytesReceived = 0;
	tcpBytesReceived = 0;

	exitFlag = false;
	secCounter = 0;

	pthread_t pcapThread;
	createThread(&pcapThread, pcapThreadFunction, NULL, PTHREAD_CREATE_JOINABLE);

	pthread_t recvThread;
	createThread(&recvThread, recvThreadFunction, NULL, PTHREAD_CREATE_JOINABLE);

	usleep(500000); // Sleep for 0.5 sec to let the other threads to initialize

	double tpCumulative = 0.0;
	double gpCumulative = 0.0;

	int mCount = 0;

	// After this "send" the server will start sending data to the client
	char c = 'a';
	res = send(clientSocket, (void*)&c, sizeof(c), 0);
	if(res == -1)
	{
		fprintf(stderr, "[measureTPandGP] Failed to send client character. Skipping this circuit. [Middleman: %s] [Exit: %s]\n", middlemanNodeName.c_str(), exitNodeName.c_str());
		close(clientSocket);
		return;
	}
	fprintf(stdout, "[measureTPandGP] Sent client character to server.\n");

	while(exitFlag == false)
	{
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
			pthread_mutex_lock(&pcapMutex);
			pcapBytesReceived = 0;
			pthread_mutex_unlock(&pcapMutex);

			pthread_mutex_lock(&tcpMutex);
			tcpBytesReceived = 0;
			pthread_mutex_unlock(&tcpMutex);

			continue;
		}

		secCounter += ((unsigned int)measurementInterval - n);

		unsigned long usecInterval = (unsigned long)((measurementInterval - (unsigned int)measurementInterval) * 1000000);

		if((usecInterval == 0) && ((unsigned int)measurementInterval == 0))
		{
			usecInterval = 1;
			measurementInterval = 1.0 / 1000000.0; // Set it to 1 us
		}

		if(usecInterval != 0)
		{
			usleep(usecInterval);
			secCounter += (measurementInterval - (unsigned int)measurementInterval);
		}

		++mCount;

		pthread_mutex_lock(&pcapMutex);
		double tp = ((pcapBytesReceived / (measurementInterval - n)) * 1) / 1024; // KBps
		pcapBytesReceived = 0;
		pthread_mutex_unlock(&pcapMutex);

		tpCumulative += tp;

		pthread_mutex_lock(&tcpMutex);
		double gp = ((tcpBytesReceived / (measurementInterval - n)) * 1) / 1024; // KBps
		tcpBytesReceived = 0;
		pthread_mutex_unlock(&tcpMutex);

		gpCumulative += gp;

		fprintf(stdout, "Middleman %s Exit %s Time %f Throughput(KBps) %f Goodput(KBps) %f MiddlemanFP %s\n", middlemanNodeName.c_str(), exitNodeName.c_str(), secCounter, tp, gp, middlemanNodeFingerprint.c_str());

		pthread_mutex_lock(&fileMutex);
		if(allDataFile != NULL)
		{
			fprintf(allDataFile, "Middleman %s Exit %s Time %f Throughput(KBps) %f Goodput(KBps) %f MiddlemanFP %s\n", middlemanNodeName.c_str(), exitNodeName.c_str(), secCounter, tp, gp, middlemanNodeFingerprint.c_str());
			fflush(allDataFile);
		}
		pthread_mutex_unlock(&fileMutex);
	}

	pthread_mutex_lock(&tcpMutex);
	if(clientSocket != -1)
	{
		close(clientSocket);
		clientSocket = -1;
	}
	pthread_mutex_unlock(&tcpMutex);

	double tpAvg = tpCumulative / ((mCount > 0)?mCount:1);
	double gpAvg = gpCumulative / ((mCount > 0)?mCount:1);

	fprintf(stdout, "Middleman %s Exit %s Time %f Throughput(KBps) %f Goodput(KBps) %f MiddlemanFP %s\n", middlemanNodeName.c_str(), exitNodeName.c_str(), secCounter, tpAvg, gpAvg, middlemanNodeFingerprint.c_str());

	pthread_mutex_lock(&fileMutex);
	if(tpgpFile != NULL)
	{
		fprintf(tpgpFile, "Middleman %s Exit %s Time %f Throughput(KBps) %f Goodput(KBps) %f MiddlemanFP %s\n", middlemanNodeName.c_str(), exitNodeName.c_str(), secCounter, tpAvg, gpAvg, middlemanNodeFingerprint.c_str());
		fflush(tpgpFile);
	}
	pthread_mutex_unlock(&fileMutex);

	// Completed measurement; now clean up
	fprintf(stdout, "[measureTPandGP] Canceling pcapThread.\n");
	res = pthread_cancel(pcapThread);
	if(res != 0)
	{
		fprintf(stderr, "[measureTPandGP] Failed to cancel pcapThread.\n");
	}
	else
	{
		fprintf(stdout, "[measureTPandGP] Successfully canceled pcapThread.\n");
	}

	fprintf(stdout, "[measureTPandGP] Canceling recvThread.\n");
	res = pthread_cancel(recvThread);
	if(res != 0)
	{
		fprintf(stderr, "[measureTPandGP] Failed to cancel recvThread.\n");
	}
	else
	{
		fprintf(stdout, "[measureTPandGP] Successfully canceled recvThread.\n");
	}

	fprintf(stdout, "[measureTPandGP] Waiting for pcapThread to terminate ...\n");
	res = pthread_join(pcapThread, NULL);
	if(res != 0)
	{
		fprintf(stderr, "[measureTPandGP] Failed to join pcapThread.\n");
	}
	else
	{
		fprintf(stdout, "[measureTPandGP] Successfully joined pcapThread.\n");
	}

	fprintf(stdout, "[measureTPandGP] Waiting for recvThread to terminate ...\n");
	res = pthread_join(recvThread, NULL);
	if(res != 0)
	{
		fprintf(stderr, "[measureTPandGP] Failed to join recvThread.\n");
	}
	else
	{
		fprintf(stdout, "[measureTPandGP] Successfully joined recvThread.\n");
	}
}

void* pcapThreadFunction(void* arg)
{
	setThreadAsyncCancel();

	char* dev;						// The device to sniff on
	char errbuf[PCAP_ERRBUF_SIZE];	// Error string
	bpf_u_int32 mask;				// Our netmask
	bpf_u_int32 net;				// Our IP

	// Define the device
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL)
	{
		fprintf(stderr, "[pcapThreadFunction] Couldn't find default device: %s. Terminating process.\n", errbuf);
		exit(1);
	}

	// Find the properties for the device
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
	{
		fprintf(stderr, "[pcapThreadFunction] Couldn't get netmask for device %s: %s. Terminating process.\n", dev, errbuf);
		exit(1);
	}

	// Open the session in non-promiscuous mode
	handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "[pcapThreadFunction] Couldn't open device %s: %s. Terminating process.\n", dev, errbuf);
		exit(1);
	}

	// char filter_exp[] = "host 128.174.240.149 and src port 22";	// The filter expression
	char buffer[MAX_BUFFER_SIZE];
	snprintf(buffer, MAX_BUFFER_SIZE - 1, "%u", middlemanNodePort);

	string filter_exp = "host ";
	filter_exp += middlemanNodeIPAddress;
	filter_exp += " and src port ";
	filter_exp += buffer; // middlemanNodePort

	// Compile and apply the filter
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

	// Start packet capture
	pcap_loop(handle, -1, got_packet, NULL);

	// Close the session
	pcap_freecode(&fp);
	pcap_close(handle);

	pthread_exit(NULL);
}

void got_packet(unsigned char* args, const struct pcap_pkthdr* header, const unsigned char* packet)
{
	if((exitFlag == true) || ((duration != 0) && (secCounter >= duration)))
	{
		exitFlag = true;

		pcap_freecode(&fp);
		pcap_close(handle);

		pthread_exit(NULL);
	}
	else
	{
		Packet p(packet, header->len);

		// fprintf(stdout, "Got packet, length: %d\n", p.getPayloadLength());

		pthread_mutex_lock(&pcapMutex);
		pcapBytesReceived += p.getPayloadLength();
		pthread_mutex_unlock(&pcapMutex);
	}
}

void* recvThreadFunction(void* arg)
{
	setThreadAsyncCancel();

	char recvBuffer[MAX_BUFFER_SIZE];
	int res;

	fprintf(stdout, "[recvThreadFunction] Starting data transfer.\n");

	while(exitFlag == false)
	{
		if((duration != 0) && (secCounter >= duration))
		{
			exitFlag = true;
			break;
		}

		res = recv(clientSocket, recvBuffer, MAX_BUFFER_SIZE, 0);
		if(res == -1)
		{
			fprintf(stderr, "[recvThreadFunction] TCP recv failure. Skipping this circuit. [Middleman: %s] [Exit: %s]\n", middlemanNodeName.c_str(), exitNodeName.c_str());
			exitFlag = true;
			break;
		}
		else
		{
			pthread_mutex_lock(&tcpMutex);
			tcpBytesReceived += res;
			pthread_mutex_unlock(&tcpMutex);

			// data[res - 1] = '\0';
			// fprintf(stdout, "%s", data);
		}
	}

	fprintf(stdout, "[recvThreadFunction] Completed data transfer.\n");

	pthread_exit(NULL);
}

void signalHandler(int sig)
{
	if(torControlSocket != -1)
	{
		close(torControlSocket);
	}

	if(clientSocket != -1)
	{
		close(clientSocket);
	}

	if(allDataFile != NULL)
	{
		fclose(allDataFile);
	}

	if(tpgpFile != NULL)
	{
		fclose(tpgpFile);
	}

	exit(0);
}
