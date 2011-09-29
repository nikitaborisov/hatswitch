#ifndef NET_H_
#define NET_H_

#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct sockaddr_in createSocketAddress(const char* ipAddress, unsigned short port);

int createSocket(int socketType);
int bindSocket(int sockfd, const char* ipAddress, unsigned short port);
int listenSocket(int sockfd, int backlog);

char* getIPAddress(const sockaddr_in& addr_in);
char* getIPAddress(unsigned long int ipAddress);

#endif /* NET_H_ */
