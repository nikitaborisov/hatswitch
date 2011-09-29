#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "socks.h"

SocksAuthMethodRequest createSocksAuthMethodRequest(char ver, char mc, char m)
{
	SocksAuthMethodRequest req;
	req.version = ver;
	req.methodCount = mc;
	req.method = m;

	return req;
}

SocksAuthMethodResponse createSocksAuthMethodResponse(char ver, char m)
{
	SocksAuthMethodResponse res;
	res.version = ver;
	res.method = m;

	return res;
}

SocksConnRequest createSocksConnRequest(char ver, char cmd, char addrType, const char* ipAddr, unsigned short int port)
{
	SocksConnRequest req;
	req.version = ver;
	req.command = cmd;
	req.addressType = addrType;
	req.ipAddress = (unsigned int)inet_addr(ipAddr);
	req.port = htons(port);

	return req;
}

SocksConnResponse createSocksConnResponse(char ver, char status, char addrType, const char* ipAddr, unsigned short int port)
{
	SocksConnResponse res;
	res.version = ver;
	res.status = status;
	res.addressType = addrType;
	res.ipAddress = (unsigned int)inet_addr(ipAddr);
	res.port = htons(port);

	return res;
}
