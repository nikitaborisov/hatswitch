#ifndef SOCKS_H_
#define SOCKS_H_

#include <sys/types.h>
#include <unistd.h>

#define SOCKS_AUTH_METHOD_NONE			(char)0x00
#define SOCKS_AUTH_METHOD_UNACCEPTABLE	(char)0xFF

#define SOCKS_CMD_TCP_CONN	(char)0x01
#define SOCKS_CMD_TCP_BIND	(char)0x02
#define SOCKS_CMD_UDP_PORT	(char)0x03

#define SOCKS_ADDR_TYPE_IPV4	(char)0x01
#define SOCKS_ADDR_TYPE_DNAME	(char)0x03
#define SOCKS_ADDR_TYPE_IPV6	(char)0x04

#define SOCKS_STATUS_REQUEST_GRANTED			(char)0x00
#define SOCKS_STATUS_GENERAL_FAILURE			(char)0x01
#define SOCKS_STATUS_CONN_NOT_ALLOWED			(char)0x02
#define SOCKS_STATUS_NETWORK_UNREACHABLE		(char)0x03
#define SOCKS_STATUS_HOST_UNREACHABLE			(char)0x04
#define SOCKS_STATUS_CONN_REFUSED				(char)0x05
#define SOCKS_STATUS_TTL_EXPIRED				(char)0x06
#define SOCKS_STATUS_CMD_NOT_SUPPORTED			(char)0x07
#define SOCKS_STATUS_ADDR_TYPE_NOT_SUPPORTED	(char)0x08

#pragma pack(1)

/*
The initial greeting from the client is

	* field 1: SOCKS version number (must be 0x05 for this version)
	* field 2: number of authentication methods supported, 1 byte
	* field 3: authentication methods, variable length, 1 byte per method supported
*/
struct SocksAuthMethodRequest
{
	char version;
	char methodCount;
	char method;
};

/*
The server's choice is communicated:

	* field 1: SOCKS version, 1 byte (0x05 for this version)
	* field 2: chosen authentication method, 1 byte, or 0xFF if no acceptable methods were offered
*/
struct SocksAuthMethodResponse
{
	char version;
	char method;
};

/*
The client's connection request is

	* field 1: SOCKS version number, 1 byte (must be 0x05 for this version)
	* field 2: command code, 1 byte:
		* 0x01 = establish a TCP/IP stream connection
		* 0x02 = establish a TCP/IP port binding
		* 0x03 = associate a UDP port
	* field 3: reserved, must be 0x00
	* field 4: address type, 1 byte:
		* 0x01 = IPv4 address
		* 0x03 = Domain name
		* 0x04 = IPv6 address
	* field 5: destination address of
		* 4 bytes for IPv4 address
		* 1 byte of name length followed by the name for Domain name
		* 16 bytes for IPv6 address
	* field 6: port number in a network byte order, 2 bytes
*/
struct SocksConnRequest
{
	char version;
	char command;
	char reserved;
	char addressType;
	unsigned int ipAddress;
	unsigned short int port; // in network byte order
};

/*
Server response:

	* field 1: SOCKS protocol version, 1 byte (0x05 for this version)
	* field 2: status, 1 byte:
		* 0x00 = request granted
		* 0x01 = general failure
		* 0x02 = connection not allowed by ruleset
		* 0x03 = network unreachable
		* 0x04 = host unreachable
		* 0x05 = connection refused by destination host
		* 0x06 = TTL expired
		* 0x07 = command not supported / protocol error
		* 0x08 = address type not supported
	* field 3: reserved, must be 0x00
	* field 4: address type, 1 byte:
		* 0x01 = IPv4 address
		* 0x03 = Domain name
		* 0x04 = IPv6 address
	* field 5: destination address of
		* 4 bytes for IPv4 address
		* 1 byte of name length followed by the name for Domain name
		* 16 bytes for IPv6 address
	* field 6: network byte order port number, 2 bytes
*/
struct SocksConnResponse
{
	char version;
	char status;
	char reserved;
	char addressType;
	unsigned int ipAddress;
	unsigned short int port; // in network byte order
};

#pragma pack()

SocksAuthMethodRequest createSocksAuthMethodRequest(char ver, char mc, char m);
SocksAuthMethodResponse createSocksAuthMethodResponse(char ver, char m);

SocksConnRequest createSocksConnRequest(char ver, char cmd, char addrType, const char* ipAddr, unsigned short int port);
SocksConnResponse createSocksConnResponse(char ver, char status, char addrType, const char* ipAddr, unsigned short int port);

#endif /* SOCKS_H_ */
