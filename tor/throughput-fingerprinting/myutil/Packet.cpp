#include <sys/types.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "Packet.h"

using namespace std;

Packet::Packet(const unsigned char* p, int l)
{
	this->length = l;
	this->packet = new unsigned char[this->length];
	if(this->packet == NULL)
	{
		fprintf(stderr, "[Packet::Packet] Memory allocation error. Terminating process.\n");
		exit(1);
	}

	memcpy(this->packet, p, this->length);

	this->ethernetHeaderLength = ETHERNET_HEADER_LEN;

	struct hdr_ethernet* eth;
	struct hdr_ip* ip;
	struct hdr_tcp* tcp;

	eth = (struct hdr_ethernet*)(this->packet);

	ip = (struct hdr_ip*)(this->packet + this->ethernetHeaderLength);
	this->ipHeaderLength = IP_HL(ip) * 4;
	if (this->ipHeaderLength < 20)
	{
		fprintf(stderr, "Invalid IP header length: %d bytes. Termination process.\n", this->ipHeaderLength);
		exit(1);
	}

	tcp = (struct hdr_tcp*)(this->packet + this->ethernetHeaderLength + this->ipHeaderLength);
	this->tcpHeaderLength = TCP_OFF(tcp) * 4;
	if (this->tcpHeaderLength < 20)
	{
		fprintf(stderr, "Invalid TCP header length: %d bytes. Termination process.\n", this->tcpHeaderLength);
		exit(1);
	}

	this->payload = (unsigned char*)(this->packet + this->ethernetHeaderLength + this->ipHeaderLength + this->tcpHeaderLength);
}

Packet::~Packet()
{
	if(this->packet != NULL)
	{
		delete [] this->packet;
	}
}

int Packet::getLength() const
{
	return this->length;
}

int Packet::getEthernetHeaderLength() const
{
	return this->ethernetHeaderLength;
}

int Packet::getIPHeaderLength() const
{
	return this->ipHeaderLength;
}

int Packet::getTCPHeaderLength() const
{
	return this->tcpHeaderLength;
}

int Packet::getPayloadLength() const
{
	return (this->length - this->ethernetHeaderLength - this->ipHeaderLength - this->tcpHeaderLength);
}

unsigned char* Packet::getPayload() const
{
	return this->payload;
}
