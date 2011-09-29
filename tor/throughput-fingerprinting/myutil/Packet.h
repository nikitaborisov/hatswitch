#ifndef PACKET_H_
#define PACKET_H_

#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Ethernet addresses are 6 bytes */
#define ETHERNET_ADDR_LEN	6

/* Ethernet header */
struct hdr_ethernet
{
	u_char ether_dhost[ETHERNET_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHERNET_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc. */
};

#define ETHERNET_HEADER_LEN 14

/* IP header */
struct hdr_ip
{
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src, ip_dst; /* source and destination address */
};

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
struct hdr_tcp
{
	u_short tcp_sport;	/* source port */
	u_short tcp_dport;	/* destination port */
	u_int tcp_seq;		/* sequence number */
	u_int tcp_ack;		/* acknowledgement number */
	u_char tcp_off_rsvd;	/* data offset, rsvd */
#define TCP_OFF(th)	(((th)->tcp_off_rsvd & 0xf0) >> 4)
	u_char tcp_flags;
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PUSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_ECE 0x40
#define TCP_CWR 0x80
#define TCP_FLAGS (TCP_FIN | TCP_SYN | TCP_RST | TCP_PUSH | TCP_ACK | TCP_URG | TCP_ECE | TCP_CWR)
	u_short tcp_win;		/* window */
	u_short tcp_sum;		/* checksum */
	u_short tcp_urp;		/* urgent pointer */
};

class Packet
{
private:
	unsigned char* packet;
	int length;

	int ethernetHeaderLength;
	int ipHeaderLength;
	int tcpHeaderLength;
	unsigned char *payload;

public:
	Packet(const unsigned char* p, int l);
	~Packet();
	int getLength() const;
	int getEthernetHeaderLength() const;
	int getIPHeaderLength() const;
	int getTCPHeaderLength() const;
	int getPayloadLength() const;
	unsigned char* getPayload() const; // unsafe
};

#endif /* PACKET_H_ */
