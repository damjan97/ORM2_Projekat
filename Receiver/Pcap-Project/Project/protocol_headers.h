#include "stdio.h"
#include "stdlib.h"
#include "pcap.h"

#define DATA_LEN 768

/* PROTOCOL HEADERS */

// Ethernet header
typedef struct ethernet_header{
	unsigned char dest_address[6];		// Destination address
	unsigned char src_address[6];		// Source address
	unsigned short type;				// Type of the next layer
}ethernet_header;

// IPv4 header
typedef struct ip_header{
	unsigned char header_length :4;	// Internet header length (4 bits)
	unsigned char version :4;		// Version (4 bits)
	unsigned char tos;				// Type of service 
	unsigned short length;			// Total length 
	unsigned short identification;	// Identification
	unsigned short fragm_flags :3;  // Flags (3 bits) & Fragment offset (13 bits)
    unsigned short fragm_offset :13;// Flags (3 bits) & Fragment offset (13 bits)
	unsigned char ttl;				// Time to live
	unsigned char next_protocol;	// Protocol of the next layer
	unsigned short checksum;		// Header checksum
	unsigned char src_addr[4];		// Source address
	unsigned char dst_addr[4];		// Destination address
	unsigned int options_padding;	// Option + Padding
		// + variable part of the header
}ip_header;

//UDP header
typedef struct udp_header{
	unsigned short src_port;		// Source port
	unsigned short dest_port;		// Destination port
	unsigned short datagram_length;	// Length of datagram including UDP header and data
	unsigned short checksum;		// Header checksum
}udp_header;

// TCP header
typedef struct tcp_header {
	unsigned short src_port;			// Source port
	unsigned short dest_port;			// Destination port
	unsigned int sequence_num;			// Sequence Number
	unsigned int ack_num;				// Acknowledgement number
	unsigned char reserved :4;			// Reserved for future use (4 bits) 
	unsigned char header_length :4;		// Header length (4 bits)
	unsigned char flags;				// Packet flags
	unsigned short windows_size;		// Window size
	unsigned short checksum;			// Header Checksum
	unsigned short urgent_pointer;		// Urgent pointer
	// + variable part of the header
} tcp_header;

typedef struct datagram {
	ethernet_header eh;
	ip_header ih;
	udp_header uh;
	char data[DATA_LEN];
	unsigned long  serial_number;
}datagram;

typedef struct first_datagram {
	ethernet_header eh;
	ip_header ih;
	udp_header uh;
	unsigned int number_of_packets;
	unsigned int data_len;
	unsigned int last_packet_data_len;
}first_datagram;

void create_packet(datagram* dat, char* data, int length, unsigned long serial_number, unsigned char* src_mac, unsigned char* dest_mac, unsigned char* src_ip, unsigned char* dest_ip);
void create_first_packet(first_datagram* dat, unsigned int number_of_packets, unsigned int data_len, unsigned int last_packet_data_len, unsigned char* src_mac, unsigned char* dest_mac, unsigned char* src_ip, unsigned char* dest_ip);
unsigned short compute_ipv4_checksum(unsigned char* data_checksum);
unsigned short compute_udp_checksum(udp_header* udp, ip_header* ip, char* data, unsigned long serial_number);
unsigned short compute_udp_checksum_for_first_packet(udp_header* udp, ip_header* ip, unsigned int number_of_packets, unsigned int data_len, unsigned int last_packet_data_len);
unsigned short BytesTo16(unsigned char X, unsigned char Y);
void print_raw_data(unsigned char* data, int data_length);
void print_message(char* data, int data_length);
void print_ethernet_header(ethernet_header * eh);
void print_ip_header(ip_header * ih);
void print_udp_header(udp_header* uh);
void print_application_data(unsigned char* data, long data_length);
void print_datagram(datagram dat, unsigned int message_length);
