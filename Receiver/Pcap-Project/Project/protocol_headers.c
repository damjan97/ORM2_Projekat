#include "protocol_headers.h"

void create_packet(datagram* dat, char* data, int length, unsigned long serial_number, unsigned char* src_mac, unsigned char* dest_mac, unsigned char* src_ip, unsigned char* dest_ip)
{
	unsigned char data_checksum[22];
	/*Ethernet header*/
	for (int i = 0; i < 6; i++)
	{
		dat->eh.src_address[i] = src_mac[i];
		dat->eh.dest_address[i] = dest_mac[i];
	}
	dat->eh.type = htons(0x0800);

	/*Ip header*/
	dat->ih.header_length = 0x5;
	dat->ih.version = 0x4;
	dat->ih.tos = 0x00;
	dat->ih.length = htons(sizeof(ip_header) + sizeof(udp_header) + DATA_LEN * sizeof(char) + sizeof(unsigned long));
	dat->ih.identification = (unsigned short)0x00;
	dat->ih.fragm_flags = (unsigned short)0x00;
	dat->ih.fragm_offset = (unsigned short)0x0000;
	dat->ih.ttl = 0x40;
	dat->ih.next_protocol = 0x11;
	dat->ih.checksum = 0;
	for(int i=0; i<4; i++)
	{
		dat->ih.src_addr[i] = src_ip[i];
		dat->ih.dst_addr[i] = dest_ip[i];
	}
	memcpy(data_checksum, dat, 22);
	dat->ih.checksum = compute_ipv4_checksum(data_checksum);
	/*Udp header*/
	dat->uh.src_port = htons(27015);
	dat->uh.dest_port = htons(27015);
	dat->uh.datagram_length = htons(sizeof(udp_header) + DATA_LEN * sizeof(char) + sizeof(unsigned long));
	dat->uh.checksum = 0;
	dat->uh.checksum = compute_udp_checksum(&(dat->uh), &(dat->ih), dat->data, dat->serial_number);
	/*Data*/
	memcpy(&(dat->data), data, length);
	dat->serial_number = serial_number;
}

void create_first_packet(first_datagram* dat, unsigned int number_of_packets, unsigned int data_len, unsigned int last_packet_data_len, unsigned char* src_mac, unsigned char* dest_mac, unsigned char* src_ip, unsigned char* dest_ip)
{
	unsigned char data_checksum[22];
	/*Ethernet header*/
	for (int i = 0; i < 6; i++)
	{
		dat->eh.src_address[i] = src_mac[i];
		dat->eh.dest_address[i] = dest_mac[i];
	}
	dat->eh.type = htons(0x0800);

	/*Ip header*/
	dat->ih.header_length = 0x5;
	dat->ih.version = 0x4;
	dat->ih.tos = 0x00;
	dat->ih.length = htons(sizeof(ip_header) + sizeof(udp_header) + 3 * sizeof(unsigned int));
	dat->ih.identification = (unsigned short)0x00;
	dat->ih.fragm_flags = (unsigned short)0x00;
	dat->ih.fragm_offset = (unsigned short)0x0000;
	dat->ih.ttl = 0x40;
	dat->ih.next_protocol = 0x11;
	dat->ih.checksum = 0;
	for (int i = 0; i<4; i++)
	{
		dat->ih.src_addr[i] = src_ip[i];
		dat->ih.dst_addr[i] = dest_ip[i];
	}
	memcpy(data_checksum, dat + sizeof(ethernet_header), 22);
	dat->ih.checksum = compute_ipv4_checksum(data_checksum);
	/*Udp header*/
	dat->uh.src_port = htons(27015);
	dat->uh.dest_port = htons(27015);
	dat->uh.datagram_length = htons(sizeof(udp_header) + 3 * sizeof(unsigned int));
	dat->uh.checksum = 0;
	dat->uh.checksum = compute_udp_checksum_for_first_packet(&(dat->uh), &(dat->ih), number_of_packets, data_len, last_packet_data_len);
	dat->number_of_packets = htonl(number_of_packets);
	dat->data_len = htonl(data_len);
	dat->last_packet_data_len = htonl(last_packet_data_len);
}

unsigned short compute_ipv4_checksum(unsigned char *data_checksum) {
	unsigned short checksum = 0;
	for (int i = 0; i < 22; i += 2)
	{
		unsigned short Tmp = BytesTo16(data_checksum[i], data_checksum[i + 1]);
		unsigned short difference = 65535 - checksum;
		checksum += Tmp;
		if (Tmp > difference) 
		{
			checksum += 1;
		}
	}
	checksum = ~checksum;
	return htons(checksum);
}

unsigned short compute_udp_checksum(udp_header* udp, ip_header* ip, char* data, unsigned long serial_number) {
	unsigned short checksum = 0;

	//length of pseudo_header = Data length + 8 bytes UDP header + Two 4 byte IP's + 1 byte protocol
	unsigned short pseudo_length = DATA_LEN * sizeof(char) + sizeof(unsigned long) + 17;

	//If bytes are not an even number, add an extra.
	pseudo_length += pseudo_length % 2;

	// This is just UDP + Data length.
	unsigned short length = DATA_LEN * sizeof(char) + sizeof(unsigned long) + 8;

	//Init
	unsigned char* pseudo_header = (unsigned char*)malloc(pseudo_length * sizeof(unsigned char));
	for (int i = 0; i < pseudo_length; i++) {
		pseudo_header[i] = 0x00;
	}

	// Protocol
	memcpy(pseudo_header, &(ip->next_protocol), 1);

	// Source and Dest IP
	memcpy(pseudo_header + 1, &(ip->src_addr), 4);
	memcpy(pseudo_header + 5, &(ip->dst_addr), 4);

	// length is not network byte order yet
	length = htons(length);

	//Included twice
	memcpy(pseudo_header + 9, (void*)&length, 2);
	memcpy(pseudo_header + 11, (void*)&length, 2);

	//Source Port
	memcpy(pseudo_header + 13, &(udp->src_port), 2);

	unsigned long sn = htonl(serial_number);

	//Dest Port
	memcpy(pseudo_header + 15, &(udp->dest_port), 2);
	memcpy(pseudo_header + 17, data, DATA_LEN);
	memcpy(pseudo_header + 17 + DATA_LEN, (void*)&sn, sizeof(unsigned long));


	for (int i = 0; i < pseudo_length; i += 2)
	{
		unsigned short tmp = BytesTo16(pseudo_header[i], pseudo_header[i + 1]);
		unsigned short difference = 65535 - checksum;
		checksum += tmp;
		if (tmp > difference) { checksum += 1; }
	}
	checksum = ~checksum; //One's complement

	pseudo_header = NULL;
	free(pseudo_header);

	return checksum;
}

unsigned short compute_udp_checksum_for_first_packet(udp_header* udp, ip_header* ip, unsigned int number_of_packets, unsigned int data_len, unsigned int last_packet_data_len)
{
	unsigned short checksum = 0;

	//length of pseudo_header = Data length + 8 bytes UDP header + Two 4 byte IP's + 1 byte protocol
	unsigned short pseudo_length = 3 * sizeof(unsigned int) + 17;

	//If bytes are not an even number, add an extra.
	pseudo_length += pseudo_length % 2;

	// This is just UDP + Data length.
	unsigned short length = 3 * sizeof(unsigned int) + 8;

	//Init
	unsigned char* pseudo_header = (unsigned char*)malloc(pseudo_length * sizeof(unsigned char));
	for (int i = 0; i < pseudo_length; i++) {
		pseudo_header[i] = 0x00;
	}

	// Protocol
	memcpy(pseudo_header, &(ip->next_protocol), 1);

	// Source and Dest IP
	memcpy(pseudo_header + 1, &(ip->src_addr), 4);
	memcpy(pseudo_header + 5, &(ip->dst_addr), 4);

	// length is not network byte order yet
	length = htons(length);

	//Included twice
	memcpy(pseudo_header + 9, (void*)&length, 2);
	memcpy(pseudo_header + 11, (void*)&length, 2);

	//Source Port
	memcpy(pseudo_header + 13, &(udp->src_port), 2);

	unsigned int nop = htonl(number_of_packets);
	unsigned int dl = htonl(data_len);
	unsigned int lpdl = htonl(last_packet_data_len);

	//Dest Port
	memcpy(pseudo_header + 15, &(udp->dest_port), 2);
	memcpy(pseudo_header + 17, (void*)&nop, sizeof(unsigned int));
	memcpy(pseudo_header + 17 + sizeof(unsigned int), (void*)&dl, sizeof(unsigned int));
	memcpy(pseudo_header + 17 + sizeof(unsigned int) + sizeof(unsigned int), (void*)&lpdl, sizeof(unsigned int));


	for (int i = 0; i < pseudo_length; i += 2)
	{
		unsigned short tmp = BytesTo16(pseudo_header[i], pseudo_header[i + 1]);
		unsigned short difference = 65535 - checksum;
		checksum += tmp;
		if (tmp > difference) { checksum += 1; }
	}
	checksum = ~checksum; //One's complement

	pseudo_header = NULL;
	free(pseudo_header);

	return checksum;
}

unsigned short BytesTo16(unsigned char X, unsigned char Y) {
	unsigned short Tmp = X;
	Tmp = Tmp << 8;
	Tmp = Tmp | Y;
	return Tmp;
}

void print_raw_data(unsigned char* data, int data_length)
{
	int i;
	printf("\n-------------------------------------------------------------\n\t");
	for (i = 0; i < data_length; i = i + 1)
	{
		printf("%.2x ", ((unsigned char*)data)[i]);

		// 16 bytes per line
		if ((i + 1) % 16 == 0)
			printf("\n\t");
	}
	printf("\n-------------------------------------------------------------");
}

void print_message(char* data, int data_length)
{
	int i;
	printf("\n-------------------------------------------------------------\n");
	for (i = 0; i < data_length; i = i + 1)
	{
		printf("%c", ((unsigned char*)data)[i]);
	}
	printf("\n-------------------------------------------------------------");
}

void print_ethernet_header(ethernet_header * eh)
{
	printf("\n=============================================================");
	printf("\n\tDATA LINK LAYER  -  Ethernet");

	print_raw_data((unsigned char*)eh, 14);

	printf("\n\tDestination address:\t%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", eh->dest_address[0], eh->dest_address[1], eh->dest_address[2], eh->dest_address[3], eh->dest_address[4], eh->dest_address[5]);
	printf("\n\tSource address:\t\t%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", eh->src_address[0], eh->src_address[1], eh->src_address[2], eh->src_address[3], eh->src_address[4], eh->src_address[5]);
	printf("\n\tNext protocol:\t\t0x%.4x", ntohs(eh->type));

	printf("\n=============================================================");

	return;
}

void print_ip_header(ip_header * ih)
{
	printf("\n=============================================================");
	printf("\n\tNETWORK LAYER  -  Internet Protocol (IP)");

	print_raw_data((unsigned char*)ih, ih->header_length * 4);

	printf("\n\tVersion:\t\t%u", ih->version);
	printf("\n\tHeader Length:\t\t%u", ih->header_length * 4);
	printf("\n\tType of Service:\t%u", ih->tos);
	printf("\n\tTotal length:\t\t%u", ntohs(ih->length));
	printf("\n\tIdentification:\t\t%u", ntohs(ih->identification));
	printf("\n\tFlags:\t\t\t%u", ntohs(ih->fragm_flags));
	printf("\n\tFragment offset:\t%u", ntohs(ih->fragm_offset));
	printf("\n\tTime-To-Live:\t\t%u", ih->ttl);
	printf("\n\tNext protocol:\t\t%u", ih->next_protocol);
	printf("\n\tHeader checkSum:\t%u", ntohs(ih->checksum));
	printf("\n\tSource:\t\t\t%u.%u.%u.%u", ih->src_addr[0], ih->src_addr[1], ih->src_addr[2], ih->src_addr[3]);
	printf("\n\tDestination:\t\t%u.%u.%u.%u", ih->dst_addr[0], ih->dst_addr[1], ih->dst_addr[2], ih->dst_addr[3]);

	printf("\n=============================================================");

	return;
}

void print_udp_header(udp_header* uh)
{
	printf("\n=============================================================");
	printf("\n\tTRANSPORT LAYER  -  UDP Protocol");

	print_raw_data((unsigned char*)uh, ntohs(uh->datagram_length));

	printf("\n\tSrc_port:\t\t%u", ntohs(uh->src_port));
	printf("\n\tDest_port:\t\t%u", ntohs(uh->dest_port));
	printf("\n\tDatagram_length:\t\t%u", ntohs(uh->datagram_length));
	printf("\n\tChecksum:\t\t%u", ntohs(uh->checksum));
	printf("\n=============================================================");

	return;
}

void print_application_data(unsigned char* data, long data_length)
{
	printf("\n=============================================================");
	printf("\n\tAPPLICATION LAYER");

	print_message(data, data_length);

	printf("\n=============================================================");

}

void print_datagram(datagram dat, unsigned int message_length)
{
	print_ethernet_header(&(dat.eh));
	print_ip_header(&(dat.ih));
	print_udp_header(&(dat.uh));
	print_application_data(dat.data, message_length);
	printf("\n=============================================================");
	printf("\tSerial number:\t%lu\n", dat.serial_number);
}
