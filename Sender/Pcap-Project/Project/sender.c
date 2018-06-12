// ================================================================
// Katedra: Katedra za racunarsku tehniku i racunarske komunikacije
// Predmet: Osnovi racunarskih mreza 2
// Godina studija: III godina
// Semestar: Letnji (VI)
// Skolska godina: 2017/2018
// Datoteka: sender.c
// Autori:   Damjan Glamocic  RA65/2015
//           Mihailo Markovic RA191/2015
// ================================================================

// Include libraries
// We do not want the warnings about the old deprecated and unsecure CRT functions since these examples can be compiled under *nix as well
#ifdef _MSC_VER
	#define _CRT_SECURE_NO_WARNINGS
	#define HAVE_STRUCT_TIMESPEC
#else
#include <netinet/in.h>
#include <time.h>
#endif

#include <pcap.h>
#include "protocol_headers.h"
#include <stdio.h>
#include <string.h>
#include <pthread.h>


pcap_if_t* select_device(pcap_if_t* devices);
void packet_handler_ethernet(unsigned char* param, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data);
void packet_handler_wifi(unsigned char* param, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data);
unsigned long read_from_file(char* file_name);
void write_to_file(char* file_name);
void create_datagrams(unsigned long length);
void* ethernet_handler(void* params);
void* wifi_handler(void* params);

unsigned int last_message_length;
unsigned int packets_number;
unsigned int eth_received = 0;
unsigned int wifi_received = 0;
int number_of_sent_packets = 0;
char* data;
char received_ack_ethernet[4];
char received_ack_wifi[4];
char line[DATA_LEN];
unsigned char eth_packet[sizeof(datagram)];
unsigned char wifi_packet[sizeof(datagram)];
unsigned char first_packet[sizeof(first_datagram)];
first_datagram first_dat;
datagram* datagrams;
pthread_mutex_t mutex_eth;
pthread_mutex_t mutex_wifi;
pcap_t* eth_handle;
pcap_t* wifi_handle;
int broken_counter = 0;
int ethernet_sent_packets = 0;
int wifi_sent_packets = 0;
int ethernet_broken = 0;
int ethernet_broken_at_packet = 0;
float ethernet_time;
float wifi_time;

unsigned char src_mac_eth[6] = { 0x28, 0xd2, 0x44, 0x2e, 0xd0, 0xb4 };
unsigned char dest_mac_eth[6] = { 0x2c, 0x60, 0x0c, 0x9c, 0x37, 0xcd };
unsigned char src_ip_eth[4] = { 192, 168, 1, 4 };
unsigned char dest_ip_eth[4] = { 192, 168, 1, 5 };

unsigned char src_mac_wifi[6] = { 0x00, 0x0f, 0x60, 0x05, 0x1c, 0xf1 };
unsigned char dest_mac_wifi[6] = { 0x00, 0x0f, 0x60, 0x05, 0xaf, 0xd4 };
unsigned char src_ip_wifi[4] = { 192, 168, 1, 7 };
unsigned char dest_ip_wifi[4] = { 192, 168, 1, 8 };

int main()
{
	pcap_if_t* devices;
	pcap_if_t* eth_device;
	pcap_if_t* wifi_device;

	char* filter_exp_eth = "udp port 27015 and ip dst 192.168.1.4";
	char* filter_exp_wifi = "udp port 27015 and ip dst 192.168.1.7";
	struct bpf_program fcode_eth, fcode_wifi;
	unsigned int netmask_wifi, netmask_eth;
	char error_buffer [PCAP_ERRBUF_SIZE];
	unsigned long length;

	pthread_t thread_ethernet;
	pthread_t thread_wifi;

	pthread_mutex_init(&mutex_eth, NULL);
	pthread_mutex_init(&mutex_wifi, NULL);

	length = read_from_file("na_drini_cuprija.txt");
	write_to_file("output.txt");

	printf("Length: %lu\n", length);
	
	create_datagrams(length);

	//Retrieve the device list on the local machine 
	if (pcap_findalldevs(&devices, error_buffer) == -1)
	{
		printf("Error in pcap_findalldevs: %s\n", error_buffer);
		return -1;
	}

	/* Selecting ethernet interface */
	printf("Choose ETHERNET interface...\n");
	printf("----------------------------\n");
	eth_device = select_device(devices);
	if (eth_device == NULL)
	{
		pcap_freealldevs(devices);
		return -1;
	}

	/* Selecting wifi interface */
	printf("\nChoose WIFI interface...\n");
	printf("----------------------------\n");
	wifi_device = select_device(devices);
	if (wifi_device == NULL)
	{
		pcap_freealldevs(devices);
		return -1;
	}

	/* Open ethernet adapter (10ms timeout) */
	if ((eth_handle = pcap_open_live(eth_device->name, 65536, 0, 100, error_buffer)) == NULL)
	{
		printf("\n Unable to open adapter %s.\n", eth_device->name);
		return -1;
	}

	/* Open wifi adapter (10ms timeout) */
	if ((wifi_handle = pcap_open_live(wifi_device->name, 65536, 0, 100, error_buffer)) == NULL)
	{
		printf("\n Unable to open adapter %s.\n", wifi_device->name);
		return -1;
	}

	/* Check the protocol type of link layer. We only support Ethernet for simplicity */
	if (pcap_datalink(eth_handle) != DLT_EN10MB || pcap_datalink(wifi_handle) != DLT_EN10MB) // DLT_EN10MB -> Ethernet
	{
		printf("\nThis program works only on Ethernet networks...\n");
		pcap_freealldevs(devices);
		return -1;
	}

#ifdef _WIN32
	if (eth_device->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask_eth = ((struct sockaddr_in *)(eth_device->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask_eth = 0xffffff;
#else
	if (!eth_device->addresses->netmask)
		netmask = 0;
	else
		netmask = ((struct sockaddr_in *)(eth_device->addresses->netmask))->sin_addr.s_addr;
#endif

#ifdef _WIN32
	if (wifi_device->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask_wifi = ((struct sockaddr_in *)(wifi_device->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask_wifi = 0xffffff;
#else
	if (!wifi_device->addresses->netmask)
		netmask = 0;
	else
		netmask = ((struct sockaddr_in *)(wifi_device->addresses->netmask))->sin_addr.s_addr;
#endif

	if (pcap_compile(eth_handle, &fcode_eth, filter_exp_eth, 1, netmask_eth) < 0)
	{
		printf("\n Unable to compile the packet filter. Check the syntax.\n");
		return -1;
	}

	if (pcap_compile(wifi_handle, &fcode_wifi, filter_exp_wifi, 1, netmask_wifi) < 0)
	{
		printf("\n Unable to compile the packet filter. Check the syntax.\n");
		return -1;
	}

	if (pcap_setfilter(eth_handle, &fcode_eth) < 0)
	{
		printf("\n Error setting the filter.\n");
		return -1;
	}

	if (pcap_setfilter(wifi_handle, &fcode_wifi) < 0)
	{
		printf("\n Error setting the filter.\n");
		return -1;
	}
	
	create_first_packet(&first_dat, packets_number, DATA_LEN, last_message_length, src_mac_eth, dest_mac_eth, src_ip_eth, dest_ip_eth);

	memcpy(first_packet, &(first_dat.eh), sizeof(ethernet_header));
	memcpy(first_packet + sizeof(ethernet_header), &(first_dat.ih), sizeof(ip_header));
	memcpy(first_packet + sizeof(ethernet_header) + sizeof(ip_header) - 4, &(first_dat.uh), sizeof(udp_header));
	memcpy(first_packet + sizeof(ethernet_header) + sizeof(ip_header) - 4 + sizeof(udp_header), &(first_dat.number_of_packets), 3 * sizeof(unsigned int));

	if (pcap_sendpacket(eth_handle, first_packet, sizeof(first_datagram)) != 0) {
		printf("Error sending first_packet\n");
	}
	else {
		printf("Success sending first_packet\n");
	}

	pcap_loop(eth_handle, 1, packet_handler_ethernet, NULL);
	printf("Received: %d\n", eth_received);

	printf("Number of packets: %d\n", packets_number);
	printf("Size of last message:%d\n", last_message_length);

	pthread_create(&thread_ethernet, NULL, ethernet_handler, NULL);
	pthread_create(&thread_wifi, NULL, wifi_handler, NULL);

	pthread_join(thread_ethernet, NULL);
	pthread_join(thread_wifi, NULL);
	
	printf("\n\nVrijeme slanja preko etherneta: %.4f\n", ethernet_time);
	printf("Vrijeme slanja po broju paketa preko etherneta: %.8f\n", ethernet_time / ethernet_sent_packets);
	printf("\nVrijeme slanja preko wifi: %.4f\n", wifi_time);
	printf("Vrijeme slanja po broju paketa preko wifi: %.8f\n", wifi_time / wifi_sent_packets);

	/*Free resources*/
	free(data);
	free(datagrams);

	/*Close adapters*/
	pcap_close(eth_handle);
	pcap_close(wifi_handle);
		
	return 0;
}

pcap_if_t* select_device(pcap_if_t* devices)
{
	int device_number;
	int i = 0;			// Count devices and provide jumping to the selected device 
	pcap_if_t* device;

	// Print the list
	for (device = devices; device; device = device->next)
	{
		printf("%d. %s", ++i, device->name);
		if (device->description)
			printf(" (%s)\n", device->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return NULL;
	}

	// Pick one device from the list
	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &device_number);

	if (device_number < 1 || device_number > i)
	{
		printf("\nInterface number out of range.\n");
		return NULL;
	}

	// Jump to the selected device
	for (device = devices, i = 0; i< device_number - 1; device = device->next, i++);

	return device;
}

// Callback function invoked by libpcap/WinPcap for every incoming packet
void packet_handler_ethernet(unsigned char* param, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{
	pthread_mutex_lock(&mutex_eth);
	// Retrieve position of ethernet_header
	ethernet_header* eh;
    eh = (ethernet_header*)packet_data;

	// Check the type of next protocol in packet
	if (ntohs(eh->type) == 0x800)	// Ipv4
	{
		ip_header* ih;
        ih = (ip_header*)(packet_data + sizeof(ethernet_header));

		if(ih->next_protocol == 17) // UDP
		{
			memcpy(received_ack_ethernet, packet_data + sizeof(ethernet_header) + sizeof(ip_header) - 4 + sizeof(udp_header), 3 * sizeof(char));
			if (strcmp(received_ack_ethernet, "Yes") == 0) {
				eth_received = 1;
			}
			else
			{
				eth_received = 0;
			}
		}
	}
	pthread_mutex_unlock(&mutex_eth);
}

// Callback function invoked by libpcap/WinPcap for every incoming packet
void packet_handler_wifi(unsigned char* param, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{
	pthread_mutex_lock(&mutex_wifi);
	// Retrieve position of ethernet_header
	ethernet_header* eh;
	eh = (ethernet_header*)packet_data;

	// Check the type of next protocol in packet
	if (ntohs(eh->type) == 0x800)	// Ipv4
	{
		ip_header* ih;
		ih = (ip_header*)(packet_data + sizeof(ethernet_header));

		if (ih->next_protocol == 17) // UDP
		{
			memcpy(received_ack_wifi, packet_data + sizeof(ethernet_header) + sizeof(ip_header) - 4 + sizeof(udp_header), 3 * sizeof(char));
			if (strcmp(received_ack_wifi, "Yes") == 0) {
				wifi_received = 1;
			}
			else
			{
				wifi_received = 0;
			}
		}
	}
	pthread_mutex_unlock(&mutex_wifi);
}

unsigned long read_from_file(char* file_name)
{
	FILE *fin = fopen(file_name, "r");
	if (fin == NULL)
	{
		printf("Cannot open file!");
		exit(-1);
	}
	fseek(fin, 0, SEEK_END);
	unsigned long length = ftell(fin);
	data = (char*)malloc(length * sizeof(char));
	rewind(fin);
	strcpy(data, "");
	while (fgets(line, DATA_LEN, fin) != NULL)
	{
		strcat(data, line);
	}
	fclose(fin);
	return (unsigned long)strlen(data);
}

void write_to_file(char* file_name)
{
	FILE *fout = fopen(file_name, "w");
	if (fout == NULL)
	{
		printf("Cannot open file!");
		exit(-1);
	}
	fprintf(fout, "%s", data);
	fclose(fout);
}

void create_datagrams(unsigned long length)
{
	packets_number = length / DATA_LEN + 1;
	last_message_length = length % DATA_LEN;
	unsigned long serial_number = 1;
	datagrams = (datagram*)malloc(packets_number * sizeof(datagram));

	/*Copy data into datagrams for ethernet*/
	for (int i = 0; i < packets_number / 2; i++)
	{
		create_packet(&(datagrams[i]), &data[i*DATA_LEN], DATA_LEN, serial_number, src_mac_eth, dest_mac_eth, src_ip_eth, dest_ip_eth);
		serial_number++;
	}

	/*Copy data into datagrams for wifi*/
	for (int i = packets_number / 2; i < packets_number - 1; i++)
	{
		create_packet(&(datagrams[i]), &data[i*DATA_LEN], DATA_LEN, serial_number, src_mac_wifi, dest_mac_wifi, src_ip_wifi, dest_ip_wifi);
		serial_number++;
	}

	/*Copy remainder*/
	create_packet(&(datagrams[packets_number - 1]), &data[(packets_number - 1) * DATA_LEN], last_message_length, serial_number, src_mac_wifi, dest_mac_wifi, src_ip_wifi, dest_ip_wifi);

}

void* ethernet_handler(void* params)
{
	clock_t start = clock();
	pthread_mutex_lock(&mutex_eth);
	int i = 0;
	broken_counter = 0;
	while (i < packets_number / 2)
	{
		memcpy(eth_packet, &(datagrams[i].eh), sizeof(ethernet_header));
		memcpy(eth_packet + sizeof(ethernet_header), &(datagrams[i].ih), sizeof(ip_header));
		memcpy(eth_packet + sizeof(ethernet_header) + sizeof(ip_header) - 4, &(datagrams[i].uh), sizeof(udp_header));
		memcpy(eth_packet + sizeof(ethernet_header) + sizeof(ip_header) - 4 + sizeof(udp_header), &(datagrams[i].data), DATA_LEN + sizeof(unsigned long));

		if (pcap_sendpacket(eth_handle, eth_packet, sizeof(datagram)) != 0) {
			printf("Error sending packet: %lu over ethernet\n", ntohl(datagrams[i].serial_number));
		}
		else {
			printf("Success sending packet: %lu over ethernet\n", ntohl(datagrams[i].serial_number));
		}

		pthread_mutex_unlock(&mutex_eth);

		pcap_dispatch(eth_handle, 1, packet_handler_ethernet, NULL);

		pthread_mutex_lock(&mutex_eth);

		if (eth_received == 1)
		{
			printf("Success receiving packet: %lu over ethernet! Go for next packet\n", ntohl(datagrams[i].serial_number));
			i++;
			eth_received = 0;
			broken_counter = 0;
			ethernet_sent_packets++;
		}
		else
		{
			broken_counter++;
			printf("Error sending packet: %lu over ethernet! Try again this packet\n", ntohl(datagrams[i].serial_number));
		}
		if (broken_counter >= 50)
		{
			printf("Ethernet disconected!\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
			ethernet_broken = 1;
			ethernet_broken_at_packet = i;
			pthread_mutex_unlock(&mutex_eth);
			break;
		}
		printf("\t\t\tBroken counter: %d\n", broken_counter);
		pthread_mutex_unlock(&mutex_eth);
	}
	pthread_mutex_lock(&mutex_eth);
	pthread_mutex_unlock(&mutex_eth);
	clock_t end = clock();
	ethernet_time = (float)(end - start) / CLOCKS_PER_SEC;
}

void* wifi_handler(void* params)
{
	clock_t start = clock();
	int i = packets_number / 2;
	while (i < packets_number)
	{
		pthread_mutex_lock(&mutex_wifi);
		memcpy(wifi_packet, &(datagrams[i].eh), sizeof(ethernet_header));
		memcpy(wifi_packet + sizeof(ethernet_header), &(datagrams[i].ih), sizeof(ip_header));
		memcpy(wifi_packet + sizeof(ethernet_header) + sizeof(ip_header) - 4, &(datagrams[i].uh), sizeof(udp_header));
		memcpy(wifi_packet + sizeof(ethernet_header) + sizeof(ip_header) - 4 + sizeof(udp_header), &(datagrams[i].data), DATA_LEN + sizeof(unsigned long));

		if (pcap_sendpacket(wifi_handle, wifi_packet, sizeof(datagram)) != 0) {
			printf("Error sending packet: %lu over wifi\n", ntohl(datagrams[i].serial_number));
		}
		else {
			printf("Success sending packet: %lu over wifi\n", ntohl(datagrams[i].serial_number));
		}

		pthread_mutex_unlock(&mutex_wifi);

		pcap_dispatch(eth_handle, 1, packet_handler_wifi, NULL);

		pthread_mutex_lock(&mutex_wifi);

		if (wifi_received == 1)
		{
			wifi_sent_packets++;
			printf("Success receiving packet: %lu over wifi! Go for next packet\n", ntohl(datagrams[i].serial_number));
			i++;
			wifi_received = 0;
		}
		else
		{
			printf("Error sending packet: %lu over wifi! Try again this packet\n", ntohl(datagrams[i].serial_number));
		}
		pthread_mutex_unlock(&mutex_wifi);
	}
	if (ethernet_broken == 1)
	{
		/*Copy data into datagrams*/
		for (int i = ethernet_broken_at_packet; i < packets_number / 2; i++)
		{
			create_packet(&(datagrams[i]), &data[i*DATA_LEN], DATA_LEN, i + 1, src_mac_wifi, dest_mac_wifi, src_ip_wifi, dest_ip_wifi);
		}
		i = ethernet_broken_at_packet;
		while (i < packets_number / 2)
		{
			pthread_mutex_lock(&mutex_wifi);
			memcpy(wifi_packet, &(datagrams[i].eh), sizeof(ethernet_header));
			memcpy(wifi_packet + sizeof(ethernet_header), &(datagrams[i].ih), sizeof(ip_header));
			memcpy(wifi_packet + sizeof(ethernet_header) + sizeof(ip_header) - 4, &(datagrams[i].uh), sizeof(udp_header));
			memcpy(wifi_packet + sizeof(ethernet_header) + sizeof(ip_header) - 4 + sizeof(udp_header), &(datagrams[i].data), DATA_LEN + sizeof(unsigned long));

			if (pcap_sendpacket(wifi_handle, wifi_packet, sizeof(datagram)) != 0) {
				printf("Error sending packet: %lu over wifi\n", ntohl(datagrams[i].serial_number));
			}
			else {
				printf("Success sending packet: %lu over wifi\n", ntohl(datagrams[i].serial_number));
			}

			pthread_mutex_unlock(&mutex_wifi);

			pcap_dispatch(eth_handle, 1, packet_handler_wifi, NULL);

			pthread_mutex_lock(&mutex_wifi);

			if (wifi_received == 1)
			{
				wifi_sent_packets++;
				printf("Success receiving packet: %lu over wifi! Go for next packet\n", ntohl(datagrams[i].serial_number));
				i++;
				wifi_received = 0;
			}
			else
			{
				printf("Error sending packet: %lu over wifi! Try again this packet\n", ntohl(datagrams[i].serial_number));
			}
			pthread_mutex_unlock(&mutex_wifi);
		}
	}

	clock_t end = clock();
	wifi_time = (float)(end - start) / CLOCKS_PER_SEC;
}