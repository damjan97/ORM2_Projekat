// ================================================================
// Katedra: Katedra za racunarsku tehniku i racunarske komunikacije
// Predmet: Osnovi racunarskih mreza 2
// Godina studija: III godina
// Semestar: Letnji (VI)
// Skolska godina: 2017/2018
// Datoteka: receiver.c
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
void first_packet_handler(unsigned char* param, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data);
void write_to_file(char* file_name);
void* ethernet_handler(void* params);
void* wifi_handler(void* params);

unsigned char* yes = "Yes";
unsigned int data_len = 666;
unsigned int last_message_length = 666;
unsigned int packets_number = 666;
int received_packets_ethernet = 0;
int received_packets_wifi = 0;
char received_ack[4];
unsigned char packet[sizeof(datagram)];
unsigned char first_packet[sizeof(first_datagram)];
unsigned char eth_ack[sizeof(datagram)];
unsigned char wifi_ack[sizeof(datagram)];
datagram* datagrams_ethernet;
datagram* datagrams_wifi;
datagram eth_ack_dat;
datagram wifi_ack_dat;
pthread_mutex_t mutex_eth;
pthread_mutex_t mutex_wifi;
pcap_t* eth_handle;
pcap_t* wifi_handle;

unsigned char src_mac_eth[6] = { 0x2c, 0x60, 0x0c, 0x9c, 0x37, 0xcd };
unsigned char dest_mac_eth[6] = { 0x28, 0xd2, 0x44, 0x2e, 0xd0, 0xb4 };
unsigned char src_ip_eth[4] = { 192, 168, 1, 5 };
unsigned char dest_ip_eth[4] = { 192, 168, 1, 4 };

unsigned char src_mac_wifi[6] = { 0x00, 0x0f, 0x60, 0x05, 0xaf, 0xd4 };
unsigned char dest_mac_wifi[6] = { 0x00, 0x0f, 0x60, 0x05, 0x1c, 0xf1 };
unsigned char src_ip_wifi[4] = { 192, 168, 1, 8 };
unsigned char dest_ip_wifi[4] = { 192, 168, 1, 7 };

int main()
{
	pcap_if_t* devices;
	pcap_if_t* eth_device;
	pcap_if_t* wifi_device;

	char* filter_exp_eth = "udp port 27015 and ip dst 192.168.1.5";
	char* filter_exp_wifi = "udp port 27015 and ip dst 192.168.1.8";
	struct bpf_program fcode_eth, fcode_wifi;
	unsigned int netmask_wifi, netmask_eth;
	char error_buffer [PCAP_ERRBUF_SIZE];
	unsigned long length;

	pthread_t thread_ethernet;
	pthread_t thread_wifi;

	pthread_mutex_init(&mutex_eth, NULL);
	pthread_mutex_init(&mutex_wifi, NULL);


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

	pcap_loop(eth_handle, 1, first_packet_handler, NULL);
	create_packet(&eth_ack_dat, yes, 3, 0, src_mac_eth, dest_mac_eth, src_ip_eth, dest_ip_eth);
	memcpy(eth_ack, &(eth_ack_dat.eh), sizeof(ethernet_header));
	memcpy(eth_ack + sizeof(ethernet_header), &(eth_ack_dat.ih), sizeof(ip_header));
	memcpy(eth_ack + sizeof(ethernet_header) + sizeof(ip_header) - 4, &(eth_ack_dat.uh), sizeof(udp_header));
	memcpy(eth_ack + sizeof(ethernet_header) + sizeof(ip_header) - 4 + sizeof(udp_header), &(eth_ack_dat.data), DATA_LEN);
	memcpy(eth_ack + sizeof(ethernet_header) + sizeof(ip_header) - 4 + sizeof(udp_header) + DATA_LEN, &(eth_ack_dat.serial_number), sizeof(unsigned long));

	if (pcap_sendpacket(eth_handle, eth_ack, sizeof(datagram)) != 0) {
		printf("Error sending ack\n");
	}
	else {
		printf("Success sending ack\n");
	}
	printf("Number of packets: %u\n", packets_number);
	printf("Data len: %u\n", data_len);
	printf("Last message length: %u\n", last_message_length);

	datagrams_ethernet = (datagram*)malloc((packets_number / 2) * sizeof(datagram));
	datagrams_wifi = (datagram*)malloc(((packets_number + 1) / 2) * sizeof(datagram));

	pthread_create(&thread_ethernet, NULL, ethernet_handler, NULL);
	pthread_create(&thread_wifi, NULL, wifi_handler, NULL);

	
	pthread_join(thread_wifi, NULL);
	pthread_join(thread_ethernet, NULL);

	printf("Total packets received over ethernet: %d\n", received_packets_ethernet);
	printf("Total packets received over wifi: %d\n", received_packets_wifi);

	write_to_file("output.txt");


	/*Free resources*/
	free(datagrams_ethernet);
	free(datagrams_wifi);

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
			memcpy(&(datagrams_ethernet[received_packets_ethernet].eh), packet_data, sizeof(ethernet_header));
			memcpy(&(datagrams_ethernet[received_packets_ethernet].ih), packet_data + sizeof(ethernet_header), sizeof(ip_header));
			memcpy(&(datagrams_ethernet[received_packets_ethernet].uh), packet_data + sizeof(ethernet_header) + sizeof(ip_header) - 4, sizeof(udp_header));
			memcpy(&(datagrams_ethernet[received_packets_ethernet].data), packet_data + sizeof(ethernet_header) + sizeof(ip_header) - 4 + sizeof(udp_header), DATA_LEN);
			memcpy(&(datagrams_ethernet[received_packets_ethernet].serial_number), packet_data + sizeof(ethernet_header) + sizeof(ip_header) - 4 + sizeof(udp_header) + DATA_LEN, sizeof(unsigned long));
			printf("Received packet number %lu over ethernet\n", ntohl(datagrams_ethernet[received_packets_ethernet].serial_number));
			if(received_packets_ethernet == (ntohl(datagrams_ethernet[received_packets_ethernet].serial_number) - 1))
                received_packets_ethernet++;
            printf("Received packets ethernet: %d\n", received_packets_ethernet);
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
            if (received_packets_wifi == (packets_number + 1) / 2 - 1)
            {

            }
			memcpy(&(datagrams_wifi[received_packets_wifi].eh), packet_data, sizeof(ethernet_header));
			memcpy(&(datagrams_wifi[received_packets_wifi].ih), packet_data + sizeof(ethernet_header), sizeof(ip_header));
			memcpy(&(datagrams_wifi[received_packets_wifi].uh), packet_data + sizeof(ethernet_header) + sizeof(ip_header) - 4, sizeof(udp_header));
            memcpy(&(datagrams_wifi[received_packets_wifi].data), packet_data + sizeof(ethernet_header) + sizeof(ip_header) - 4 + sizeof(udp_header), DATA_LEN);
            memcpy(&(datagrams_wifi[received_packets_wifi].serial_number), packet_data + sizeof(ethernet_header) + sizeof(ip_header) - 4 + sizeof(udp_header) + DATA_LEN, sizeof(unsigned long));
			printf("Received packet number %lu over wifi\n", ntohl(datagrams_wifi[received_packets_wifi].serial_number));
			if((received_packets_wifi + packets_number / 2)  == (ntohl(datagrams_wifi[received_packets_wifi].serial_number) - 1))
			    received_packets_wifi++;
            printf("Received packets wifi: %d\n", received_packets_wifi);
		}
	}
	pthread_mutex_unlock(&mutex_wifi);
}

void first_packet_handler(unsigned char* param, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{
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
			memcpy(&packets_number, packet_data + sizeof(ethernet_header) + sizeof(ip_header) - 4 + sizeof(udp_header), sizeof(unsigned int));
			memcpy(&data_len, packet_data + sizeof(ethernet_header) + sizeof(ip_header) - 4 + sizeof(udp_header) + sizeof(unsigned int), sizeof(unsigned int));
			memcpy(&last_message_length, packet_data + sizeof(ethernet_header) + sizeof(ip_header) - 4 + sizeof(udp_header) + sizeof(unsigned int) + sizeof(unsigned int), sizeof(unsigned int));
			packets_number = ntohl(packets_number);
			data_len = ntohl(data_len);
			last_message_length = ntohl(last_message_length);
		}
	}
}

void write_to_file(char* file_name)
{
	FILE *fout = fopen(file_name, "w");
	if (fout == NULL)
	{
		printf("Cannot open file!");
		exit(-1);
	}
	for (int i = 0; i < received_packets_ethernet; i++)
	{
		fprintf(fout, "%s", datagrams_ethernet[i].data);
	}
	for (int i = 0; i < received_packets_wifi - 1; i++)
	{
		fprintf(fout, "%s", datagrams_wifi[i].data);
	}
	unsigned char* last_message = (unsigned char*)malloc(last_message_length * sizeof(unsigned char));
	strcpy(last_message, "");
	strcat(last_message, &(datagrams_wifi[received_packets_wifi - 1].data), last_message_length);
	fprintf(fout, "%s", last_message);
	free(last_message);
	fclose(fout);
}

void* ethernet_handler(void* params)
{
	while (1)
	{
		pcap_loop(eth_handle, 1, packet_handler_ethernet, NULL);
		create_packet(&eth_ack_dat, yes, 3, 0, src_mac_eth, dest_mac_eth, src_ip_eth, dest_ip_eth);
		memcpy(eth_ack, &(eth_ack_dat.eh), sizeof(ethernet_header));
		memcpy(eth_ack + sizeof(ethernet_header), &(eth_ack_dat.ih), sizeof(ip_header));
		memcpy(eth_ack + sizeof(ethernet_header) + sizeof(ip_header) - 4, &(eth_ack_dat.uh), sizeof(udp_header));
		memcpy(eth_ack + sizeof(ethernet_header) + sizeof(ip_header) - 4 + sizeof(udp_header), &(eth_ack_dat.data), 3);
		memcpy(eth_ack + sizeof(ethernet_header) + sizeof(ip_header) - 4 + sizeof(udp_header) + DATA_LEN, &(eth_ack_dat.serial_number), sizeof(unsigned long));
		if (pcap_sendpacket(eth_handle, eth_ack, sizeof(datagram)) != 0) {
			printf("Error sending ack over ethernet\n");
		}
		else {
			//printf("Success sending ack over ethernet\n");
		}
		if (received_packets_ethernet == packets_number / 2)
		{
			break;
		}
	}
    printf("Ethernet done!\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
	return NULL;
}


void* wifi_handler(void* params)
{
	while (1)
	{
		pcap_loop(wifi_handle, 1, packet_handler_wifi, NULL);
		create_packet(&wifi_ack_dat, yes, 3, 0, src_mac_wifi, dest_mac_wifi, src_ip_wifi, dest_ip_wifi);
		memcpy(wifi_ack, &(wifi_ack_dat.eh), sizeof(ethernet_header));
		memcpy(wifi_ack + sizeof(ethernet_header), &(wifi_ack_dat.ih), sizeof(ip_header));
		memcpy(wifi_ack + sizeof(ethernet_header) + sizeof(ip_header) - 4, &(wifi_ack_dat.uh), sizeof(udp_header));
		memcpy(wifi_ack + sizeof(ethernet_header) + sizeof(ip_header) - 4 + sizeof(udp_header), &(wifi_ack_dat.data), 3);
		memcpy(wifi_ack + sizeof(ethernet_header) + sizeof(ip_header) - 4 + sizeof(udp_header) + DATA_LEN, &(wifi_ack_dat.serial_number), sizeof(unsigned long));
		if (pcap_sendpacket(wifi_handle, wifi_ack, sizeof(datagram)) != 0) {
			printf("Error sending ack over wifi\n");
		}
		else {
			//printf("Success sending ack over wifi\n");
		}
		if (received_packets_wifi == (packets_number + 1) / 2)
		{
			break;
		}
	}
    printf("Wifi done!\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
	return NULL;
}