// We do not want the warnings about the old deprecated and unsecure CRT functions since these examples can be compiled under *nix as well
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

// Include libraries
#include <stdlib.h>
#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include "conio.h"
#include "pcap.h"
#include "protocol_headers.h"

// Function declarations
void dispatcher_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data);
const char* homofon(char* poruka);
const char* vizner(char* poruka);
//referenca na fajl u koji se upisuje
pcap_dumper_t* file_dumper;
int icmp_packet_counter = 0;
int ttl_packet_counter = 0;

int main()
{
	pcap_t* device_handle;
	char error_buffer[PCAP_ERRBUF_SIZE];
	if ((device_handle = pcap_open_offline("input_packets.pcap", // Name of the device
		error_buffer)) == NULL){
		printf("\n Unable to open the file %s.\n", "packetsv12.pcap");
		return -1;
	}
	file_dumper = pcap_dump_open(device_handle, "encrypackets.pcap");
	if (file_dumper == NULL){
		printf("Error opening output file\n");
		return -1;
	}
	// Check the link layer. We support only Ethernet for simplicity. 
	if (pcap_datalink(device_handle) != DLT_EN10MB){
		printf("\nThis program works only on Ethernet networks.\n");
		return -1;
	}
	// Read and dispatch packets until EOF is reached 
	pcap_loop(device_handle, 0, dispatcher_handler, NULL);
	printf("Ukupno ima %d TLS paketa", ttl_packet_counter);
	// Close the file associated with device_handle and deallocates resources 
	pcap_close(device_handle);
	getchar();
}
void dispatcher_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{
	int duzinaPaketa = packet_header->len;
	printf("Duzina paketa u bajtima je %d\n", duzinaPaketa);// da li ovde treba duzinaPaketa * 4 nisam siguran
	ethernet_header* eh = (ethernet_header*)packet_data;
	printf("Fizicka adresa posiljaoca %d:%d:%d:%d:%d:%d\n", eh->src_address[0],
		eh->src_address[1], eh->src_address[2], eh->src_address[3],
		eh->src_address[4], eh->src_address[5]);
	printf("Fizicka adresa primaoca %d:%d:%d:%d:%d:%d\n", eh->dest_address[0],
		eh->dest_address[1], eh->dest_address[2], eh->src_address[3],
		eh->dest_address[4], eh->dest_address[5]);

	char kopija[10000];
	memset(kopija, 0, duzinaPaketa * sizeof(char));
	memcpy(kopija, eh, sizeof(ethernet_header) * sizeof(char));

	if (ntohs(eh->type) == 0x0800) {
		printf("IP \n");
		ip_header* ih = (ip_header*)((unsigned char*)eh + sizeof(ethernet_header));
		printf("Logicka adresa posiljaoca %d.%d.%d.%d\n", ih->src_addr[0],
			ih->src_addr[1], ih->src_addr[2], ih->src_addr[3]);
		printf("Time to live je %d\n", ih->ttl);
		printf("Duzina zaglavlja u bajtima je %d\n", ih->header_length * 4);

		memcpy(kopija + sizeof(ethernet_header), ih, ih->header_length * 4);

		if (ih->next_protocol == 6) {
			printf("TCP *************************************************\n");
			tcp_header* th = (tcp_header*)((unsigned char*)ih + ih->header_length * 4);
			printf("Port posiljaoca je %d\n", ntohs(th->src_port));
			printf("Broj potrvrde je %u\n", th->ack_num);

			if (ntohs(th->dest_port) == 443 || ntohs(th->src_port) == 443) {
				printf("PRIKAZA\n");
				ttl_packet_counter++;
				char* app_data = (char*)((unsigned char*)th + th->header_length * 4);
				printf("Content type je %d\n", app_data[0]);
			}
		}
		else if (ih->next_protocol == 17) {
			printf("UDP __________________________________________________________\n");
			udp_header* uh = (udp_header*)((unsigned char*)ih + ih->header_length * 4);
			printf("Ukupna duzina UDP zaglavlja je %d\n", ntohs(uh->datagram_length));
			
			memcpy(kopija + sizeof(ethernet_header) + ih->header_length * 4, uh, sizeof(udp_header));
			
			char* app_data = (char*)((unsigned char*)uh + sizeof(udp_header));
			int app_data_size = ntohs(uh->datagram_length) - sizeof(udp_header);
			for (int i = 0; i < app_data_size; i++) {
				printf("%c", app_data[i]);
				if ((i + 1) % 16 == 0) {
					printf("\n");
				}
			}
			printf("\n");
			app_data[app_data_size] = '\0';

		
			char cipher[200] = "\0";
			strcpy(cipher, vizner(app_data));
			printf("Sifrovano: %s\n", cipher);

			//kopiranje sifrovane poruke u kopiju aplikativnog dela paketa
			memcpy(kopija + sizeof(ethernet_header) + ih->header_length * 4 + sizeof(udp_header), 
				cipher, app_data_size);

			//zapisivanje kopije u fajl
			pcap_dump((unsigned char*)file_dumper, packet_header, (const unsigned char*)kopija);
			
		}
	}
}
const char* vizner(char* poruka)
{
	char kljucVizner[] = "KLJUC";

	int duzinaPoruke = strlen(poruka);
	int i, j;
	int duzinaKljuca = strlen(kljucVizner);
	char* kriptovanaPoruka = (char*)malloc(256 * sizeof(char));
	char* noviKljuc = (char*)malloc(256 * sizeof(char));
	for (i = 0, j = 0; i < duzinaPoruke; ++i, ++j) {
		if (j == duzinaKljuca)
			j = 0;

		noviKljuc[i] = kljucVizner[j];
	}
	noviKljuc[i] = '\0';
	for (i = 0; i < duzinaPoruke; ++i)
		kriptovanaPoruka[i] = ((poruka[i] + noviKljuc[i]) % 26) + 'A';

	kriptovanaPoruka[duzinaKljuca] = '\0';
	return (const char*)kriptovanaPoruka;
}

