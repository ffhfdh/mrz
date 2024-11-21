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

//referenca na fajl u koji se upisuje
pcap_dumper_t* file_dumper;
int udp_counter = 0;
int udp_koji_prenosi_DNS_counter = 0;
const char* cezar(char* poruka);
const char* vizner(char* poruka, char* kljuc);

int main()
{
	pcap_t* device_handle;
	char error_buffer[PCAP_ERRBUF_SIZE];
	// Open the capture file
	if ((device_handle = pcap_open_offline("packetsv12.pcap", // Name of the device
		error_buffer // Error buffer
	)) == NULL)
	{
		printf("\n Unable to open the file %s.\n", "packetsv12.pcap");
		return -1;
	}
	file_dumper = pcap_dump_open(device_handle, "example.pcap");
	if (file_dumper == NULL)
	{
		printf("file dumper je null\n");
		return -1;
	}
	// Check the link layer. We support only Ethernet for simplicity. 
	if (pcap_datalink(device_handle) != DLT_EN10MB)
	{
		printf("\nThis program works only on Ethernet networks.\n");
		return -1;
	}
	// Read and dispatch packets until EOF is reached 
	pcap_loop(device_handle, 0, dispatcher_handler, NULL);
	printf("Broj udp paketa je %d\n", udp_counter);
	printf("Broj udp paketa koji prenose dns je %d\n", udp_koji_prenosi_DNS_counter);
	printf("Broj udp paketa koji ne prenosi dns je %d", udp_counter - udp_koji_prenosi_DNS_counter);
	// Close the file associated with device_handle and deallocates resources 
	pcap_close(device_handle);
	getchar();
	return 0;
}

void dispatcher_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{
	ethernet_header* eh = (ethernet_header*)packet_data;
	int duzinaPaketaSaZaglavljem = packet_header->len;
	printf("duzina paketa sa zaglavljem je %d\n", duzinaPaketaSaZaglavljem);
	int duzinaBezZaglavlja = duzinaPaketaSaZaglavljem - sizeof(ethernet_header);
	printf("duzina paketa bez zaglavlja je %d\n", duzinaBezZaglavlja);

	char kopija[2000];
	memset(kopija, 0, packet_header->len);
	memcpy(kopija, eh, sizeof(ethernet_header));

	if (ntohs(eh->type) == 0x0800) {
		printf("IP \n");
		ip_header* ih = (ip_header*)((unsigned char*)eh + sizeof(ethernet_header));
		printf("Identifikacioni broj ip paketa je %d\n", ntohs(ih->identification));
		printf("Logicka adresa posiljaoca je %d.%d.%d.%d\n", ih->src_addr[0],
			ih->src_addr[1], ih->src_addr[2], ih->src_addr[3]);

		memcpy(kopija + sizeof(ethernet_header), ih, sizeof(ip_header));

		if (ih->next_protocol == 1) {
			printf("ICMP\n");
			icmp_header* ich = (icmp_header*)((unsigned char*)ih + ih->header_length * 4);
			printf("Brojevni kod icmp poruke je %d\n", ich->code);
			printf("Sadrzaj icmp poruke je %d.%d.%d.%d\n", ich->data[0], 
				ich->data[1], ich->data[2], ich->data[3]);
		}
		else if (ih->next_protocol == 6) {
			printf("TCP\n");
			tcp_header* th = (tcp_header*)((unsigned char*)ih + ih->header_length * 4);
			printf("Port posiljaoca je %d\n", ntohs(th->src_port));
			printf("Duzina TCP zaglavlja je %d\n", th->header_length*4);

			if (ntohs(th->src_port) == 53 || ntohs(th->dest_port) == 53) {
				printf("DNS\n");
				char* app_data = (char*)((unsigned char*)th + th->header_length * 4);
				int app_data_size = packet_header->len - sizeof(ethernet_header) -
					ih->header_length * 4 - th->header_length * 4;
				for (int i = 0; i < app_data_size; i++) {
					printf("%.2x", app_data[i]);
					if ((i % 32) == 0) {
						printf("\n");
					}
				}
				printf("\n");
			}
		}
		else if (ih->next_protocol == 17) {
			printf("UDP\n");
			udp_header* uh = (udp_header*)((unsigned char*)ih + ih->header_length * 4);
			printf("Port UDP posiljaoca je %d\n", ntohs(uh->src_port));
			printf("Duzina UDP zaglavlja je %d\n", sizeof(udp_header));
			udp_counter++;
			char* app_data = (char*)((unsigned char*)uh + sizeof(udp_header));
			int app_data_length = ntohs(uh->datagram_length) - sizeof(udp_header);

			if (ntohs(uh->src_port) == 53 || ntohs(uh->dest_port) == 53) {
				printf("DNS\n");
				udp_koji_prenosi_DNS_counter++;
				for (int i = 0; i < app_data_length; i++) {
					printf("%.2x", app_data[i]);
					if ((i % 32) == 0) {
						printf("\n");
					}
				}
				printf("\n");
			}
			app_data[app_data_length] = '\0';
			///5. tacka yall know that aint happenin

			memcpy(kopija + sizeof(ethernet_header) + ih->header_length * 4, uh,
				sizeof(udp_header));

			//char prvaRec[] = "WPCAP";
			char* prvaRec = "WPCAP";
			printf("rec koja ulazi u Cezara je %s\n", prvaRec);
			char cezarovaRec[10] = "\0";
			strcpy(cezarovaRec, cezar(prvaRec));
			printf("rec koja je izasla iz Cezara je %s\n", cezarovaRec);

			char cipher[200] = "\0";
			strcpy(cipher, vizner(app_data, cezarovaRec));
			printf("_________________________Izlaz iz Viznera je %s\n", cipher);

			memcpy(kopija + sizeof(ethernet_header) + ih->header_length * 4 + sizeof(udp_header),
				cipher, app_data_length);

			pcap_dump((unsigned char*)file_dumper, packet_header, (const unsigned char*)kopija);
		}
	}
}
const char* cezar(char* poruka) {
	int duzinaPoruke = strlen(poruka);
	char* kriptovanaPoruka = (char*)malloc(duzinaPoruke);

	for (int i = 0; i < duzinaPoruke; i++) {
		kriptovanaPoruka[i] = (poruka[i] - 'A' + 4) % 26 + 'A';
	}
	kriptovanaPoruka[duzinaPoruke] = '\0';

	return (const char*)kriptovanaPoruka;
}
const char* vizner(char* poruka, char* kljucVizner) {
	int duzinaPoruke = strlen(poruka);
	int i, j;
	int duzinaKljuca = strlen(kljucVizner);
	char* kriptovanaPoruka = (char*)malloc(256 * sizeof(char));
	char* noviKljuc = (char*)malloc(256 * sizeof(char));
	for (i = 0, j = 0; i < duzinaPoruke; i++, j++) {
		if (j == duzinaKljuca) {
			j = 0;
		}
		noviKljuc[i] = kljucVizner[j];
	}
	noviKljuc[i] = '\0';
	for (i = 0; i < duzinaPoruke; i++) {
		kriptovanaPoruka[i] = ((poruka[i] + noviKljuc[i]) % 26) + 'A';
	}
	kriptovanaPoruka[duzinaKljuca] = '\0';
	return (const char*)kriptovanaPoruka;
}