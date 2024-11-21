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
//referenca na fajl u koji se upisuje
pcap_dumper_t* file_dumper;
int icmp_packet_counter = 0;
int ttl_packet_counter = 0;

int main()
{
	pcap_t* device_handle;
	char error_buffer[PCAP_ERRBUF_SIZE];
	// Open the capture file
	if ((device_handle = pcap_open_offline("input_packets.pcap", // Name of the device
		error_buffer)) == NULL) {
		printf("\n Unable to open the file %s.\n", "input_packets.pcap");
		return -1;
	}
	file_dumper = pcap_dump_open(device_handle, "example.pcap");
	if (file_dumper == NULL) {
		printf("Error opening output files\n");
	}
	if (pcap_datalink(device_handle) != DLT_EN10MB) {
		printf("\nThis program works only on Ethernet networks.\n");
		return -1;
	}
	// Read and dispatch packets until EOF is reached 
	pcap_loop(device_handle, 0, dispatcher_handler, NULL);
	printf("Broj ICMP paketa je %d\n", icmp_packet_counter);
	printf("Broj TTL paketa je %d\n", ttl_packet_counter);
	// Close the file associated with device_handle and deallocates resources 
	pcap_close(device_handle);
	getchar();
	return 0;
}

void dispatcher_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{
	printf("paket pristigao, vreme je %ld:%ld\n", packet_header->ts.tv_sec, packet_header->ts.tv_usec);
	int velicinaPaketa = packet_header->len;
	printf("Ukupna duzina paketa u bajtima je %d\n", velicinaPaketa);

	ethernet_header* eh = (ethernet_header*)packet_data;
	char kopija[1000];
	//memset(kopija, 0, sizeof(kopija));
	memset(kopija, 0, velicinaPaketa * sizeof(char));
	memcpy(kopija, eh, sizeof(ethernet_header));


	printf("Fizicka adresa primaoca je %d:%d:%d:%d:%d:%d\n",
		eh->dest_address[0], eh->dest_address[1], eh->dest_address[2],
		eh->dest_address[3], eh->dest_address[4], eh->dest_address[5]);


	if (ntohs(eh->type) == 0x0800) {
		printf("IP protokol ***************************************************\n");
		ip_header* ih = (ip_header*)((unsigned char*)eh + sizeof(ethernet_header));
		printf("Kontrolna suma %d\n", ntohs(ih->checksum));
		printf("Logicka adresa primaoca %d.%d.%d.%d\n", ih->dst_addr[0],
			ih->dst_addr[1], ih->dst_addr[2], ih->dst_addr[3]);
		printf("Time to live %d\n", ih->ttl);

		memcpy(kopija + sizeof(ethernet_header), ih, (ih->header_length * 4) * sizeof(char));

		if (ih->next_protocol == 1) {
			printf("ICMP protokol\n");
			icmp_packet_counter++;
		}
		else if (ih->next_protocol == 6) {	///TCP{
			printf("TCP protokol __________________________________\n");
			tcp_header* th = (tcp_header*)((unsigned char*)ih + ih->header_length * 4);
			printf("Velicina prozora za TCP paket je %d\n", ntohs(th->windows_size));

			if (ntohs(th->src_port) == 443 || ntohs(th->dest_port) == 443) { //TTL
				printf("TTL protokol ODVRATNI, TTL SPODOBA\n");
				ttl_packet_counter++;
				char* app_data = (char*)((unsigned char*)th + th->header_length * 4);
				printf("Version je %d\n", app_data[1]);
				//na slici je objasnjeno zasto je ovde bas app_data[1]
				//samo je pitanje kako se printa app_data, da li sa %d %s %c %u 
				//to se radi pogadjackom metodom, proba se neki od ovih i ako
				//rezulat na konzoli bude neki nakaradan broj onda se proba neki drugi
			}
		}
		else if (ih->next_protocol == 17) {	//UDP
			printf("UDP protokol !!!!!!!!!!!!!!!!!!!!!!!!!!\n");
			udp_header* uh = (udp_header*)((unsigned char*)ih + ih->header_length * 4);
			printf("Odredisni port %d\n", ntohs(uh->src_port));
			//isto je kada se printa sa %u ili %d u oba slucaja isti broj ispise
			//printf("Odredisni port %u\n", ntohs(uh->src_port));	
			char* app_data = (char*)((unsigned char*)uh + sizeof(udp_header));
			//zato sto udp header nema polje header length ne moze da se pristupi preko
			//uh->header_length * 4 jer to polje ne postoji, zato se pise sizeof(udp_header)
			int app_length = ntohs(uh->datagram_length) - sizeof(udp_header);
			//u datagram length se nalaze i UDP protokol i aplikativni podaci, ako 
			//hocemo da dodjemo do velicine aplikativnih podataka samo oduzmemo sizeof(udp)

			memcpy(kopija + sizeof(ethernet_header) + ih->header_length * 4, uh, sizeof(udp_header));
			///sad se u kopija nalazi sve iz paketa osim aplikativnih podataka, mi njih treba da sifurjemo i onda da ih ubacimo u kopiju
			for (int i = 0; i < app_length; i++) {
				printf("%c", app_data[i]);
				if ((i + 1) % 16 == 0) {
					printf("\n");
				}
			}
			printf("\n");
			app_data[app_length] = '\0';//ne znam da li ovo mora, mozda i ne mora al nek bude

			char encrypted[200] = "\0";
			strcpy(encrypted, homofon(app_data));
			printf("Sifrovana poruka je %s\n", encrypted);

			memcpy(kopija + sizeof(ethernet_header) + ih->header_length * 4 + sizeof(udp_header),
				encrypted, app_length); //kopiramo ono je u encrypted u app_datu nase kopije

			pcap_dump((unsigned char*)file_dumper, packet_header, (const unsigned char*)kopija);

		}
	}
}
const char* homofon(char* poruka) {
	// A  A  B C  D  E  E  F  G  H  I I J  K L
	// 33 2 55 4 10 58 12 21 99 83 71 1 6 47 91
	// -------------------------------------------
	//  M  N  O  O  P  R  S T  U  U  V  W  X  Y  Z
	// 11 22 14 16 31 56 41 8 77 66 51 39 46 24 29
	char matrica[52] = { 32, 2, 55, -1, 4, -1, 10, -1, 58, 12, 21, -1, 99, -1, 83, -1,
	71, 1, 6, -1, 47, -1, 91, -1, 11, -1, 22, -1, 14, 16, 31, -1, 56, -1, 41, -1, 8,
	-1, 77, 66, 51, -1, 39, -1, 46, -1, 24, -1, 29, -1 };
	//ako se slovo pojavi samo jednom onda se pise -1 posle njega
	//ako se slovo javi 2 puta onda se zapisu ta dva broja i NE zapise se -1 posle
	int duzinaPoruke = strlen(poruka);
	char* kriptovanaPoruka = (char*)malloc(256 * sizeof(char));
	int nasumicnoSlovo = 0;
	for (int i = 0; i < duzinaPoruke; i++) {
		int trenutnoSlovoAscii = poruka[i] - 65;
		if (matrica[trenutnoSlovoAscii * 2] != -1) {
			if (matrica[trenutnoSlovoAscii * 2 + 1] != -1) {
				kriptovanaPoruka[i] = matrica[trenutnoSlovoAscii * 2 + nasumicnoSlovo];
				nasumicnoSlovo = ~nasumicnoSlovo;	//ovde stvarno ne znam sta se desilo, NAPAMET
			}
			else {
				kriptovanaPoruka[i] = matrica[trenutnoSlovoAscii * 2];
			}
		}
	}
	kriptovanaPoruka[duzinaPoruke] = '\0';
	return (const char*)kriptovanaPoruka;
}
