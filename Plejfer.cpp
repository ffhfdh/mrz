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
const char* plejfer(char* poruka);
//referenca na fajl u koji se upisuje
pcap_dumper_t* file_dumper;
int svi_osim_arp_counter = 0;
int arp_counter = 0;

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
		printf("Error opening output file\n");
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
	printf("Broj svih paketa koji nisu ARP je %d\n", svi_osim_arp_counter);
	printf("Broj svih arp paketa je %d\n", arp_counter);
	double udeo_arp = (double)arp_counter / (double)svi_osim_arp_counter;
	printf("udeo ARP paketa je %lf\n", udeo_arp);
	// Close the file associated with device_handle and deallocates resources 
	pcap_close(device_handle);
	getchar();
	return 0;
}


void dispatcher_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{
	ethernet_header* eh = (ethernet_header*)packet_data;
	printf("Fizicka adresa posiljaoca je %d:%d:%d:%d:%d:%d\n", eh->src_address[0],
		eh->src_address[1], eh->src_address[2], eh->src_address[3], eh->src_address[4], eh->src_address[5]);
	printf("Tip podataka koji se prenose je %d\n", ntohs(eh->type));

	char kopija[1000];
	memset(kopija, 0, packet_header->len);
	memcpy(kopija, eh, sizeof(ethernet_header));
	if (ntohs(eh->type) == 0x0800) {
		svi_osim_arp_counter++;
		ip_header* ih = (ip_header*)((unsigned char*)eh + sizeof(ethernet_header));
		printf("Logicka adresa posiljaoca %d.%d.%d.%d\n", ih->src_addr[0],
			ih->src_addr[1], ih->src_addr[2], ih->src_addr[3]);
		printf("Time to live je %d\n", ih->ttl);

		memcpy(kopija + sizeof(ethernet_header), ih, ih->header_length * 4);

		if (ih->next_protocol == 6) {
			tcp_header* th = (tcp_header*)((unsigned char*)ih + ih->header_length * 4);
			printf("Port posiljoca je %d\n", th->src_port);
			printf("Broj potvrde je %u\n", th->ack_num);
			///4. tacka da bog prosti, moj poraz
			if (ntohs(th->src_port) == 80 || ntohs(th->dest_port) == 80) {
				printf("HTTP \n");
				char* app_data = (char*)((unsigned char*)th + th->header_length * 4);
				int app_data_length = packet_header->len - (sizeof(ethernet_header)
					+ ih->header_length * 4 + th->header_length * 4);
				for (int i = 0; i < app_data_length; i++) {
					printf("%c", app_data[i]);
					if ((i % 32) == 0) {
						printf("\n");
					}
				}
				printf("\n");
			}
		}
		else if (ih->next_protocol == 17) {
			udp_header* uh = (udp_header*)((unsigned char*)ih + ih->header_length * 4);
			int ukupna_duzina_zaglavlja_i_podataka = ntohs(uh->datagram_length);
			printf("Ukupna duzina zaglavja je %d\n", ukupna_duzina_zaglavlja_i_podataka);

			memcpy(kopija + sizeof(ethernet_header) + ih->header_length * 4,
				uh, sizeof(udp_header));

			char* app_data = (char*)((unsigned char*)uh + sizeof(udp_header));
			int app_data_length = ntohs(uh->datagram_length) - sizeof(udp_header);

			app_data[app_data_length] = '\0';

			char cipher[200];
			strcpy(cipher, plejfer(app_data));
			printf("Sifrovano %s \n", cipher);

			memcpy(kopija + sizeof(ethernet_header) + ih->header_length * 4 +
				sizeof(udp_header), cipher, app_data_length);

			pcap_dump((unsigned char*)file_dumper, packet_header, (const unsigned char*)kopija);
		}

	}
	else if (ntohs(eh->type) == 0x0806) {
		arp_counter++;
	}

}
// B  D E F G H I J K L M  O P Q  S T  V W X Y Z
char kljuc[5][5] = { {'R', 'A', 'C', 'U', 'N'},
					{'B', 'D', 'E', 'F', 'G'},
					{'H', 'I', 'K', 'L', 'M'},
					{'O', 'P', 'Q', 'S', 'T'},
					{'V', 'W', 'X', 'Y', 'Z'} };
const char* plejfer(char* poruka)
{
	//pozicija slova u redovima i kolonama matrice
	int r1 = -1, r2 = -1, k1 = -1, k2 = -1;
	int duzinaPoruke = strlen(poruka);
	//Ako je poruka neparne duzine, na kraj se dodaje neutralni karakter
	char neutralniKarakter = 'Z';
	if (duzinaPoruke % 2 == 1)
	{
		strncat(poruka, &neutralniKarakter, 1);
		duzinaPoruke += 1;
	}
	char kriptovanaPoruka[200];
	for (int i = 0; i < duzinaPoruke; i++)
	{
		//ako se u poruci pojavi slovo J menja se u slovo I
		if (poruka[i] == 'J')
		{
			poruka[i] = 'I';
		}
	}
	//Trazenje pozicije parova slova u matrici
	for (int i = 0; i < duzinaPoruke; i += 2)
	{
		for (int j = 0; j < 5; j++)
		{
			for (int k = 0; k < 5; k++)
			{
				if (kljuc[j][k] == poruka[i])
				{
					r1 = j;
					k1 = k;
				}
				if (kljuc[j][k] == poruka[i + 1])
				{
					r2 = j;
					k2 = k;
				}
			}
		}
		//ako su dva ista slova
		if (r1 == r2 && k1 == k2)
		{
			//ono ostaje isto, i dodaje se X
			kriptovanaPoruka[i] = poruka[i];
			kriptovanaPoruka[i + 1] = 'X';
		}
		else
		{
			//ako su slova u istom redu
			if (r1 == r2)
			{
				//ako je poslednja kolona, pomera se na prvu
				if (k1 == 4)
				{
					kriptovanaPoruka[i] = kljuc[r1][0];
				}
				//u suprotnom, pomera se u kolonu desno
				else
				{
					kriptovanaPoruka[i] = kljuc[r1][k1 + 1];
				}
				if (k2 == 4)
				{
					kriptovanaPoruka[i + 1] = kljuc[r2][0];
				}
				else
				{
					kriptovanaPoruka[i + 1] = kljuc[r2][k2 + 1];
				}
			}
			//ako su slova u istoj koloni
			else if (k1 == k2)
			{
				//ako je poslednji red, pomera se na prvi
				if (r1 == 4)
				{
					kriptovanaPoruka[i] = kljuc[0][k1];
				}
				//u suprotnom, pomera se u red dole
				else
				{
					kriptovanaPoruka[i] = kljuc[r1 + 1][k1];
				}
				if (r2 == 4)
				{
					kriptovanaPoruka[i + 1] = kljuc[0][k2];
				}
				else
				{
					kriptovanaPoruka[i + 1] = kljuc[r2 + 1][k2];
				}
			}
			//u slucaju da su u razlicitim redovima i kolonama, menjaju se kolone
			else
			{
				kriptovanaPoruka[i] = kljuc[r1][k2];
				kriptovanaPoruka[i + 1] = kljuc[r2][k1];
			}
		}
	}
	//zavrsava se poruka
	kriptovanaPoruka[duzinaPoruke] = '\0';
	return kriptovanaPoruka;
}
