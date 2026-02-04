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
const char* playfair(char* plaintext);

// Plejfer matrica
char kljuc[5][5] = { {'M', 'R', 'E', 'Z', 'A'}, 
					 {'B', 'C', 'D', 'F', 'G'}, 
					 {'H', 'I', 'K', 'L', 'N'},  
					 {'O', 'P', 'Q', 'S', 'T'},  
					 {'U', 'V', 'W', 'X', 'Y'} };

int icmpBrojac = 0;

//referenca na fajl u koji se upisuje
pcap_dumper_t* file_dumper;

int main()
{
	pcap_t* device_handle;
	char error_buffer[PCAP_ERRBUF_SIZE];

	//otvori fajl iz kojeg ce se citati paketi
	if ((device_handle = pcap_open_offline("inputpackets.pcap", error_buffer)) == NULL) 
	{
		printf("\n Unable to open the file inputpackets.pcap\n");
		return -1;
	}

	//otvori fajl u koji ce se upisivati kopirani i sifrovani paketi
	file_dumper = pcap_dump_open(device_handle, "encryptedpackets.pcap");
	if (file_dumper == NULL)
	{
		printf("\n Error opening output file\n");
		return -1;
	}

	// Paketi hvatani na eternetu 
	if (pcap_datalink(device_handle) != DLT_EN10MB)
	{
		printf("\nThis program works only on Ethernet networks.\n");
		return -1;
	}

	// Citanje svih paketa iz otvorenog fajla (0 - svi paketi) 
	pcap_loop(device_handle, 0, dispatcher_handler, NULL);

	printf("Number of ICMP packets: %d\n", icmpBrojac);

	pcap_close(device_handle);

	return 0;
}

void dispatcher_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{
	//ispis vremena kada je paket pristigao
	printf("New packet read at %ld:%ld\n", packet_header->ts.tv_sec,
		packet_header->ts.tv_usec);

	//duzina paketa za potrebe pravljenja
	int packetLength = packet_header->len;

	//kopija paketa, postavlja se na vrednosti 0
	char packetCopy[2000];
	memset(packetCopy, 0, packetLength * sizeof(char));

	//preuzimanje podataka iz Ethernet okvira i smestanje zaglavlja u kopiju
	ethernet_header* eh = (ethernet_header*)packet_data;

	printf("Ethernet -> Type: 0x%.4x\n", ntohs(eh->type));

	memcpy(packetCopy, eh, sizeof(ethernet_header));

	//provera da li je IPv4
	if (ntohs(eh->type) == 0x0800)
	{
		//pristupanje IP zaglavlju i smestanje u kopiju
		ip_header* ih = (ip_header*)((unsigned char*)eh + sizeof(ethernet_header));
		int ipLength = ih->header_length * 4;

		memcpy(packetCopy + sizeof(ethernet_header), ih, ipLength * sizeof(char));

		printf("IP -> DST address: %u.%u.%u.%u\n", ih->dst_addr[0], ih->dst_addr[1], ih->dst_addr[2], ih->dst_addr[3]);
		printf("IP -> TTL: %u\n", ih->ttl);

		//Provera sledeceg protokola: ICMP - 1; TCP - 6; UDP - 17
		if (ih->next_protocol == 1)
		{
			printf("Protocol: ICMP\n");
			icmpBrojac++;
		}
		else if (ih->next_protocol == 6)
		{
			//pristupanje TCP zaglavlju
			tcp_header* th = (tcp_header*)((unsigned char*)ih + ipLength);

			printf("Protocol: TCP\n");
			printf("TCP -> TTL: %u\n", ih->ttl);
			printf("IP -> TTL: %u\n", ih->ttl);
		}
		else if (ih->next_protocol == 17)
		{
			//Pristupanje UDP zaglavlju i smestanje u kopiju
			printf("Protocol: UDP\n");
			udp_header* uh = (udp_header*)((unsigned char*)ih + ipLength);
			memcpy(packetCopy + sizeof(ethernet_header) + ipLength, uh, sizeof(udp_header));

			//Aplikativni deo
			unsigned char* app_data = (unsigned char*)uh + sizeof(udp_header);
			int app_length = ntohs(uh->datagram_length) - sizeof(udp_header);

			app_data[app_length] = '\0';

			//sifrovanje poruke
			char cipher[200] = "\0";
			strcpy(cipher, playfair((char*)app_data));

			//kopiranje sifrovane poruke u kopiju aplikativnog dela paketa
			memcpy(packetCopy + sizeof(ethernet_header) + ipLength + sizeof(udp_header), cipher, app_length);

			//zapisivanje kopije u fajl
			pcap_dump((unsigned char*)file_dumper, packet_header, (const unsigned char*)packetCopy);
		}
	}
	printf("\n\n");
}

const char* playfair(char* plaintext)
{
	//pozicija slova u redovima i kolonama matrice
	int r1 = -1, r2 = -1, c1 = -1, c2 = -1;

	int textLength = strlen(plaintext);

	//Ako je poruka neparne duzine, na kraj se dodaje neutralni karakter
	char neutralCharacter = 'Z';
	if (textLength % 2 != 0)
	{
		strncat(plaintext, &neutralCharacter, 1);
		textLength += 1;
	}

	char ciphertext[200];

	//Trazenje pozicije parova slova u matrici
	for (int i = 0; i < textLength; i += 2)
	{
		//ako se u poruci pojavi slovo J menja se u slovo I
		if (plaintext[i] == 'J')
		{
			plaintext[i] = 'I';
		}
		if (plaintext[i + 1] == 'J')
		{
			plaintext[i + 1] = 'I';
		}

		for (int j = 0; j < 5; j++)
		{
			for (int k = 0; k < 5; k++)
			{
				if (kljuc[j][k] == plaintext[i])
				{
					r1 = j;
					c1 = k;
				}
				if (kljuc[j][k] == plaintext[i + 1])
				{
					r2 = j;
					c2 = k;
				}
			}
		}

		//ako su dva ista slova
		if (r1 == r2 && c1 == c2)
		{
			//ono ostaje isto, i dodaje se X
			ciphertext[i] = plaintext[i];
			ciphertext[i + 1] = 'X';
		}
		else
		{
			//ako su slova u istom redu
			if (r1 == r2)
			{
				//ako je poslednja kolona, pomera se na prvu
				if (c1 == 4)
				{
					ciphertext[i] = kljuc[r1][0];
				}
				//u suprotnom, pomera se u kolonu desno
				else
				{
					ciphertext[i] = kljuc[r1][c1 + 1];
				}
				if (c2 == 4)
				{
					ciphertext[i + 1] = kljuc[r2][0];
				}
				else
				{
					ciphertext[i + 1] = kljuc[r2][c2 + 1];
				}
			}
			//ako su slova u istoj koloni
			else if (c1 == c2)
			{
				//ako je poslednji red, pomera se na prvi
				if (r1 == 4)
				{
					ciphertext[i] = kljuc[0][c1];
				}
				//u suprotnom, pomera se u red dole
				else
				{
					ciphertext[i] = kljuc[r1 + 1][c1];
				}
				if (r2 == 4)
				{
					ciphertext[i + 1] = kljuc[0][c2];
				}
				else
				{
					ciphertext[i + 1] = kljuc[r2 + 1][c2];
				}
			}
			//u slucaju da su u razlicitim redovima i kolonama, menjaju se kolone
			else
			{
				ciphertext[i] = kljuc[r1][c2];
				ciphertext[i + 1] = kljuc[r2][c1];
			}
		}
	}

	//zavrsava se poruka
	ciphertext[textLength] = '\0';
	return ciphertext;
}