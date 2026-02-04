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
	return kriptovanaPoruka;
}




//////////////////////////////////

const char* cezar(char* poruka) {
	int duzinaPoruke = strlen(poruka);
	char* kriptovanaPoruka = (char*)malloc(duzinaPoruke);

	for (int i = 0; i < duzinaPoruke; i++) {
		kriptovanaPoruka[i] = (poruka[i] - 'A' + 4) % 26 + 'A';
	}
	kriptovanaPoruka[duzinaPoruke] = '\0';

	return kriptovanaPoruka;
}



///////////////////////////////////




const char* vizner(char* poruka)

{
	char kljuc[] = "PSI";

	int duzinaPoruke = strlen(poruka);
	int duzinaKljuca = strlen(kljuc);

	char* kriptovanaPoruka = (char*)malloc(256 * sizeof(char));

	if (duzinaKljuca == 0)
	{
		return "Nista to";
	}

	for (int i = 0; i < duzinaPoruke; i++)
	{
		if (kljuc[i % duzinaKljuca] == '\0')
		{
			kljuc[i % duzinaKljuca] = kljuc[i % duzinaKljuca - duzinaKljuca];
		}
	}

	for (int i = 0; i < duzinaPoruke; i++)
	{
		kriptovanaPoruka[i] = 'A' + (poruka[i] - 'A' + kljuc[i % duzinaKljuca] - 'A') % 26;
	}

	kriptovanaPoruka[duzinaPoruke] = '\0';

	return kriptovanaPoruka;
}



////////////////////////////////



const char* plejfer(char* poruka)
{
    char kljuc[5][5] = { {'P', 'R', 'I', 'M', 'E'}, 
					 {'N', 'A', 'B', 'C', 'D'}, 
					 {'F', 'G', 'H', 'K', 'L'},  
					 {'O', 'Q', 'S', 'T', 'U'},  
					 {'V', 'W', 'X', 'Y', 'Z'} };
                     
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