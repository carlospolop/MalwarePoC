#include "ciphers_header.h"
#include <Windows.h>




void simple_xor_crypt(const char *key, int key_len, char *data, int data_len) {
	for (int i = 0; i < data_len; i++)
		data[i] ^= key[i % key_len];
}

void recursive_xor_encrypt(const char key, char *data, int data_len) {
	char last_byte;
	data[0] ^= key;
	memcpy(&last_byte, &data[0], 1);
	for (int i = 1; i < data_len; i++) {
		data[i] ^= last_byte;
		memcpy(&last_byte, &data[i], 1);
	}
}

void recursive_xor_decrypt(const char key, char *data, int data_len) {
	char last_byte, pre_byte;
	memcpy(&last_byte, &data[0], 1);
	data[0] ^= key;
	for (int i = 1; i < data_len; i++) {
		memcpy(&pre_byte, &data[i], 1);
		data[i] ^= last_byte;
		memcpy(&last_byte, &pre_byte, 1);
	}
}


/*
************************************************************
Author:       Monsi Terdex
Description:  RC4 cipher along with other, simpler methods
************************************************************
*/

#include <iostream>
#include <string>
#include <cstdlib>
#include <fstream>

using namespace std;
const unsigned int blockSize = 0x10000;
// these variables are RC4 facilities
unsigned char S[0x100]; // dec 256
unsigned int i, j;
// target file path and key file used for xor one-time-pad
char* loadedFile;
char* keyFile;
// functional prototypes
void rc4_init(unsigned char *, unsigned int);
unsigned char rc4_output(void);
//void xorCipher(void);
int byteCipher(int mode, char* path, char* key);
char cycle(char);
int three_cip_types(int mode, char* path, char* key) {
	int resp;
	/*cout << " * * * File Protector * * *\n"
		<< "Enter the cipher mode:\n"
		<< "Mode 1: byte inversion\n"
		<< "Mode 2: byte cycle\n"
		<< "Mode 3: xor cipher\n"
		<< "Mode 4: RC4 cipher\n"; cin >> mode;*/
	switch (mode) {
	case 1:
		resp = byteCipher(0, path, NULL);
		break;
	case 2:
		resp = byteCipher(1, path, NULL);
		break;
	//case 3: Doesnt work
		//xorCipher();
		//break;
	case 4:
		resp = byteCipher(2, path, key); // Key (8 chars min)
		break;
	default:
		//cout << "Invalid mode\n";
		break;
	}
	/*cout << "\nCipher completed.\n"
		<< "Program terminated.\n";*/
	return resp;
}
// ---------------------------------------------------------------------------
/* status: completed
* description:
* XOR cipher implementaiton, key file must be larger or equal in size to
* the message file
*/
/*void xorCipher() {
	int bufferSize = blockSize; // arbitrary choice of buffer size
	int difference = 0; // difference between current position and file size
	int targetFilePointer = 0; // starting at the beginning of the target file
	int targetFileSize = 0;
	int keyFileSize = 0;
	fstream fileStream; // using fstream for binary i/o for target file
	fstream keyStream; // using fstream for binary i/o for key file
					   // target file is opened on this line
					   // all flags must be present for successful completition of this step
	cout << "Specify file path\n";
	cin.ignore();
	getline(cin, loadedFile);
	fileStream.open(loadedFile.c_str(), ios::in | ios::out | ios::binary);
	// verifying if target file was opened successfully
	if (!fileStream.is_open()) {
		cout << "Unable to load specified target file\n";
		exit(EXIT_FAILURE);
	}
	// key file is opened on this line
	keyStream.open(keyFile.c_str(), ios::in | ios::binary);
	if (!keyStream.is_open()) {
		cout << "Unable to load specified target file\n";
		fileStream.close(); // closing already opened target file stream
		exit(EXIT_FAILURE);
	}
	// setting the reading position of the target file stream to the end
	fileStream.seekg(0, ios::end);
	// getting the position of the reading pointer, thereby retrieving target file size
	targetFileSize = fileStream.tellg();
	// setting position of the reading pointer to the start of the file
	fileStream.seekg(0, ios::beg);
	keyStream.seekg(0, ios::end);
	keyFileSize = keyStream.tellg();
	keyStream.seekg(0, ios::beg);
	if (keyFileSize < targetFileSize) {
		cout << "Unable to carry out XOR cipher. Key file is smaller than target file.\n";
		fileStream.close();
		keyStream.close();
		exit(EXIT_FAILURE);
	}
	// adjusting interface
	// loop until file pointer has reached the end of the target file
	while (targetFilePointer < targetFileSize) {
		// initializing byte array of certain specified size
		char buffer[blockSize];
		char keyBuffer[blockSize];
		// calculating difference between the current position in the file and file size
		difference = targetFileSize - targetFilePointer;
		// if the difference is less than the buffer size, then no need to fill the
		// buffer completely, only by the difference
		if (difference < bufferSize) {
			bufferSize = difference;
		}
		fileStream.seekg(targetFilePointer);
		fileStream.read(buffer, bufferSize);
		keyStream.seekg(targetFilePointer);
		keyStream.read(keyBuffer, bufferSize);
		for (int i = 0; i < bufferSize; i++) {
			// inverting every byte in the buffer
			buffer[i] = buffer[i] ^ keyBuffer[i];
		}
		// setting writing pointer to the current location
		fileStream.seekp(targetFilePointer);
		// writing the inverted file
		fileStream.write(buffer, bufferSize);
		// incrementing current file pointer by the amount of buffer
		targetFilePointer += bufferSize;
		// adjusting interface
	}
	// closing the target file stream
	fileStream.close();
	// closing the key file stream
	keyStream.close();
	// resetting interface
}*/
//---------------------------------------------------------------------------
/* status: completed
* description:
* general subroutine responsible for iterating over every byte in
* in the target file and modifying based on mode
*/
int byteCipher(int mode, char* path, char* key) {
	int bufferSize = blockSize; // arbitrary choice of buffer size
	int difference = 0; // difference between current position and file size
	int filePointer = 0; // starting at the beginning of a file
	fstream fileStream; // using fstream for binary i/o
						// file is opened on this line
						// all flags must be present for successful completition of this step
	/*cout << "Specify file path\n";
	cin.ignore();
	getline(cin, loadedFile);*/
	keyFile = key;
	loadedFile = path;
	fileStream.open(loadedFile, ios::in | ios::out | ios::binary);
	// verifying if file was opened successfully
	if (!fileStream.is_open()) {
		//cout << "Unable to load specified file.\n";
		return 1;
	}
	// setting the reading position of the file stream to the end
	fileStream.seekg(0, ios::end);
	// getting this position of the reading pointer, thereby retrieving file size
	int fileSize = fileStream.tellg();
	// setting position of the reading pointer to the start of the file
	fileStream.seekg(0, ios::beg);	
	if (mode == 2) {
		/*cout << "Please enter the RC4 key (8 chars min)\n";
		getline(cin, keyString);
		cout << "The password is: " << keyString;*/
		//setting up RC4 key
		string keyString = key;
		rc4_init((unsigned char *)keyString.c_str(), keyString.length()); // setting up RC4 using the password
	}
	// RC4 setup
	// loop until file pointer has reached the end of the file
	//cout << "\nBeginning encryption\n";
	while (filePointer < fileSize) {
		// initializing byte array of certain specified size
		char buffer[blockSize];
		// calculating difference between the current position in the file and file size
		difference = fileSize - filePointer;
		// if the difference is less than the buffer size, then no need to fill the
		// buffer completely, only by the difference
		if (difference < bufferSize) {
			bufferSize = difference;
		}
		fileStream.seekg(filePointer);
		fileStream.read(buffer, bufferSize);
		for (int i = 0; i < bufferSize; i++) {
			// going over every byte in the file
			switch (mode) {
			case 0: // inversion
				buffer[i] = ~buffer[i];
				break;
			case 1: // cycle
				buffer[i] = cycle(buffer[i]);
				break;
			case 2: // RC4
				buffer[i] = buffer[i] ^ rc4_output();
				break;
			}
		}
		// setting writing pointer to the current location
		fileStream.seekp(filePointer);
		// writing the inverted file
		fileStream.write(buffer, bufferSize);
		// incrementing current file pointer by the amount of buffer
		filePointer += bufferSize;
		// adjusting interface
		float progress = (float)filePointer / (float)fileSize * 100.0f;
		/*cout << '\r';
		cout << "Completed: "
			<< (int)progress
			<< "%";*/
		return 0;
	} // closing the stream fileStream.close(); // resetting interface } //---------------------------------------------------------------------------
}
/*status: completed

* description:

* byte cycling algorithm

*/

char cycle(char value) {

	int leftMask = 170;

	int rightMask = 85;

	int iLeft = value & leftMask;

	int iRight = value & rightMask;

	iLeft = iLeft >> 1;
	iRight = iRight << 1;
	return iLeft | iRight;
}
// ---------------------------------------------------------------------------
/* status: completed
* description:
* RC4 stream initializer
*/
void rc4_init(unsigned char *key, unsigned int key_length) {
	for (i = 0; i < 0x100; i++)
		S[i] = i;
	for (i = j = 0; i < 0x100; i++) {
		unsigned char temp;
		j = (j + key[i % key_length] + S[i]) & 0xFF;
		temp = S[i];
		S[i] = S[j];
		S[j] = temp;
	}
	i = j = 0;
}
// ---------------------------------------------------------------------------
/* status: completed
* description:
* RC4 stream byte generator
*/
unsigned char rc4_output() {
	unsigned char temp;
	i = (i + 1) & 0xFF;
	j = (j + S[i]) & 0xFF;
	temp = S[i];
	S[i] = S[j];
	S[j] = temp;
	return S[(S[i] + S[j]) & 0xFF];
}
//---------------------------------------------------------------------------