#include <WinSock2.h>
#include <WS2tcpip.h>
#include <stdio.h>
#include <IPHlpApi.h>
#include <stdlib.h>
#include <math.h>
#include <intrin.h>
#include <Windows.h>

#define DEFAULT_PORT 50267
#define MAX_NICKNAME_LENGTH 50
#define ADDRESSES_SIZE 15360
#define MAX_MESSAGE_LENGTH 1024
#define SLEEP_TIME 5000

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

typedef struct SubnetworkInfo
{
	char *GatewayAddress;
	char *UnicastAddress;
	unsigned long Mask;
} SubnetworkInfo;

typedef struct UserInformation
{
	char *UserNickname;
	char *UserIPAddress;
	SOCKET Socket;
	struct UserInformation *Next;
} UserInformation;

typedef struct ThreadParameters
{
	HANDLE hMutex;
	UserInformation *Header;
	UserInformation *Current;
	sockaddr_in OwnAddress;
	char *OwnNickname;
	SOCKET UDPSocket;
} ThreadParameters;

char *GetGatewayAddress(PIP_ADAPTER_ADDRESSES pAddresses)
{
	PIP_ADAPTER_GATEWAY_ADDRESS_LH pGatewayAddress;
	char *GatewayAddressBuf = (char *)calloc(1, BUFSIZ);
	for (pGatewayAddress = pAddresses->FirstGatewayAddress; pGatewayAddress != NULL; pGatewayAddress = pGatewayAddress->Next)
	{
		if (pGatewayAddress->Address.lpSockaddr != NULL)
		{
			getnameinfo(pGatewayAddress->Address.lpSockaddr, pGatewayAddress->Address.iSockaddrLength, GatewayAddressBuf, BUFSIZ, NULL, 0, NI_NUMERICHOST);
			return GatewayAddressBuf;
		}
	}
	return NULL;
}

unsigned long ConvertLengthToMask(unsigned long Length)
{
	unsigned long Mask = 0;
	for (int i = 31; i > 31 - Length; i--)
	{
		Mask += (unsigned long)pow(2.0, i);
	}
	return Mask;
}

unsigned long GetSubnetMask(PIP_ADAPTER_ADDRESSES pAddresses, char *GatewayAddress, char **UnicastAddressBuf)
{
	PIP_ADAPTER_UNICAST_ADDRESS pUnicastAddress;
	*UnicastAddressBuf = (char *)calloc(1, BUFSIZ);
	unsigned long Mask;
	for (pUnicastAddress = pAddresses->FirstUnicastAddress; pUnicastAddress != NULL; pUnicastAddress = pUnicastAddress->Next)
	{
		getnameinfo(pUnicastAddress->Address.lpSockaddr, pUnicastAddress->Address.iSockaddrLength, *UnicastAddressBuf, BUFSIZ, NULL, 0, NI_NUMERICHOST);
		if (UnicastAddressBuf != NULL)
		{
			unsigned long Length = pUnicastAddress->OnLinkPrefixLength;
				Mask = ConvertLengthToMask(pUnicastAddress->OnLinkPrefixLength);
				if ((_byteswap_ulong(inet_addr(GatewayAddress)) & Mask) == (_byteswap_ulong(inet_addr(*UnicastAddressBuf)) & Mask))
				{
					return Mask;
				}
		}
	}
}

struct SubnetworkInfo *GetSubnetworkInfo()
{
	char *GatewayAddressBuf, *UniAddressBuf;
	unsigned long Mask; 
	struct SubnetworkInfo *Info = (struct SubnetworkInfo *)calloc(1, sizeof(struct SubnetworkInfo));
	unsigned long Size = ADDRESSES_SIZE;
	PIP_ADAPTER_ADDRESSES pAddresses = (IP_ADAPTER_ADDRESSES *)calloc(1,Size), pCurrentAddress;
	long ReturnValue;
	if ((ReturnValue = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS, NULL, pAddresses, &Size)) == NO_ERROR)
	{
		for (pCurrentAddress = pAddresses; pCurrentAddress != NULL; pCurrentAddress = pCurrentAddress->Next)
		{
			GatewayAddressBuf = GetGatewayAddress(pCurrentAddress);
			if (GatewayAddressBuf != NULL)
			{
				Mask = GetSubnetMask(pCurrentAddress, GatewayAddressBuf, &UniAddressBuf);
				Info->GatewayAddress = GatewayAddressBuf;
				Info->UnicastAddress = UniAddressBuf;
				Info->Mask = Mask;
				return Info;
			}
		}
	}
	else
	{
		printf("GetAdapterAddresses return error: %d", GetLastError());
		return NULL;
	}
}

UserInformation *AddToUserInformationList(SOCKET Socket, UserInformation *Header, char *Nick, char *IP)
{
	while (Header->Next != NULL)
		Header = Header->Next;
	Header->Next = (UserInformation *)calloc(1, sizeof(UserInformation));
	Header = Header->Next;
	Header->Next = NULL;
	Header->Socket = Socket;
	Header->UserNickname = (char *)calloc(1, strlen(Nick) + 1);
	strcpy_s(Header->UserNickname, strlen(Nick) + 1, Nick);
	Header->UserIPAddress = (char *)calloc(1, strlen(IP) + 1);
	strcpy_s(Header->UserIPAddress, strlen(IP) + 1, IP);
	return Header;
}

void RemoveFromUserInformationList(UserInformation *Header, SOCKET RemovedSocket)
{
	UserInformation *Current, *Prev;
	for (Current = Header; Current != NULL && Current->Socket != RemovedSocket; Current = Current->Next)
		Prev = Current;
		
	Prev->Next = Current->Next;
	shutdown(Current->Socket, SD_BOTH);
	closesocket(Current->Socket);
	free(Current);
}

UserInformation *FindUserInfoInList(UserInformation *Header, SOCKET TargetSocket)
{
	UserInformation *Current;
	for (Current = Header; Current != NULL; Current = Current->Next)
	{
		if (Current->Socket == TargetSocket)
			return Current;
	}
}

DWORD WINAPI UDPCheckThread(LPVOID lpParam)
{
	fd_set Temp;
	Temp.fd_count = 1;
	Temp.fd_array[0] = ((ThreadParameters *)lpParam)->UDPSocket;

	sockaddr_in TempAddr;
	char *AnotherUserName = (char *)calloc(1, MAX_NICKNAME_LENGTH);
	printf("Waiting\n");
	int Size = sizeof(sockaddr_in);
	while (int Ret = select(0, &Temp, NULL, NULL, NULL))
	{
		WaitForSingleObject(((ThreadParameters *)lpParam)->hMutex, INFINITE);
		if (Ret != SOCKET_ERROR)
		{
			recvfrom(((ThreadParameters *)lpParam)->UDPSocket, AnotherUserName, MAX_NICKNAME_LENGTH, 0, (sockaddr *)&TempAddr, &Size);
			((ThreadParameters *)lpParam)->Current = AddToUserInformationList(NULL, ((ThreadParameters *)lpParam)->Header, AnotherUserName, inet_ntoa(TempAddr.sin_addr)); 
			sendto(((ThreadParameters *)lpParam)->UDPSocket, ((ThreadParameters *)lpParam)->OwnNickname, strlen(((ThreadParameters *)lpParam)->OwnNickname), 0, (sockaddr *)&TempAddr, sizeof(TempAddr));
			memset(AnotherUserName, 0, MAX_NICKNAME_LENGTH);
		}
		else
		{
			printf("select : %d\n", WSAGetLastError());
			Sleep(SLEEP_TIME);
		}
		ReleaseMutex(((ThreadParameters *)lpParam)->hMutex);
	}
	return 0;
}

DWORD WINAPI RecoveringFromSocketThread(LPVOID lpParam)
{
	SOCKET RecvSocket = ((ThreadParameters *)lpParam)->Current->Socket;
	char *MessageBuf = (char *)calloc(1, MAX_MESSAGE_LENGTH);
	while (true)
	{
		printf("Waiting message\n");
		int Ret = recv(RecvSocket, MessageBuf, MAX_MESSAGE_LENGTH, 0);
		WaitForSingleObject(((ThreadParameters *)lpParam)->hMutex, INFINITE);
		UserInformation *Info = FindUserInfoInList(((ThreadParameters *)lpParam)->Header, RecvSocket);
		if (Ret != SOCKET_ERROR && Ret != 0)
		{
			SYSTEMTIME Time;
			GetLocalTime(&Time);
			printf("%s %s %d:%d:%d %s\n", Info->UserNickname, Info->UserIPAddress, Time.wHour, Time.wMinute, Time.wSecond, MessageBuf);
		}
		else
		{
			if (Ret == SOCKET_ERROR)
				printf("Error: %d", WSAGetLastError());
			else
				printf("%s %s Left chat\n", Info->UserNickname, Info->UserIPAddress);
			RemoveFromUserInformationList(((ThreadParameters *)lpParam)->Header, RecvSocket);
			ExitThread(0);
		}
		ReleaseMutex(((ThreadParameters *)lpParam)->hMutex);
	}
}

DWORD WINAPI TCPListeningThread(LPVOID lpParam)
{
	printf("Listening\n");

	SOCKET ListeningSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (bind(ListeningSocket, (sockaddr *)&((ThreadParameters *)lpParam)->OwnAddress, sizeof(sockaddr_in)) == SOCKET_ERROR)
	{
		printf("ListeningSocket: bind return error: %d\n", WSAGetLastError());
		Sleep(SLEEP_TIME);
		return 1;
	}

	if (listen(ListeningSocket, SOMAXCONN) == SOCKET_ERROR)
	{
		printf("ListeningSocket: listen return error: %d\n", WSAGetLastError());
		Sleep(SLEEP_TIME);
		return 1;
	}

	sockaddr_in AcceptAddress;
	int Size = sizeof(AcceptAddress);
	SOCKET AcceptSocket;
	while (AcceptSocket = accept(ListeningSocket, (sockaddr *)&AcceptAddress, &Size))
	{
		WaitForSingleObject(((ThreadParameters *)lpParam)->hMutex, INFINITE);
		UserInformation *Current;
		for (Current = ((ThreadParameters *)lpParam)->Header->Next; strcmp(Current->UserIPAddress, inet_ntoa(AcceptAddress.sin_addr)) ; Current = Current->Next);
		Current->Socket = AcceptSocket;

		CreateThread(NULL, 0, &RecoveringFromSocketThread, (ThreadParameters *)lpParam, 0, 0);
		ReleaseMutex(((ThreadParameters *)lpParam)->hMutex);
	}
	return 0;
}

void FreeUserInformation(UserInformation **Header)
{
	UserInformation *Current, *Prev;
	for (Current = (*Header)->Next; Current != NULL;)
	{
		Prev = Current;
		Current = Current->Next;
		if (shutdown(Prev->Socket, SD_BOTH) == SOCKET_ERROR)
			printf("TCPSocket: shutdown return error: %d\n", WSAGetLastError());
		if (closesocket(Prev->Socket) == SOCKET_ERROR)
			printf("TCPSocket: closesocket return error: %d\n", WSAGetLastError());
		free(Prev->UserNickname);
		free(Prev->UserIPAddress);
		free(Prev);
	}
	free(*Header);
}

int main(int argc, char **argv)
{
	WSADATA wsaDate;
	if (WSAStartup(MAKEWORD(2,2),&wsaDate))
	{
		printf("WSAStartup return error: %d\n", WSAGetLastError());
		Sleep(SLEEP_TIME);
		return 1;
	}

	char *UserNickname = (char *)calloc(1, MAX_NICKNAME_LENGTH);
	printf("Enter your nickname: ");
	scanf("%s", UserNickname);

	SOCKET BroadcastSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (BroadcastSocket == INVALID_SOCKET)
	{
		printf("BroadcastSocket: socket return error: %d\n", WSAGetLastError());
		Sleep(SLEEP_TIME);
		return 1;
	}

	bool BroadcastResolution = true;
	if (setsockopt(BroadcastSocket, SOL_SOCKET, SO_BROADCAST, (char *)&BroadcastResolution, sizeof(bool)) == SOCKET_ERROR)
	{
		printf("BroadcastSocket: socket return error: %d\n", WSAGetLastError());
		Sleep(SLEEP_TIME);
		return 1;
	}

	SubnetworkInfo *OwnSubnetwork;
	OwnSubnetwork = GetSubnetworkInfo();

	sockaddr_in OwnIPAddress;
	OwnIPAddress.sin_family = AF_INET;
	OwnIPAddress.sin_port = htons(DEFAULT_PORT);
	OwnIPAddress.sin_addr.s_addr = inet_addr(OwnSubnetwork->UnicastAddress);

	if (bind(BroadcastSocket, (sockaddr *)&OwnIPAddress, sizeof(OwnIPAddress)) == SOCKET_ERROR)
	{
		printf("BroadcastSocket: bind return error: %d\n", WSAGetLastError());
		Sleep(SLEEP_TIME);
		return 1;
	}
	
	sockaddr_in BroadcastAddress;
	BroadcastAddress.sin_family = AF_INET;
	BroadcastAddress.sin_port = htons(DEFAULT_PORT);
	BroadcastAddress.sin_addr.s_addr = OwnIPAddress.sin_addr.s_addr | _byteswap_ulong(~OwnSubnetwork->Mask);

	if (sendto(BroadcastSocket, UserNickname, strlen(UserNickname), 0, (sockaddr *)&BroadcastAddress, sizeof(BroadcastAddress)) == SOCKET_ERROR)
	{
		printf("BroadcastSocket: sendto return error: %d\n", WSAGetLastError());
		Sleep(SLEEP_TIME);
		return 1;
	}

	fd_set BroadcastSocketList;
	BroadcastSocketList.fd_count = 1;
	BroadcastSocketList.fd_array[0] = BroadcastSocket;

	TIMEVAL WaitingRecvTime;
	WaitingRecvTime.tv_sec = 5;
	WaitingRecvTime.tv_usec = 0;

	sockaddr_in RecvFromAddr;

	UserInformation *UsersListHeader = NULL, *UsersListCurrent = NULL;

	UsersListHeader = (UserInformation *)calloc(1, sizeof(UserInformation));
	UsersListCurrent = UsersListHeader;
	UsersListCurrent->Next = NULL;
	UsersListCurrent->UserIPAddress = NULL;
	UsersListCurrent->UserNickname = NULL;
	UsersListCurrent->Socket = NULL;

	int SizeOfsockaddr_in = sizeof(sockaddr_in);
	
	ThreadParameters *pThreadParam = (ThreadParameters *)calloc(1, sizeof(ThreadParameters));
	pThreadParam->hMutex = CreateMutex(NULL, false, NULL);
	pThreadParam->OwnAddress = OwnIPAddress;
	pThreadParam->Current = UsersListCurrent;
	pThreadParam->Header = UsersListHeader;
	pThreadParam->OwnNickname = UserNickname;
	pThreadParam->UDPSocket = BroadcastSocket;

	HANDLE hThreadArr[2];

	while (int Ret = select(0, &BroadcastSocketList, NULL, NULL, &WaitingRecvTime))
	{
		if (Ret != SOCKET_ERROR)
		{
			char *NicknameBuf = (char *)calloc(1, MAX_NICKNAME_LENGTH);
			if (recvfrom(BroadcastSocket, NicknameBuf, MAX_NICKNAME_LENGTH, 0, (sockaddr *)&RecvFromAddr, &SizeOfsockaddr_in) != SOCKET_ERROR)
			{
				if (RecvFromAddr.sin_addr.s_addr != OwnIPAddress.sin_addr.s_addr)
				{
					SOCKET TCPSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
					printf("Connecting...\n");
					if (connect(TCPSocket, (sockaddr *)&RecvFromAddr, sizeof(RecvFromAddr)) == SOCKET_ERROR)
						printf("TCPSocket connect return error: %d\n", WSAGetLastError());
					else
					{ 
						pThreadParam->Current = AddToUserInformationList(TCPSocket, UsersListHeader, NicknameBuf, inet_ntoa(RecvFromAddr.sin_addr)); 
						CreateThread(NULL, 0, &RecoveringFromSocketThread, pThreadParam, 0, 0);
					}
				}
			}
			else
				printf("BroadcastSocket: recvfrom return error: %d\n", WSAGetLastError());
		}
		else
			printf("BroadcastSocket: select return error: %d\n", WSAGetLastError());
	}   

	hThreadArr[0] = CreateThread(NULL, 0, UDPCheckThread, pThreadParam, 0, NULL);
	hThreadArr[1] = CreateThread(NULL, 0, TCPListeningThread, pThreadParam, 0, NULL);

	bool ContinueWork = true;

	while (ContinueWork)
	{
		char *MessageBuf = (char *)calloc(1, MAX_MESSAGE_LENGTH);
		do
		{
			gets_s(MessageBuf, MAX_MESSAGE_LENGTH);
		}
		while (strlen(MessageBuf) == 0);
		WaitForSingleObject(pThreadParam->hMutex, INFINITE);
		if (strcmp(MessageBuf, "PTPChat -Exit"))
		{
			UserInformation *Current;
			
			for (Current = UsersListHeader->Next; Current != NULL; Current = Current->Next)
				send(Current->Socket, MessageBuf, strlen(MessageBuf), 0);
		}
		else
			ContinueWork = false;
		memset(MessageBuf, 0, MAX_MESSAGE_LENGTH);
		ReleaseMutex(pThreadParam->hMutex);
	}
	WaitForSingleObject(pThreadParam->hMutex, INFINITE);
	TerminateThread(hThreadArr[0], 0);
	TerminateThread(hThreadArr[1], 0);
	CloseHandle(hThreadArr[0]);
	CloseHandle(hThreadArr[1]);
	FreeUserInformation(&UsersListHeader);

	if (closesocket(pThreadParam->UDPSocket) == SOCKET_ERROR)
	{
		printf("UDPSocket: closesocket return error: %d\n", WSAGetLastError());
	}
	

	if (WSACleanup() == SOCKET_ERROR)
	{
		printf("WSACleanup return error: %d\n", WSAGetLastError());
	}
	
	printf("End");
	return 0;
}