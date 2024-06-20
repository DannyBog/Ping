#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <stdint.h>
#include <stdbool.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#define MAX_COMMAND_LINE_ARGS 8192 // https://devblogs.microsoft.com/oldnewthing/20031210-00/?p=41553
#define MAX_IP_PACKET UINT16_MAX // (theoretical) max IP packet size

typedef struct {
	uint32_t bAddrSrc, bAddrDest;
	char sAddrSrc[INET_ADDRSTRLEN], sAddrDest[INET_ADDRSTRLEN];
} ip_address;

typedef struct {
	uint32_t num, timeout;
	uint16_t size;
	uint8_t ttl;
	
	uint32_t sent, received, lost;
	uint32_t min, max, avg;
} ip_packet;

static ip_address ip;
static ip_packet packet;
static bool flood, resolve, resolved, source, success;

static void Print(char *msg, ...) {
	va_list args;
	va_start(args, msg);

	char buffer[1024];
	DWORD length = wvsprintf(buffer, msg, args);

	DWORD written;
	WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buffer, length, &written, 0);

	va_end(args);
}

static void PrintUsage() {
	Print("Usage: ping [-t] [-a] [-n count] [-l size] [-i TTL] [-w timeout] [-S srcaddr]"
		  " target_name\n\n");
	Print("Options:\n");
	Print("    -t         Ping the specified host until stopped.\n");
	Print("               To see statistics and continue - type Control-Break;\n");
	Print("               To stop - type Control-C.\n");
	Print("    -a         Resolve addresses to hostnames.\n");
	Print("    -n count   Number of echo requests to send.\n");
	Print("    -l size    Send buffer size.\n");
	Print("    -i TTL     Time To Live.\n");
	Print("    -w timeout Timeout in milliseconds to wait for each reply.\n");
	Print("    -S srcaddr Source address to use.\n");
}

static bool IsDigit(char c) {
	return (c >= '0' && c <= '9');
}

static bool IsNumber(char *s) {
	char *temp = s;
	if (temp[0] == '-' && temp[1]) temp++;
	while (*temp && IsDigit(*temp)) temp++;
	return !*temp;
}

static int32_t StringToInt(char *s) {
	char *temp = s;
	int32_t result = 0;
	int8_t sign = 1;
	
	if (*s == '-') {
		sign = -1;
		*s++;
	}
	
	while (*temp && IsNumber(s)) result = 10 * result + (*temp++ - '0');
	
	return sign * result;
}

static bool ValidateArgs(int argc, char **argv) {
	bool result = false;
	
	packet.num = 4;
	packet.size = 32;
	packet.timeout = 4000;
	
	if (argc < 2) {
		PrintUsage();
		return result;
	}
	
	for (size_t i = 1; i < argc; ++i) {
		if ((argv[i][0] == '-') || (argv[i][0] == '/')) {
			switch (argv[i][1]) {
				case 'a': {
					resolve = true;
				} break;
				
				case 't': {
					flood = true;
				} break;
				
				case 'n': {
					if ((i + 1 < argc) && IsDigit(argv[i + 1][0])) {
						packet.num = StringToInt(argv[i++ + 1]);
					} else {
						Print("Value must be supplied for option -n.\n");
						return result;
					}
				} break;
				
				case 'l': {
					if ((i + 1 < argc) && IsDigit(argv[i + 1][0])) {
						int32_t size = StringToInt(argv[i++ + 1]);
						if (size >= 0 && size <= 65500) {
							packet.size = (uint16_t) size;
						} else {
							Print("Bad value for option -l, valid range is from 0 to 65500.\n");
							return result;
						}
					} else {
						Print("Value must be supplied for option -l.\n");
						return result;
					}
				} break;
				
				case 'i': {
					if ((i + 1 < argc) && IsDigit(argv[i + 1][0])) {
						int32_t ttl = StringToInt(argv[i++ + 1]);
						if (ttl >= 1 && ttl <= 255) {
							packet.ttl = (uint8_t) ttl;
						} else {
							Print("Bad value for option -i, valid range is from 1 to 255.\n");
							return result;
						}
					} else {
						Print("Value must be supplied for option -i.\n");
						return result;
					}
				} break;
				
				case 'w': {
					if ((i + 1 < argc) && IsDigit(argv[i + 1][0])) {
						int32_t timeout = StringToInt(argv[i++ + 1]);
						packet.timeout = (uint32_t) timeout;
					} else {
						Print("Value must be supplied for option -w.\n");
						return result;
					}
				} break;
				
				case 'S': {
					if (i + 1 < argc) {
						if (!InetPton(AF_INET, argv[i++ + 1], &ip.bAddrSrc)) {
							Print("%s is not a valid address.\n", argv[i]);
							return result;
						}
						
						source = true;
					} else {
						Print("Value must be supplied for option -S.\n");
						return result;
					}
				} break;
				
				default: {
					PrintUsage();
					return result;
				}
			}
			
			result = true;
		} else if (IsDigit(argv[i][0])) {
			if (!InetPton(AF_INET, argv[i], &ip.bAddrDest)) {
				Print("IP address must be specified.\n");
				return result;
			}
			
			result = true;
		} else {
			resolved = true;
			
			struct addrinfo hints = {0};
			hints.ai_family = AF_INET;
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_protocol = IPPROTO_TCP;
			
			struct addrinfo *addr;
			DWORD dwRetval = GetAddrInfo(argv[i], 0, &hints, &addr);
			if (dwRetval != 0) {
				Print("Ping request could not find host %s. Please check the name and try again.\n",
					   argv[i]);
				return result;
			}
			
			while (addr) {
				switch (addr->ai_family) {
					case AF_INET: {
						struct sockaddr_in *sockaddr_ipv4 = (struct sockaddr_in *) addr->ai_addr;
						
						ip.bAddrDest = sockaddr_ipv4->sin_addr.S_un.S_addr;
						
						size_t index = 0;
						while (argv[i][index]) {
							ip.sAddrDest[index] = argv[i][index];
							++index;
						}
					} break;
				}
				
				addr = addr->ai_next;
			}
			
			result = true;
		}
	}
	
	return result;
}

static void Ping(HANDLE hIcmpFile, char *payload, uint16_t payloadSize, void *replyBuffer,
				 DWORD replySize) {
	DWORD dwRetVal = 0;
	
	if (source) {
		if (packet.ttl) {
			IP_OPTION_INFORMATION ioi = {0};
			ioi.Ttl = packet.ttl;
			dwRetVal = IcmpSendEcho2Ex(hIcmpFile, 0, 0, 0, ip.bAddrSrc, ip.bAddrDest, payload,
									   payloadSize, &ioi, replyBuffer, replySize, packet.timeout);
		} else {
			dwRetVal = IcmpSendEcho2Ex(hIcmpFile, 0, 0, 0, ip.bAddrSrc, ip.bAddrDest, payload,
									   payloadSize, 0, replyBuffer, replySize, packet.timeout);
		}
	} else {
		if (packet.ttl) {
			IP_OPTION_INFORMATION ioi = {0};
			ioi.Ttl = packet.ttl;
			dwRetVal = IcmpSendEcho(hIcmpFile, ip.bAddrDest, payload, payloadSize, &ioi, replyBuffer,
									replySize, packet.timeout);
		} else {
			dwRetVal = IcmpSendEcho(hIcmpFile, ip.bAddrDest, payload, payloadSize, 0, replyBuffer,
									replySize, packet.timeout);
		}
	}
	
	packet.sent++;
	
	PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY) replyBuffer;
	if (dwRetVal || pEchoReply->Status)  {
		switch (pEchoReply->Status) {
			case IP_SUCCESS: {
				packet.received++;
				success = true;
				InetNtop(AF_INET, &pEchoReply->Address, ip.sAddrDest, INET_ADDRSTRLEN);
			
				if (pEchoReply->DataSize != packet.size) {
					if (pEchoReply->RoundTripTime >= 1) {
						Print("Reply from %s: bytes=%d (sent %d) time=%dms TTL=%d\n", ip.sAddrDest,
							  pEchoReply->DataSize, packet.size, pEchoReply->RoundTripTime,
							  pEchoReply->Options.Ttl);
					} else {
						Print("Reply from %s: bytes=%d (sent %d) time<%dms TTL=%d\n", ip.sAddrDest,
							  pEchoReply->DataSize, packet.size, 1, pEchoReply->Options.Ttl);
					}
				} else {
					if (pEchoReply->RoundTripTime >= 1) {
						Print("Reply from %s: bytes=%d time=%dms TTL=%d\n", ip.sAddrDest, packet.size,
							  pEchoReply->RoundTripTime, pEchoReply->Options.Ttl);
					} else {
						Print("Reply from %s: bytes=%d time<%dms TTL=%d\n", ip.sAddrDest, packet.size,
							  1, pEchoReply->Options.Ttl);
					}
				}
			
				if (!packet.avg) packet.min = packet.max = pEchoReply->RoundTripTime;
				if (pEchoReply->RoundTripTime < packet.min) packet.min = pEchoReply->RoundTripTime;
				if (pEchoReply->RoundTripTime > packet.max) packet.max = pEchoReply->RoundTripTime;
			
				packet.avg += pEchoReply->RoundTripTime;
			} break;
		
			case IP_REQ_TIMED_OUT: {
				packet.lost++;
				Print("Request timed out.\n");
			} break;
		
			case IP_DEST_HOST_UNREACHABLE: {
				packet.received++;
				InetNtop(AF_INET, &pEchoReply->Address, ip.sAddrDest, INET_ADDRSTRLEN);
				Print("Reply from %s: Destination host unreachable.\n", ip.sAddrDest);
			} break;
		
			case IP_TTL_EXPIRED_TRANSIT: {
				packet.received++;
				InetNtop(AF_INET, &pEchoReply->Address, ip.sAddrDest, INET_ADDRSTRLEN);
				Print("Reply from %s: TTL expired in transit.\n", ip.sAddrDest);
			} break;
		
			case IP_GENERAL_FAILURE: {
				packet.lost++;
				Print("General failure.\n");
			} break;
		}
	} else {
		packet.lost++;
		Print("PING: transmit failed. General failure.\n");
	}
	
	Sleep(1000);
}

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) {
	bool result = false;
	
	switch (fdwCtrlType) {
		case CTRL_C_EVENT: {
			Print("\nPing statistics for %s:\n", ip.sAddrDest);
			Print("    Packets: Sent = %d, Received = %d, Lost = %d (%d%% loss)\n", packet.sent,
				   packet.received, packet.lost,
				   (uint32_t) (((packet.sent - packet.received) / (float) packet.sent) * 100.0f));
			
			if (success) {
				Print("Approximate round trip times in milli-seconds:\n");
				Print("    Minimum = %dms, Maximum = %dms, Average = %dms\n", packet.min, packet.max,
					   (uint32_t) (packet.avg / packet.received));
			}
			
			result = false;
		} break;
		
		case CTRL_BREAK_EVENT: {
			Print("\nPing statistics for %s:\n", ip.sAddrDest);
			Print("    Packets: Sent = %d, Received = %d, Lost = %d (%d%% loss)\n", packet.sent,
				   packet.received, packet.lost,
				   (uint32_t) (((packet.sent - packet.received) / (float) packet.sent) * 100.0f));
			
			if (packet.received) {
				Print("Approximate round trip times in milli-seconds:\n");
				Print("    Minimum = %dms, Maximum = %dms, Average = %dms\n\n", packet.min, packet.max,
					   (uint32_t) (packet.avg / packet.received));
			}
			
			result = true;
		} break;
	}
	
	return result;
}

static void CommandLineToArgv(int *argc, char ***argv) {
	// Get the command line arguments as wchar_t strings
	wchar_t **wargv = CommandLineToArgvW(GetCommandLineW(), argc);
	if (!wargv) {
		*argc = 0;
		*argv = 0;
		return;
	}
	
	int32_t bytes = 0;
	for (size_t i = 0; i < *argc; ++i) {
		bytes += WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, 0, 0, 0, 0) + 1;
	}
	
	// Convert all wargv[] to argv[]
	char *arg = (char *) &((*argv)[*argc + 1]);
	for (size_t i = 0; i < *argc; ++i) {
		(*argv)[i] = arg;
		arg += WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, arg, bytes, 0, 0) + 1;
	}
	
	(*argv)[*argc] = '\0';
	LocalFree(argv);
}

#ifdef _DEBUG
int main(int argc, char **argv) {
#else
void mainCRTStartup() {
	int argc;
	char **argv;
	char *argv_storage[MAX_COMMAND_LINE_ARGS];
	argv = (char **) argv_storage;
	CommandLineToArgv(&argc, &argv);
#endif
	SetConsoleCtrlHandler(CtrlHandler, true);
	
	WSADATA wsaData = {0};
	int32_t iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		Print("WSAStartup failed: %d\n", iResult);
		ExitProcess(1);
	}
	
	if (!ValidateArgs(argc, argv)) ExitProcess(1);
	
	HANDLE hIcmpFile  = IcmpCreateFile();
	if (hIcmpFile == INVALID_HANDLE_VALUE) {
		Print("\tUnable to open handle.\n");
		Print("IcmpCreatefile returned error: %ld\n", GetLastError());
		ExitProcess(1);
	}    
	
	char alphabet[33] = "abcdefghijklmnopqrstuvwabcdefghi";
	char payload[MAX_IP_PACKET];
	for (size_t i = 0; i < packet.size; ++i) {
		payload[i] = alphabet[i % 32];
	}
	
	uint32_t replySize = sizeof(ICMP_ECHO_REPLY) + packet.size + 8;
	void *replyBuffer[MAX_IP_PACKET];
	
	if (resolved) {
		char hostname[NI_MAXHOST] = {0};
		
		size_t index = 0;
		while (ip.sAddrDest[index]) hostname[index] = ip.sAddrDest[index++];
		
		InetNtop(AF_INET, &ip.bAddrDest, ip.sAddrDest, INET_ADDRSTRLEN);
		if (source) {
			InetNtop(AF_INET, &ip.bAddrSrc, ip.sAddrSrc, INET_ADDRSTRLEN);
			Print("\nPinging %s [%s] from %s with %d bytes of data:\n", hostname, ip.sAddrDest,
				  ip.sAddrSrc, packet.size);
		} else {
			Print("\nPinging %s [%s] with %d bytes of data:\n", hostname, ip.sAddrDest, packet.size);
		}
	} else if (resolve) {
		struct sockaddr_in saGNI;
		saGNI.sin_family = AF_INET;
		saGNI.sin_addr.s_addr = ip.bAddrDest;
		char hostname[NI_MAXHOST];
		DWORD dwRetVal = GetNameInfo((struct sockaddr *) &saGNI, sizeof(struct sockaddr), hostname,
									 NI_MAXHOST, 0, 0, 0);
		
		if (dwRetVal != 0) {
			Print("getnameinfo failed with error # %ld\n", WSAGetLastError());
			ExitProcess(1);
		}
		
		InetNtop(AF_INET, &ip.bAddrDest, ip.sAddrDest, INET_ADDRSTRLEN);
		if (source) {
			InetNtop(AF_INET, &ip.bAddrSrc, ip.sAddrSrc, INET_ADDRSTRLEN);
			
			if (!IsDigit(*hostname)) {
				Print("\nPinging %s [%s] from %s with %d bytes of data:\n", hostname, ip.sAddrDest,
					  ip.sAddrSrc, packet.size);
			} else {
				Print("\nPinging %s from %s with %d bytes of data:\n", ip.sAddrDest, ip.sAddrSrc,
					  packet.size);
			}
		} else {
			if (!IsDigit(*hostname)) {
				Print("\nPinging %s [%s] with %d bytes of data:\n", hostname, ip.sAddrDest,
					  packet.size);
			} else {
				Print("\nPinging %s with %d bytes of data:\n", ip.sAddrDest, packet.size);
			}
		}
	} else {
		InetNtop(AF_INET, &ip.bAddrDest, ip.sAddrDest, INET_ADDRSTRLEN);
		
		if (source) {
			InetNtop(AF_INET, &ip.bAddrSrc, ip.sAddrSrc, INET_ADDRSTRLEN);
			
			Print("\nPinging %s from %s with %d bytes of data:\n", ip.sAddrDest, ip.sAddrSrc,
					  packet.size);
		} else {
			Print("\nPinging %s with %d bytes of data:\n", ip.sAddrDest, packet.size);
		}
	}
	
	if (flood) {
		while (true) {
			Ping(hIcmpFile, payload, packet.size, replyBuffer, replySize);
		}
	} else {
		for (size_t i = 0; i < packet.num; ++i) {
			Ping(hIcmpFile, payload, packet.size, replyBuffer, replySize);
		}
	}
	
	Print("\nPing statistics for %s:\n", ip.sAddrDest);
	Print("    Packets: Sent = %d, Received = %d, Lost = %d (%d%% loss)\n", packet.sent,
		   packet.received, packet.lost,
		   (uint32_t) (((packet.sent - packet.received) / (float) packet.sent) * 100.0f));
    
	if (success) {
		Print("Approximate round trip times in milli-seconds:\n");
		Print("    Minimum = %dms, Maximum = %dms, Average = %dms\n", packet.min, packet.max,
			   (uint32_t) (packet.avg / packet.received));
	}
	
	IcmpCloseHandle(hIcmpFile);
	WSACleanup();
	
	ExitProcess(0);
}
