/*
 * 참고 코드
 * https://github.com/YOONSEOYUL/yulshark_rawsocket.git
 *
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define BUFFER_SIZE 65536

#define ICMP 1
#define TCP 6
#define UDP 17

#define LOG_HTTP 0
#define LOG_DNS 1
#define LOG_ICMP 2

FILE* logfile[3];
int sock_raw;
struct sockaddr_in source, dest;
int myflag = 0;

int count_http = 0;
int count_dns = 0;
int count_icmp = 0;

void ProcessPacket(unsigned char* buffer, int size, char* pip_so);
void LogHttpPacket(unsigned char* buffer, int size, char* pip_so);
void LogIcmpPacket(unsigned char* buffer, int size, char* pip_so);
void LogDnsPacket(unsigned char* buffer, int size, char* pip_so);
void LogIpHeader(unsigned char* buffer, int size, char* pip_so, int pType, int psrc, int pdst);
void LogData(unsigned char* buffer, int size, int pType);

//패킷 캡쳐 함수 선언은 이곳에

void ProcessPacket(unsigned char* buffer, int size, char* pip_so)
{
	struct iphdr* iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));

	// 1 -> ICMP
	// 6 -> tcp
	// 17 -> udp
	switch (iph->protocol)
	{
	case ICMP:
		LogIcmpPacket(buffer, size, pip_so);
		break;
	case TCP: //http, dns(512바이트 넘는 경우 tcp로 전송됨)
		LogHttpPacket(buffer, size, pip_so);
		break;
	case UDP: // dns(보통의 dns)
		LogDnsPacket(buffer, size, pip_so);
		break;
	}

}

//http 패킷 캡쳐 함수(예.)
//각 프로토콜 함수 마다 추가해야되는 기능
// - 패킷이 해당 프로토콜을 확인하는 기능.
// - 패킷을 분석하는 기능
// ㄴ (ex) 000.000.000.000 (포트번호) 에서 000.000.000.000(포트번호)로 어떤 메세지를 보냄.
void LogHttpPacket(unsigned char* buffer, int size, char* pip_so)
{
	//공통적으로 추가해야되는 기능
	FILE* log = logfile[LOG_HTTP];
	int type = LOG_HTTP;

	unsigned short iphdrlen;

	struct iphdr* iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	struct tcphdr* tcph = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));

	int header_size = sizeof(struct ethhdr) + iphdrlen + tcph->doff * 4;
	int src = ntohs(tcph->source);
	int dst = ntohs(tcph->dest);

	//아래 부터는 프로토콜따라 달라짐.
	if (80 == src || 80 == dst)
	{

		fprintf(log, "\n\n- - - - - - - - - - - HTTP Packet - - - - - - - - - - - - \n");
		count_http++;
		

		fprintf(log, "\n");
		fprintf(log, "IP Header\n");
		LogIpHeader(buffer, size, pip_so, type, src, dst);
		fprintf(log, " + Source Port          : %u\n", ntohs(tcph->source));
		fprintf(log, " | Destination Port     : %u\n", ntohs(tcph->dest));
		fprintf(log, " | Sequence Number      : %u\n", ntohl(tcph->seq));
		fprintf(log, " | Acknowledge Number   : %u\n", ntohl(tcph->ack_seq));
		fprintf(log, " | Header Length        : %d BYTES\n", (unsigned int)tcph->doff * 4);
		fprintf(log, " | Acknowledgement Flag : %d\n", (unsigned int)tcph->ack);
		fprintf(log, " | Finish Flag          : %d\n", (unsigned int)tcph->fin);
		fprintf(log, " + Checksum             : %d\n", ntohs(tcph->check));
		fprintf(log, "\n");

		LogData(buffer, size, type);
	}
}

void LogIcmpPacket(unsigned char* buffer, int size, char* pip_so)
{

	FILE* log = logfile[LOG_ICMP];
	int type = LOG_ICMP;
	unsigned short iphdrlen;
	struct iphdr* iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	struct icmphdr* icmph = (struct icmphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
	int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
	count_icmp++;

	fprintf(log, "\n\n- - - - - - - - - - - ICMP Packet - - - - - - - - - - - - \n");
	fprintf(log, "\n");
	fprintf(log, "ICMP Header\n");
	fprintf(log, "   |-Type : %d", (unsigned int)(icmph->type));

	if ((unsigned int)(icmph->type) == 11)
	{
		fprintf(log, "  (데이터그램 시간초과(TTL 초과))\n");
	}
	else if ((unsigned int)(icmph->type) == 0)
	{
		fprintf(log, "  (icmp 요청에 대한 icmp 응답)\n");
	}
	else if ((unsigned int)(icmph->type) == 3)
	{
		fprintf(log, "  (수신지까지 메시지가 도착할수 없음)\n");
	}
	else if ((unsigned int)(icmph->type) == 4)
	{
		fprintf(log, "  (송신지 억제)\n");
	}
	else if ((unsigned int)(icmph->type) == 5)
	{
		fprintf(log, "  (재지시)\n");
	}
	else if ((unsigned int)(icmph->type) == 8)
	{
		fprintf(log, "  (목적지 호스트에 ICMP 응답을 요청)\n");
	}
	else if ((unsigned int)(icmph->type) == 12)
	{
		fprintf(log, "  (데이터그램에서의 파라메타 문제)\n");
	}
	else if ((unsigned int)(icmph->type) == 13)
	{
		fprintf(log, "  (시간기록요청)\n");
	}
	else if ((unsigned int)(icmph->type) == 14)
	{
		fprintf(log, "  (시간기록응답)\n");
	}

	fprintf(log, "   |-Code : %d\n", (unsigned int)(icmph->code));
	fprintf(log, "   |-Checksum : %d\n", ntohs(icmph->checksum));
	fprintf(log, "   |-ID       : %d\n", (unsigned int)getpid());
	//fprintf(log, "   |-Sequence : %d\n", (unsigned int)(icmp_seq));
	fprintf(log, "\n");

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	fprintf(log, "IP Header\n");
	fprintf(log, "   |-IP Version        : %d\n", (unsigned int)iph->version);
	fprintf(log, "   |-IP Header Length  : %d DWORDS or %d Bytes\n", (unsigned int)iph->ihl, ((unsigned int)(iph->ihl)) * 4);
	fprintf(log, "   |-Type Of Service   : %d\n", (unsigned int)iph->tos);
	fprintf(log, "   |-IP Total Length   : %d  Bytes(Size of Packet)\n", ntohs(iph->tot_len));
	fprintf(log, "   |-Identification    : %d\n", ntohs(iph->id));
	fprintf(log, "   |-TTL      : %d\n", (unsigned int)iph->ttl);
	fprintf(log, "   |-Protocol : %d\n", (unsigned int)iph->protocol);
	fprintf(log, "   |-Checksum : %d\n", ntohs(iph->check));

	fprintf(log, "\n");
	LogData(buffer, size, type);
}

void LogDnsPacket(unsigned char* buffer, int size, char* pip_so)
{

	FILE* log = logfile[LOG_DNS];
	int type = LOG_DNS;
	unsigned short iphdrlen;
	struct iphdr* iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;
	struct udphdr* udph = (struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
	int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof udph;
	int i, j;
	int src = ntohs(udph->source);
	int dst = ntohs(udph->dest);
	if ((53 == src || (53 == dst)))
	{
		count_dns++;
		fprintf(log, "\n\n- - - - - - - - - - - - DNS Packet - - - - - - - - - - - - \n");
		fprintf(log, "\nUDP Header\n");
		LogIpHeader(buffer, size, pip_so, type, src, dst);
		fprintf(log, "\n");
		fprintf(log, "IP Header\n");

		memset(&source, 0, sizeof(source));
		iph->saddr = inet_addr(pip_so);
		source.sin_addr.s_addr = iph->saddr; //ip를 받아온다.
		memset(&dest, 0, sizeof(dest));
		dest.sin_addr.s_addr = iph->daddr;

		fprintf(log, " + IP Version          : %d\n", (unsigned int)iph->version);
		fprintf(log, " | IP Header Length    : %d Bytes\n", ((unsigned int)(iph->ihl)) * 4);
		fprintf(log, " | Type Of Service     : %d\n", (unsigned int)iph->tos);
		fprintf(log, " | IP Total Length     : %d  Bytes (FULL SIZE)\n", ntohs(iph->tot_len));
		fprintf(log, " | TTL                 : %d\n", (unsigned int)iph->ttl);
		fprintf(log, " | Protocol            : %d\n", (unsigned int)iph->protocol);
		fprintf(log, " | Checksum            : %d\n", ntohs(iph->check));
		fprintf(log, " | Source IP           : %s\n", inet_ntoa(source.sin_addr));
		fprintf(log, " + Destination IP      : %s\n", inet_ntoa(dest.sin_addr));
		fprintf(log, "Data Payload\n");
		LogData(buffer, size, type);
	}
	
}

//헤더 로그하는 함수
void LogIpHeader(unsigned char* buffer, int size, char* pip_so, int pType, int psrc, int pdst)
{
	FILE* log = logfile[pType];
	unsigned short iphdrlen;

	struct iphdr* iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	memset(&source, 0, sizeof(source));

	iph->saddr = inet_addr(pip_so);
	source.sin_addr.s_addr = iph->saddr; //ip를 받아온다.

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	char src[30];
	char dst[30];

	strcpy(src, inet_ntoa(source.sin_addr));
	strcpy(dst, inet_ntoa(dest.sin_addr));
	if (pType == LOG_ICMP)
	{
		printf("%s -> %s \n", src, dst);
		fprintf(log, " | Source IP           : %s\n", src);
		fprintf(log, " + Destination IP      : %s\n", dst);
	}
	else
	{
		printf("%s (%d) -> %s (%d)\n", src, psrc, dst, pdst);
		fprintf(log, " | Source IP           : %s\n", src);
		fprintf(log, " | Source Port         : %d\n", psrc);
		fprintf(log, " | Destination IP      : %s\n", dst);
		fprintf(log, " | Destination Port    : %d\n", pdst);
	}
	LogData(buffer, size, pType);
}

void LogData(unsigned char* buffer, int size, int pType)
{
	FILE* log = logfile[pType];
	fprintf(log, "Data Payload\n");
	int i, j;
	for (i = 0; i < size; i++)
	{
		if (i != 0 && i % 16 == 0)
		{
			for (j = i - 16; j < i; j++)
			{
				if (buffer[j] >= 32 && buffer[j] <= 128)
				{
					fprintf(log, " %c", (unsigned char)buffer[j]);
				}
				else
				{
					fprintf(log, " *");
				}
			}
			fprintf(log, "\t\n");
		}
		if (i % 16 == 0)
		{
			fprintf(log, " ");
		}
		fprintf(log, " %02X", (unsigned int)buffer[i]);

		if (i == size - 1)
		{
			for (j = 0; j < 15 - i % 16; j++)
			{
				fprintf(log, "  ");
			}
			for (j = i - i % 16; j <= i; j++)
			{
				if (buffer[j] >= 32 && buffer[j] <= 128)
				{
					fprintf(log, " %c", (unsigned char)buffer[j]);
				}
				else
				{
					fprintf(log, " *");
				}
			}
			fprintf(log, "\n");
		}
	}
	fprintf(log, "\n- - - - - - - - - - - - - - - - - - - - - - - - \n ");
}

int main(int argc, char* argv[])
{
	char ip_source[18];
	char* pip_so = ip_source;

	strcpy(ip_source, argv[1]);

	socklen_t saddr_size;
	int data_size;
	struct sockaddr saddr;
	struct in_addr in;

	unsigned char* buffer = (unsigned char*)malloc(BUFFER_SIZE);

	logfile[LOG_HTTP] = fopen("log_http.txt", "w");
	logfile[LOG_DNS] = fopen("log_dns.txt", "w");
	logfile[LOG_ICMP] = fopen("log_icmp.txt", "w");

	for (int i = 0; i < 3; i++)
	{
		if (logfile[i] == NULL)
		{
			printf("fail to create log files\n");
			return -1;
		}
	}

	//create socket
	sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock_raw < 0)
	{
		printf("소켓  초기화 실패\n");
		return -1;
	}

	while (1)
	{
		saddr_size = sizeof saddr;

		data_size = recvfrom(sock_raw, buffer, BUFFER_SIZE, 0, &saddr, &saddr_size);
		if (data_size < 0)
		{
			printf("리턴값0보다 작은 에러");
			return 1;
		}
		printf("+------ 캡처 프로그램 시작-------+\n");
		printf("| 캡처하는 ip:   %s\n", ip_source);
		printf("+--------------------------------+\n");
		printf("captured packet - HTTP : %d ICMP : %d DNS : %d \n", count_http, count_icmp, count_dns);
		ProcessPacket(buffer, data_size, pip_so);
		printf("\033[2J");
	}

	close(sock_raw);

	return 0;
}
