#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <stdlib.h>
#define HTTP_PORT 80

struct ethheader{
	u_char ether_dhost[6];
	u_char ether_shost[6];
	u_short ether_type;
};

struct ipheader{
	unsigned char      iph_ihl:4,
					   iph_ver:4;
	unsigned char      iph_tos;
	unsigned short int iph_ident;
	unsigned short int iph_len;
	unsigned short int iph_flag:3,
				       iph_offset:13;
	unsigned char      iph_ttl;
	unsigned char      iph_protocol;
	unsigned short int iph_chksum;
	struct  in_addr    iph_sourceip;
	struct  in_addr    iph_destip;
};

struct tcpheader{
	u_short tcp_sport;
	u_short tcp_dport;
	u_int   tcp_seq;
	u_int   tcp_ack;
	u_char  tcp_offx2;
	u_char  tcp_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS    (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short tcp_win;
	u_short tcp_sum;
	u_short tcp_urp;
};

void packet_capture(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	struct ethheader *eth = (struct ethheader *)packet;
	struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
	struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) +(ip->iph_ihl * 4));

	printf("source MAC: %s\n", ether_ntoa((struct ether_addr *)eth->ether_shost));
	printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *)eth->ether_dhost));
	
	printf("Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
	printf("Destination IP: %s\n", inet_ntoa(ip->iph_destip));
	
	printf("Source Port: %d\n", ntohs(tcp->tcp_sport));
	printf("Destination port: %d\n", ntohs(tcp->tcp_dport));

	if(ntohs(tcp->tcp_dport) == HTTP_PORT || ntohs(tcp->tcp_sport) == HTTP_PORT){
		int ip_header_size = ip->iph_ihl * 4;
		int tcp_header_size = (tcp->tcp_offx2 >> 4)*4;
		int total_header_size = sizeof(struct ethheader) + ip_header_size + tcp_header_size;
		int payload_size = header->caplen - total_header_size;

		if(payload_size > 0){
			const u_char *payload = packet + total_header_size;
			printf("HTTP message:");
		    for(int i=0;i<payload_size;i++){
			    if(payload[i] >= 32 && payload[i] <=126){
					printf("%c", payload[i]);
				}
				else{
				    printf("  ");
				}
	       	}
			printf("\n");
		}
	}
    printf("\n");
}

int main(){
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];

	handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("pcap_open_live() failed: %s\n", errbuf);
        return 1;
    }
	pcap_loop(handle, 0, packet_capture, NULL);

	pcap_close(handle);

	return 0;
}

