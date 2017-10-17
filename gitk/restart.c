#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>

void IP(const u_char* packet)
{
	struct ip *ip;
	ip=(struct ip *)packet;//ip header//
        printf("src ip: %s\n",inet_ntoa(ip->ip_src));
        printf("dst ip: %s\n",inet_ntoa(ip->ip_dst));
}

void TCP(const u_char* packet)
{
	struct tcphdr *tcp;
	tcp = (struct tcphdr *)packet;//tcp header//
        printf("src port: %u\n",ntohs(tcp->source));
        printf("dst port: %u\n",ntohs(tcp->dest));
        printf("Data : ");
        for(int i=0;i<16;i++)
        {
        	printf("%02x",*(packet++));
        }
}

int main(int argc, char* argv[]) {
	char errbuf[PCAP_ERRBUF_SIZE];
	char *dev=pcap_lookupdev(errbuf);
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
  		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
  		return -1;
	}
	while (1) {	
		struct pcap_pkthdr *header;//packet pointer//
		struct ether_header *eth;//ethernet heade//
		struct ip *ip;//ip header//
		uint8_t *tcp_data;
		const u_char *packet;//packet//
		int res=pcap_next_ex(handle,&header,&packet);
		if(res==-1||res==-2) break;
		printf("=====================================================\n");
		printf("%ubyte packet captured\n",header->caplen);
		eth=(struct ether_header *)packet;//ethernet 
		eth->ether_type = ntohs(eth->ether_type);
		printf("%p\n", packet);
		printf("src mac: %x %x %x %x %x %x\n",eth->ether_shost[0],eth->ether_shost[1],eth->ether_shost[2],eth->ether_shost[3],eth->ether_shost[4],eth->ether_shost[5]);
		printf("dst mac: %x %x %x %x %x %x\n",eth->ether_dhost[0],eth->ether_dhost[1],eth->ether_dhost[2],eth->ether_dhost[3],eth->ether_dhost[4],eth->ether_dhost[5]);
		packet +=sizeof(struct ether_header);
		if(eth->ether_type==0x0800)
		{
			ip=(struct ip *)packet;//ip header//
			IP(packet);
			packet +=sizeof(struct ip);
			if(ip->ip_p==IPPROTO_TCP)
			{				
				TCP(packet);
			}
		}
		printf("\n=====================================================\n");
	}
	pcap_close(handle);
	return 0;
}
