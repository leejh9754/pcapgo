

#include <pcap.h>

#include <stdio.h>

#include <stdint.h>

#include <libnet.h>

#include <arpa/inet.h>

 

void usage() {

	printf("syntax: pcap_test <interface>\n");

	printf("sample: pcap_test wlan0\n");

}

 

int main(int argc, char* argv[]) {

	if (argc != 2) {

		usage();

		return -1;

	}

 

	char* dev = argv[1];

	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL) {

		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);

		return -1;

	}

 

while(1)
{

		struct pcap_pkthdr* header;

		struct libnet_ethernet_hdr *eth;

		struct libnet_ipv4_hdr *iphdr;

		struct libnet_tcp_hdr *tcphdr;

		uint8_t *tcp_data;

		const u_char* packet;

		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0) continue;

		if (res == -1 || res == -2) break;

		printf("%u bytes captured\n", header->caplen);

		eth = (struct ether_header *)packet;

		eth->ether_type = ntohs(eth->ether_type);

		printf("ether_type : %x\n", eth->ether_type);

		printf("src mac : %x  :  %x  :  %x  :  %x  :  %x  :  %x\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);

		printf("dst mac : %x  :  %x  :  %x  :  %x  :  %x  :  %x\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

		packet = packet + sizeof(struct libnet_ethernet_hdr);
if(eth->ether_type)
{

			printf("src ip : %s\n", inet_ntoa(iphdr->ip_src));

			printf("dst ip : %s\n", inet_ntoa(iphdr->ip_dst));

			if (iphdr->ip_p == 6)

			{

				tcphdr = (struct libnet_tcp_hdr *)(packet + iphdr->ip_hl * 4);
printf("tcp src port : %d \n",ntohs(tcphdr->src_port));
printf("tcp dst port : %d \n",ntohs(tcphdr->dest_port));
uint32_t tcp_length = iphdr->ip_len - iphdr->ip_hl * 4;

				uint32_t tcp_data_len = tcp_length - tcphdr->th_off * 4;

				if (tcp_data_len)

				{

					tcp_data = (uint8_t *)tcphdr + tcphdr->th_off * 4;

					if (tcp_data_len >= 16)

					{

						tcp_data_len = 16;

					}

					printf("data 16byte까지 : ");

					for (int i = 0; i < tcp_data_len; i++)

					{

						printf(" %x ", tcp_data[i]);

					}

					printf("\n");

				}

			}

		}

	}

 

	pcap_close(handle);

	return 0;

}


