#include<pcap.h>
#include<stdlib.h>
#include<time.h>
#include<ctype.h>
#include<netinet/if_ether.h>
#include<net/if_arp.h>
#include<netinet/ether.h>
#include<netinet/in.h>
#include<netinet/ip.h>
#include<stdint.h>
#include<string.h>
#include<arpa/inet.h>

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};


struct udp_hdr {
	u_short sport;
	u_short dport;
	u_short data_len;
	u_short checksum;
};

#define SIZE_ETHERNET 14
#define UDP_HEADER_SIZE 8
#define ICMP_HEADER_SIZE 8
#define ARP_REQUEST 1
#define ARP_REPLY 2     
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806

void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;
}

void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(payload, len, 0);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		line_len = line_width % len_rem;
		print_hex_ascii_line(ch, line_len, offset);
		len_rem = len_rem - line_len;
		ch = ch + line_len;
		offset = offset + line_width;
		if (len_rem <= line_width) {
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}

void handlearp(const struct ethhdr *eptr, const struct pcap_pkthdr* pkthdr,const u_char* packet, u_char *usrarg) {
	char time[50];
	const struct ether_arp *arp = (struct ether_arp *)(packet + SIZE_ETHERNET); //if_ether struct used
	const u_char *payload = (u_char *)(packet + SIZE_ETHERNET + 28);
	if (usrarg != NULL) {
		if (strstr((char *)payload, (char *)usrarg) == NULL) {
			return;
		}
	}
	struct tm* tm_info = localtime(&pkthdr->ts.tv_sec);
	strftime(time, sizeof(time), "%Y-%m-%d %H:%M:%S", tm_info);
	fprintf(stdout, "\n%s.%ld %s -> %s ", time, pkthdr->ts.tv_usec, ether_ntoa((const struct ether_addr *)eptr->h_source), ether_ntoa((const struct ether_addr *)eptr->h_dest));
	fprintf(stdout, "type %x len %d\n", ETHERTYPE_ARP, pkthdr->len);
	for (int i=0; i < 4; i++) {
		if (i < 3)
			fprintf(stdout, "%d.", arp->arp_spa[i]);
		else
			fprintf(stdout, "%d", arp->arp_spa[i]);
	} 
	fprintf(stdout, " -> ");
	for (int j=0; j<4; j++) {
		if (j < 3)
			fprintf(stdout, "%d.", arp->arp_tpa[j]);
		else
			fprintf(stdout, "%d", arp->arp_tpa[j]);

	}
	if (ntohs(arp->ea_hdr.ar_op) == ARP_REQUEST)
		fprintf(stdout, " ARP Request");
	else if (ntohs(arp->ea_hdr.ar_op) == ARP_REPLY)
		fprintf(stdout, " ARP Reply");
	printf("\n");
	//print_payload(payload, strlen(payload));
}

void handleip(const struct ethhdr *eptr, const struct pcap_pkthdr* pkthdr, const u_char* packet, u_char *usrarg) {
	char time[50];
	u_int size_ip = 0, size_tcp = 0;
	const struct ip *ip;
	const struct sniff_tcp *tcp;
	const struct udp_hdr *udp;
	const u_char *payload;
	u_short dport = 0, sport = 0;
	int psize = 0;
	//char *buffer = NULL;

	ip = (struct ip*)(packet + SIZE_ETHERNET); 
	size_ip = (ip->ip_hl)*4;
	//printf("%d", size_ip);
	//size_ip = IP_HL(ip)*4;
	if (size_ip < 20)
		return;

	if (ip->ip_p == IPPROTO_TCP) {
		tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
		size_tcp = TH_OFF(tcp)*4;
		if (size_tcp < 20)
			return;
		payload = '\0';
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
		sport = tcp->th_sport;
		dport = tcp->th_dport;
		psize = ntohs(ip->ip_len) - size_ip - size_tcp;
	} else if (ip->ip_p == IPPROTO_UDP) {
		udp = (struct udp_hdr *)(packet + SIZE_ETHERNET + size_ip);
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + UDP_HEADER_SIZE);
		sport = udp->sport;
		dport = udp->dport;
		psize = ntohs(ip->ip_len) - size_ip - UDP_HEADER_SIZE;
	} else if (ip->ip_p == IPPROTO_ICMP) {
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + ICMP_HEADER_SIZE);
		psize = ntohs(ip->ip_len) - size_ip - ICMP_HEADER_SIZE;
	} else {
		//printf("in other");
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip);
		psize = ntohs(ip->ip_len) - size_ip;
	}
	if (usrarg != NULL && payload != NULL) {
		const char *start = payload;
		int len = strlen(payload);
		char buffer[len+1];
		int i = 0;
		//printf("%d ", len);
		//buffer = (char *) malloc(sizeof(char)*(len+1));
		//memset(buffer, 0, sizeof(buffer));
		buffer[len] = '\0';
		while(len > 0) {
			if (isprint(*payload)) {
				//printf("%c", *payload);
				buffer[i++] = *payload;
			}
			payload++;
			len--;
		}
		buffer[i] = '\0';
		payload = start;
		//printf("%d ", strlen(buffer));
		//printf("%s", buffer);
		if (strstr((char *)payload, (char *)usrarg) == NULL || psize <= 0) {
			return;
		} else {
			printf("Found %s", buffer);
			//free(buffer);
			//printf("\nPayload: %s", payload);
		}
	}

	struct tm* tm_info = localtime(&pkthdr->ts.tv_sec);
	strftime(time, sizeof(time), "%Y-%m-%d %H:%M:%S", tm_info);
	fprintf(stdout, "\n%s.%ld %s -> %s ", time, pkthdr->ts.tv_usec, ether_ntoa((const struct ether_addr *)eptr->h_source), ether_ntoa((const struct ether_addr *)eptr->h_dest));
	fprintf(stdout, "type %x len %d\n", ETHERTYPE_IP, pkthdr->len);
	if (sport == 0 && dport == 0)
		fprintf(stdout, "%s -> %s ", inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));
	else
		fprintf(stdout, "%s:%d -> %s:%d ", inet_ntoa(ip->ip_src), sport, inet_ntoa(ip->ip_dst), dport);
	char *prototype = malloc(sizeof(char)*256);
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			prototype = "TCP";
			break;
		case IPPROTO_UDP:
			prototype = "UDP";
			break;
		case IPPROTO_ICMP:
			prototype = "ICMP";
			break;
		case IPPROTO_IP:
			prototype = "IP";
		default:
			prototype = "OTHER";
			break;
	}
	fprintf(stdout, "%s\n", prototype);
	if (psize > 0)
		print_payload(payload, psize);
	//fprintf(stdout, "%d %d %d %d\n", SIZE_ETHERNET, size_ip, size_tcp, ntohs(ip->ip_len));
	//fprintf(stdout, "\n%s", payload);
	return;
}

void handler(u_char *usrarg, const struct pcap_pkthdr* pkthdr, const u_char* packet) {

	//eptr = (struct ether_header *) packet;
	const struct ethhdr *eptr = (struct ethhdr*)(packet);
	if (ntohs(eptr->h_proto) == ETHERTYPE_ARP) {
		handlearp(eptr, pkthdr, packet, usrarg);
		return;
	} else if (ntohs(eptr->h_proto) == ETHERTYPE_IP) {
		handleip(eptr, pkthdr, packet, usrarg);
		return;
	}

}

int main(int argc, char **argv){
	int j = 0, param = 1;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct bpf_program fp;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	char *interface = NULL, *filename = NULL, *sstring = NULL, expr[256] = "";

	if (argc > 1) {
		for (j =1; j < argc; j=j+2) {
			if (strcmp(argv[j], "-i") == 0){
				interface = argv[j+1];
				param += 2;
				//	printf("interface found %s\n", interface);
			} else if (strcmp(argv[j], "-r") == 0) {
				param += 2;
				filename = argv[j+1];
				//	printf("filename: %s\n",filename);
			} else if (strcmp(argv[j], "-s") == 0) {
				param += 2;
				sstring = argv[j+1];
				//	printf("search string: %s\n",sstring);
			}
		}
		if (param < argc) {
			while (argc != param) {
				strcat(expr, argv[param]);
				strcat(expr, " ");
				param += 1;
			}
			//printf("Expression: %s\n",expr);
		}
	}

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find device: %s\n", errbuf);
		return -1;
	} 
	//printf("Dev: %s", dev);
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get net mask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	if (filename != NULL) {
		handle = pcap_open_offline(filename, errbuf);
	} else {
		if (interface != NULL)
			handle = pcap_open_live(interface, 65535, 1, 1000, errbuf);
		else
			handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);
	}
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device: %s\n", errbuf);
		return -1;
	}
	//if (pcap_datalink(handle) != DLT_EN10MB) {
	//	fprintf(stdout, "Only ethernet supported\n");
	//	return -1;
	//}	
	if (expr != NULL && pcap_compile(handle, &fp, expr, 0, net) == -1){
		fprintf(stderr, "Filter complie error %s\n", pcap_geterr(handle));
		return -1;
	}
	if (expr != NULL && pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Set filter error %s\n", pcap_geterr(handle));
		return -1;
	}
	// pcap_loop(pcap_t*, cnt, handler,u_char *userarg)
	pcap_loop(handle, -1, handler, (u_char *)sstring);
	pcap_freecode(&fp);
	pcap_close(handle);

	return 0;
}
