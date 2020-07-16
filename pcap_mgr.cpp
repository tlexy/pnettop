#include "pcap_mgr.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <chrono>
#include <atomic>
#include "utils.h"

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6

/* Ethernet header */
struct sniff_ethernet
{
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type;                 /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip
{
    u_char ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char ip_tos;                 /* type of service */
    u_short ip_len;                /* total length */
    u_short ip_id;                 /* identification */
    u_short ip_off;                /* fragment offset field */
#define IP_RF 0x8000               /* reserved fragment flag */
#define IP_DF 0x4000               /* dont fragment flag */
#define IP_MF 0x2000               /* more fragments flag */
#define IP_OFFMASK 0x1fff          /* mask for fragmenting bits */
    u_char ip_ttl;                 /* time to live */
    u_char ip_p;                   /* protocol */
    u_short ip_sum;                /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp
{
    u_short th_sport; /* source port */
    u_short th_dport; /* destination port */
    tcp_seq th_seq;   /* sequence number */
    tcp_seq th_ack;   /* acknowledgement number */
    u_char th_offx2;  /* data offset, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
    u_short th_win; /* window */
    u_short th_sum; /* checksum */
    u_short th_urp; /* urgent pointer */
};

#define SIZE_ETHERNET 14

const struct sniff_ethernet *ethernet; /* The ethernet header */
const struct sniff_ip *ip;             /* The IP header */
const struct sniff_tcp *tcp;           /* The TCP header */
const struct udphdr *udp;              /* The UDP header */

u_int size_ip;
u_int size_tcp;

typedef std::list<packet_stats>	st_pkt_list;

pcap_mgr::pcap_mgr(const std::string& filter)
    :_is_stop(false),
    _p(NULL),
    _filter_exp(filter)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    _dev = pcap_lookupdev(errbuf);
    if (_dev == NULL)
    {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return ;
    }
    if (pcap_lookupnet(_dev, &_net, &_mask, errbuf) == -1)
    {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", _dev, errbuf);
        _net = 0;
        _mask = 0;
        return ;
    }
    _p = pcap_open_live(_dev, BUFSIZ, 1, 1000, errbuf);
    if (_p == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", _dev, errbuf);
        return;
    }
    if (pcap_compile(_p, &_fp, _filter_exp.c_str(), 0, _net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", _filter_exp.c_str(), pcap_geterr(_p));
        return;
    }
    if (pcap_setfilter(_p, &_fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", _filter_exp, pcap_geterr(_p));
        return;
    }
}

pcap_mgr::~pcap_mgr()
{
    pcap_close(_p);
}

extern "C" {
    	// linux cooked header
	// glanced from libpcap/ssl.h
	#define SLL_ADDRLEN     	(8)               /* length of address field */
	#define SLL_PROTOCOL_IP		(0x0008)
	#define SLL_PROTOCOL_IP6	(0xDD86)
	struct sll_header {
        	u_int16_t	sll_pkttype;          /* packet type */
        	u_int16_t	sll_hatype;           /* link-layer address type */
        	u_int16_t	sll_halen;            /* link-layer address length */
        	u_int8_t	sll_addr[SLL_ADDRLEN]; /* link-layer address */
        	u_int16_t	sll_protocol;         /* protocol */
	};

	inline void process_tcp(const u_char *data, st_pkt_list& p_list, const double ts, const size_t len, const addr_t& src, const addr_t& dst) {
		const struct tcphdr	*tcp = (struct tcphdr*)data;
		const uint16_t		p_src = ntohs(tcp->source),
					p_dst = ntohs(tcp->dest);
        fprintf(stderr, "tcp here...\n");
		p_list.push_back(packet_stats(src, dst, p_src, p_dst, len, packet_stats::type::PACKET_TCP, ts));
	}

	inline void process_udp(const u_char *data, st_pkt_list& p_list, const double ts, const size_t len, const addr_t& src, const addr_t& dst) {
		const struct udphdr	*udp = (struct udphdr*)data;
		const uint16_t		p_src = ntohs(udp->source),
					p_dst = ntohs(udp->dest);
        fprintf(stderr, "udp here...\n");
		p_list.push_back(packet_stats(src, dst, p_src, p_dst, len, packet_stats::type::PACKET_UDP, ts));
	}

	inline void process_ip(const u_char *data, st_pkt_list& p_list, const double ts, const size_t len) {
		const struct ip *ip = (struct ip*)data;
		const addr_t	src(ip->ip_src),
				dst(ip->ip_dst);
        fprintf(stderr, "ip here...%d\n", ip->ip_p);
		switch(ip->ip_p) {
			case IPPROTO_TCP:
				process_tcp(data + sizeof(struct ip), p_list, ts, len, src, dst);
				break;
			case IPPROTO_UDP:
				process_udp(data + sizeof(struct ip), p_list, ts, len, src, dst);
				break;
			default:
				//std::cerr << "Unknown ip protocol " << (int)ip->ip_p << ", skipping packet" << std::endl;
				break;
		}
	}

	inline void process_ip6(const u_char *data, st_pkt_list& p_list, const double ts, const size_t len) {
		const struct ip6_hdr	*ip6 = (struct ip6_hdr*)data;
		const addr_t		src(ip6->ip6_src),
					dst(ip6->ip6_dst);
		switch(ip6->ip6_nxt) {
			case IPPROTO_TCP:
				process_tcp(data + sizeof(struct ip6_hdr), p_list, ts, len, src, dst);
				break;
			case IPPROTO_UDP:
				process_udp(data + sizeof(struct ip6_hdr), p_list, ts, len, src, dst);
				break;
			default:
				//std::cerr << "Unknown ip protocol " << (int)ip6->ip6_nxt << ", skipping packet" << std::endl;
				break;
		}
	}

	void p_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *data) {
		const struct sll_header *sll = (struct sll_header*)data;
		st_pkt_list& 		p_list = *(st_pkt_list*)user;
		const double		ts = tv_to_sec(header->ts);
        fprintf(stderr, "sll_protocol:%d\n", sll->sll_protocol);
		switch(sll->sll_protocol) {
			case SLL_PROTOCOL_IP:
				process_ip(data + sizeof(struct sll_header), p_list, ts, header->len);
				break;
			case SLL_PROTOCOL_IP6:
				process_ip6(data + sizeof(struct sll_header), p_list, ts, header->len);
				break;
			default:
				//std::cerr << "Unknown SLL protocol " << (int)sll->sll_protocol << ", skipping packet" << std::endl;
				break;
		}
	}

    void pc_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) 
    {
        st_pkt_list& p_list = *(st_pkt_list*)user;

        ethernet = (struct sniff_ethernet*)(packet);
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        if (size_ip < 20) 
        {
            printf("   * Invalid IP header length: %u bytes\n", size_ip);
            return;
        }

        if (ip->ip_p == IPPROTO_UDP)
        {
            udp = (struct udphdr*)(packet + SIZE_ETHERNET + size_ip);
            //fprintf(stderr, "UDP src port:%d:%d, dest port:%d:%d\n", udp->source, ntohs(udp->source), udp->dest, ntohs(udp->dest));
            p_list.push_back(packet_stats(ip->ip_src, ip->ip_dst, ntohs(udp->source), ntohs(udp->dest), header->len, packet_stats::type::PACKET_UDP, 0));
        }
        else if (ip->ip_p == IPPROTO_TCP)
        {
            tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
            size_tcp = TH_OFF(tcp)*4;
            if (size_tcp < 20) 
            {
                printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                return;
            }
            //fprintf(stderr, "TCP src port:%d:%d, dest port:%d:%d\n", tcp->th_sport, ntohs(tcp->th_sport), tcp->th_dport, ntohs(tcp->th_dport));
            p_list.push_back(packet_stats(ip->ip_src, ip->ip_dst, ntohs(tcp->th_sport), ntohs(tcp->th_dport), header->len, packet_stats::type::PACKET_TCP, 0));
        }
        else 
        {

        }
    }
}

void pcap_mgr::capture_dispatch(packet_list& list)
{
    st_pkt_list	pkt_list;
    const int ret = pcap_dispatch(_p, -1, pc_handler, (u_char*)&pkt_list);
	if(ret == -1)
    {
		throw runtime_error(pcap_geterr(_p));
    }
	list.push_many(pkt_list);
	list.total_pkts += ret;
}

void pcap_mgr::async_cap(packet_list& list)
{
    while(!_is_stop)
    {
        capture_dispatch(list);
    }
}

void pcap_mgr::stop()
{
    _is_stop = true;
}