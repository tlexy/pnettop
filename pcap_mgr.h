#ifndef PCAP_MGR_H
#define PCAP_MGR_H

#include <pcap.h>
#include <atomic>
#include "mt_list.h"
#include "packet_stats.h"
#include <stdint.h>
#include <string>

struct packet_list : public mt_list<packet_stats> 
{
	std::atomic<size_t>	total_pkts;

	packet_list() : total_pkts(0)
    {
	}
};

class pcap_mgr
{
public:
    pcap_mgr(const std::string& filter);
    ~pcap_mgr();
    pcap_mgr(const pcap_mgr&) = delete;
	pcap_mgr& operator=(const pcap_mgr&) = delete;

    void async_cap(packet_list& list);
    void stop();

private:
    void capture_dispatch(packet_list& p_list);

private:
    bool _is_stop;
    pcap_t* _p;
    uint32_t _net;
    uint32_t _mask;
    char* _dev;
    struct bpf_program _fp;
    std::string _filter_exp;
};

#endif
