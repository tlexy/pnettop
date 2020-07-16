#include "pcap_mgr.h"
#include <thread>
#include "packet_stats.h"
#include "pcap_mgr.h"
#include "proc.h"

void print_process(const std::vector<process_stat>& procs)
{
    fprintf(stderr, "size:%u\n", procs.size());
    for (int i = 0; i < procs.size(); ++i)
    {
        fprintf(stderr, "pid:%d, rB:%ld, tB:%ld\n", procs[i].pid(), procs[i].recv_len(), procs[i].trans_len());
    }
}

void net_speed(const std::list<packet_stats>& list)
{
    size_t len = 0;
    std::list<packet_stats>::const_iterator it = list.begin();
    for (; it != list.end(); ++it)
    {
        len += it->len;
    }
    float net = len/1.0/1024;
    fprintf(stderr, "total kB/s: %0.2f\n", net);
}

int main()
{
    pcap_mgr pcap("udp or tcp");
    packet_list plist;
    std::thread th(&pcap_mgr::async_cap, &pcap, std::ref(plist));
    std::vector<pid_t> pids;
    pids.push_back(62999);

    while (true)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        std::list<packet_stats> clist;
        //fprintf(stderr, "plist size:%u\n", plist.size());
        plist.swap(clist);
        net_speed(clist);
        // proc_mgr pmgr(pids);
        // std::vector<process_stat> procs;
        // pmgr.get_stat(clist, procs);
        // print_process(procs);

    }
    return 0;
}