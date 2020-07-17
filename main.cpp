#include "pcap_mgr.h"
#include <thread>
#include "packet_stats.h"
#include "pcap_mgr.h"
#include "proc.h"
#include <fstream>

void print_process(const std::vector<process_stat>& procs)
{
    fprintf(stderr, "size:%u\n", procs.size());
    for (int i = 0; i < procs.size(); ++i)
    {
        size_t r = procs[i].recv_len(true) + procs[i].recv_len(false);
        size_t t = procs[i].trans_len(true) + procs[i].trans_len(false);
        fprintf(stderr, "pid:%d, rB:%ld, tB:%ld\n", procs[i].pid(), r/1024, t/1024);
    }
}

void net_speed(const std::list<packet_stats>& list)
{
    // std::ofstream of("packet_record.log", std::ostream::out | std::ostream::binary);
	// if (!of.is_open())
	// {
	// 	return;
	// }

    size_t len = 0;
    std::list<packet_stats>::const_iterator it = list.begin();
    for (; it != list.end(); ++it)
    {
        //of << it->to_string() << std::endl;
        len += it->len;
    }
    //of.close();
    float net = len/1.0/1024;
    fprintf(stderr, "total kB/s: %0.2f\n", net);
}

int main()
{
    //local_addr_mgr local_mgr;
    int a;
    std::vector<pid_t> pids;
    pids.push_back(95189);
    pcap_mgr pcap("udp or tcp");
    // proc_mgr pmgr(pids);
    // scanf("%d\n", &a);
    packet_list plist;
    std::thread th(&pcap_mgr::async_cap, &pcap, std::ref(plist));

    while (true)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        std::list<packet_stats> clist;
        //fprintf(stderr, "plist size:%u\n", plist.size());
        plist.swap(clist);
        net_speed(clist);
        proc_mgr pmgr(pids);
        std::vector<process_stat> procs;
        pmgr.get_stat(clist, procs);
        print_process(procs);

    }
    return 0;
}