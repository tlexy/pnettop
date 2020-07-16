#ifndef PROC_H
#define PROC_H

#include "packet_stats.h"
#include "addr_t.h"
#include <sys/types.h>
#include <vector>
#include "pcap_mgr.h"
#include <map>

typedef struct ext_sd
{
    addr_t addr;
    int port;
    enum packet_stats::type t;

    ext_sd(const addr_t &addr_ = addr_t(), const int port_ = 0, const enum packet_stats::type t_ = packet_stats::type::PACKET_TCP) : addr(addr_), port(port_), t(t_)
    {
    }

    inline bool operator==(const ext_sd &rhs) const
    {
        return port == rhs.port && t == rhs.t && addr == rhs.addr;
    }

    inline bool operator<(const ext_sd &rhs) const
    {
        if (port == rhs.port)
        {
            if (t == rhs.t)
            {
                return addr < rhs.addr;
            }
            return t < rhs.t;
        }
        return port < rhs.port;
    }
} ext_sd_t;

typedef std::vector<unsigned long>	v_inodes;
typedef std::map<ext_sd_t, std::vector<unsigned long>> sd_inodes;

class process_stat
{
public:
    process_stat(pid_t pid);
    void get_inodes(v_inodes& inodes);
    pid_t pid() const;

    void add_recv_len(size_t len);
    void add_trans_len(size_t len);

    size_t recv_len() const;
    size_t trans_len() const;

private:
    v_inodes _vnodes;
    pid_t _pid;
    std::string _cmd_str;
    size_t _r_len;
    size_t _t_len;
};

class proc_mgr
{
public:
    proc_mgr(const std::vector<pid_t> pids);

    void get_stat(const std::list<packet_stats>& list, std::vector<process_stat>& pros);

private:
    std::vector<process_stat> _pros;
    sd_inodes _sd_nodes;
};

#endif