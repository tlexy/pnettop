#ifndef PROC_H
#define PROC_H

#include "packet_stats.h"
#include "addr_t.h"
#include <sys/types.h>
#include <vector>
#include "pcap_mgr.h"
#include <map>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <cstring>

typedef struct ext_sd
{
    addr_t laddr;
    int lport;
    addr_t raddr;
    int rport;
    unsigned long inode;
    enum packet_stats::type t;

    ext_sd(const addr_t &addr_ = addr_t(), const int port_ = 0, 
            const addr_t &raddr_ = addr_t(), const int rport_ = 0, 
            const enum packet_stats::type t_ = packet_stats::type::PACKET_TCP,
            unsigned long inode_ = 0) 
        : laddr(addr_), 
        lport(port_), 
        raddr(raddr_),
        rport(rport_),
        t(t_),
        inode(inode_)
    {
    }

    inline bool operator==(const ext_sd &rhs) const
    {
        return lport == rhs.lport && t == rhs.t && laddr == rhs.laddr && rport == rhs.rport && raddr == rhs.raddr;
    }

    inline bool operator<(const ext_sd &rhs) const
    {
        if (lport == rhs.lport)
        {
            if (t == rhs.t)
            {
                return laddr < rhs.laddr or raddr < rhs.raddr;
            }
            return t < rhs.t;
        }
        return lport < rhs.lport or rport < rhs.rport;
    }

    std::string to_string() const
    {
        char src_buf[20], dst_buf[20];
        memset(src_buf, 0x0, sizeof(src_buf));
        memset(dst_buf, 0x0, sizeof(dst_buf));
        inet_ntop(AF_INET, (void *)&laddr.ip_data_, src_buf, sizeof(src_buf));
        inet_ntop(AF_INET, (void *)&raddr.ip_data_, dst_buf, sizeof(dst_buf));
        //fprintf(stderr, "ip str:%s\n", mask_buf);
        std::string ret_str;
        ret_str += src_buf;
        ret_str += std::string(":");
        ret_str += std::to_string(lport);

        ret_str += std::string("  --------  ");
        ret_str += dst_buf;
        ret_str += std::string(":");
        ret_str += std::to_string(rport);

        ret_str += std::string("  inode: ");
        ret_str += std::to_string(inode);
        ret_str += std::string("   type:");
        if (t == packet_stats::type::PACKET_TCP)
        {
            ret_str += std::string(" TCP");
        }
        else 
        {
            ret_str += std::string(" UDP");
        }
        return ret_str;
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

    void add_recv_tcp_len(size_t len);
    void add_trans_tcp_len(size_t len);

    void add_recv_udp_len(size_t len);
    void add_trans_udp_len(size_t len);

    size_t recv_len(bool tcp = true) const;
    size_t trans_len(bool tcp = true) const;

private:
    v_inodes _vnodes;
    pid_t _pid;
    std::string _cmd_str;
    size_t _r_len;
    size_t _t_len;
    size_t _ru_len;
    size_t _tu_len;
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