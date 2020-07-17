#include "proc.h"
#include <unistd.h>
#include <algorithm>
#include <dirent.h>
#include <cstring>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "utils.h"
#include <fstream>

static local_addr_mgr local_mgr;

/* Parses /proc/<pid>/cmdline */
std::string get_cmd_line(const pid_t pid)
{
    char cur_fd[64];
    std::snprintf(cur_fd, 64, "/proc/%i/cmdline", pid);
    int fd = open(cur_fd, O_RDONLY);
    if (-1 == fd)
        return "(no cmd line)";
    char buf[1024] = "";
    const int rb = read(fd, buf, 1024);
    if (rb >= 0)
    {
        const size_t max_rb = (1024 > rb) ? rb : 1024;
        for (size_t i = 0; i < max_rb; ++i)
        {
            if (buf[i] == '\0')
                buf[i] = ' ';
        }
        buf[max_rb - 1] = '\0';
    }
    close(fd);
    return buf;
}

// 获得pid进程所有打开的socket inode号
void get_sockets_inodes(const pid_t pid, v_inodes &out)
{
    char cur_fd[64];
    std::snprintf(cur_fd, 64, "/proc/%i/fd", pid);
    DIR *dir = opendir(cur_fd);
    if (!dir)
    {
        return;
    }
    for (struct dirent *entry = readdir(dir); entry; entry = readdir(dir))
    {
        // skip . and ..
        if (!std::strcmp(entry->d_name, ".") || !std::strcmp(entry->d_name, ".."))
        {
            continue;
        }
        // we're not interested in directories
        if (entry->d_type == DT_DIR)
        {
            continue;
        }
        // prepare and read the sym link
        char cur_sd[128],
            buf_sd[128];
        std::snprintf(cur_sd, 128, "/proc/%i/fd/%s", pid, entry->d_name);
        const size_t rb = readlink(cur_sd, buf_sd, 128);
        if (rb >= 128)
        {
            buf_sd[127] = '\0';
        }
        // check if it's a socket or not
        unsigned long inode = 0;
        if (std::sscanf(buf_sd, "socket:[%ld]", &inode) != 1)
        {
            continue;
        }
        // else add it ot the vector
        out.push_back(inode);
    }
    closedir(dir);
    std::sort(out.begin(), out.end());
}

// get an address from hex string
inline const addr_t get_addr_hexstr(const char *addr_s)
{
    const size_t str_len = std::strlen(addr_s);
    addr_t ret;
    switch (str_len)
    {
    case 8:
    {
        struct in_addr in_local;
        if (1 != std::sscanf(addr_s, "%08X", &in_local.s_addr))
        {
            throw runtime_error("Invalid ipv4 hex network address: \"") << addr_s << "\"";
        }
        ret = addr_t(in_local);
    }
    break;
    default:
        throw runtime_error("Invalid hex network address: \"") << addr_s << "\"";
        break;
    }
    return ret;
}


void get_sockets_raw(const bool tcp, sd_inodes &out)
{
    // open /proc directories and scan for all processes
    char cur_fd[64];
    std::snprintf(cur_fd, 64, "/proc/net/%s", tcp ? "tcp" : "udp");
    std::ifstream istr(cur_fd);
    std::set<int> lcl_ports;
    while (istr)
    {
        std::string cur_line;
        std::getline(istr, cur_line);
        char rem_addr[128],
            local_addr[128];
        int local_port = -1,
            rem_port = -1;
        unsigned long inode = 0;
        const int matches = std::sscanf(cur_line.c_str(), "%*d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %*X %*X:%*X %*X:%*X %*X %*d %*d %ld %*512s\n", local_addr, &local_port, rem_addr, &rem_port, &inode);
        if (5 != matches || lcl_ports.end() != lcl_ports.find(local_port))
        {
            continue;
        }
        // get the address
        //fprintf(stderr, "get local addr...\n");
        const addr_t lcl_addr = get_addr_hexstr(local_addr);
        const addr_t r_addr = get_addr_hexstr(rem_addr);
        const ext_sd_t esd(lcl_addr, local_port, r_addr, rem_port, tcp ? packet_stats::type::PACKET_TCP : packet_stats::type::PACKET_UDP, inode);
        out[esd].push_back(inode);
        lcl_ports.insert(local_port);
    }
}

//获得系统所有的socket及inode号
void get_all_sockets(sd_inodes &out)
{
    get_sockets_raw(true, out);
    get_sockets_raw(false, out);
    // now we need to sort all vectors of inodes
    for (auto &i : out)
    {
       std::sort(i.second.begin(), i.second.end());
    }

    // std::ofstream of("system_record.log", std::ostream::out | std::ostream::binary);
	// if (!of.is_open())
	// {
	// 	return;
	// }
    // for (auto &i : out)
    // {
    //     of << i.first.to_string() << std::endl;
    // }
    // of.close();
}

process_stat::process_stat(pid_t pid)
    :_pid(pid),
    _r_len(0),
    _t_len(0),
    _ru_len(0),
    _tu_len(0)
{
    get_sockets_inodes(pid, _vnodes);
    //fprintf(stderr, "inodes size:%u\n", _vnodes.size());
    _cmd_str = get_cmd_line(pid);
}

void process_stat::get_inodes(v_inodes& inodes)
{
    inodes = _vnodes;
}

pid_t process_stat::pid() const
{
    return _pid;
}

void process_stat::add_recv_tcp_len(size_t len)
{
    _r_len += len;
}

void process_stat::add_trans_tcp_len(size_t len)
{
    _t_len += len;
}

void process_stat::add_recv_udp_len(size_t len)
{
    _ru_len += len;
}

void process_stat::add_trans_udp_len(size_t len)
{
    _tu_len += len;
}

size_t process_stat::recv_len(bool tcp) const
{
    if (!tcp)
    {
        return _ru_len;
    }
    return _r_len;
}

size_t process_stat::trans_len(bool tcp) const
{
    if (!tcp)
    {
        return _tu_len;
    }
    return _t_len;
}

//////////////////--------------------------- proc_mgr
proc_mgr::proc_mgr(const std::vector<pid_t> pids)
{
    get_all_sockets(_sd_nodes);

    for (int i = 0; i < pids.size(); ++i)
    {
        process_stat proc(pids[i]);
        _pros.push_back(proc);
    }
}

bool match(const std::map<ext_sd_t, unsigned long>& pid_socks, const packet_stats& packet)
{
    std::map<ext_sd_t, unsigned long>::const_iterator it = pid_socks.begin();
    for (; it != pid_socks.end(); ++it)
    {
        if (it->first.t != packet.t)
        {
            continue;
        }
        if (it->first.laddr == packet.src || it->first.laddr == packet.dst)
        {
            return true;
        }
    }
}

/*
    总的来说，将一个packet_stats转换为struct ext_sd，判断两者是否相等（或者通过转换为inode来判断？）
    再根据packet_stats中的laddr和raddr来判断发送或者接收
*/
void proc_mgr::get_stat(const std::list<packet_stats>& list, std::vector<process_stat>& pros)
{
    //系统中所有的sockets...
    std::map<unsigned long, sd_inodes::const_iterator>	link_inodes;
	for(sd_inodes::const_iterator it = _sd_nodes.begin(); it != _sd_nodes.end(); ++it)
    {
		for(const auto& i : it->second)
        {
			link_inodes[i] = it;//多个inode对应一个ext_sd
        }
    }

    for (int i = 0; i < _pros.size(); ++i)
    {
        v_inodes inodes;
        //获得当前进程的所有inode号
        _pros[i].get_inodes(inodes);
        std::map<ext_sd_t, unsigned long> proc_sd;//当前进程用到的地址集合
        for (int j = 0; j < inodes.size(); ++j)
        {
            std::map<unsigned long, sd_inodes::const_iterator>::iterator sit = link_inodes.find(inodes[j]);
            if (sit != link_inodes.end())
            {
                proc_sd[sit->second->first] = sit->first;
            }
        }
        //对于每个进程
        std::list<packet_stats>::const_iterator it = list.begin();
        fprintf(stderr, "list size:%u, proc_sd size:%d\n", list.size(), proc_sd.size());
        for (; it != list.end(); ++it)
        {
            // ext_sd_t sd(it->src, it->p_src, it->dst, it->p_dst, it->t);
            // if (proc_sd.find(sd) == proc_sd.end())
            // {
            //     continue;
            // }
            if (!match(proc_sd, *it))
            {
                continue;
            }
            bool is_send = local_mgr.is_local(it->src);
            bool is_recv = local_mgr.is_local(it->dst);
            if (is_send && it->t == packet_stats::PACKET_TCP)
            {
                _pros[i].add_trans_tcp_len(it->len);
            }
            else if (is_send && it->t == packet_stats::PACKET_UDP)
            {
                 _pros[i].add_trans_udp_len(it->len);
            }
            else if (is_recv && it->t == packet_stats::PACKET_TCP)
            {
                 _pros[i].add_recv_udp_len(it->len);
            }
            else if (is_recv && it->t == packet_stats::PACKET_UDP)
            {
                 _pros[i].add_recv_udp_len(it->len);
            }
            // ext_sd_t sd_dst(it->dst, it->p_dst, it->t);
            // if (proc_sd.find(sd_src) != proc_sd.end())
            // {
            //     _pros[i].add_trans_len(it->len);
            // }
            // else if (proc_sd.find(sd_dst) != proc_sd.end())
            // {
            //     _pros[i].add_recv_len(it->len);
            // }
        }
    }
    pros = _pros;
}