#ifndef PACKET_STATS_H
#define PACKET_STATS_H

#include "addr_t.h"
#include <set>

class packet_stats
{
	packet_stats &operator=(const packet_stats &) = delete;

public:
	enum type
	{
		PACKET_TCP = 0,
		PACKET_UDP
	};

	const addr_t src,
		dst;
	const uint16_t p_src,
		p_dst;
	const size_t len;
	const enum type t;
	const double ts;

	packet_stats(const addr_t &src_, const addr_t &dst_, const uint16_t p_src_, const uint16_t p_dst_, const size_t len_, const enum type t_, const double ts_) : src(src_), dst(dst_), p_src(p_src_), p_dst(p_dst_), len(len_), t(t_), ts(ts_)
	{
	}

	packet_stats(const packet_stats &rhs) : src(rhs.src), dst(rhs.dst), p_src(rhs.p_src), p_dst(rhs.p_dst), len(rhs.len), t(rhs.t), ts(rhs.ts)
	{
	}
};

class local_addr_mgr
{
	std::set<addr_t> local_addrs_;

public:
	local_addr_mgr();

	bool is_local(const addr_t &in) const;
};

#endif //PACKET_STATS_H
