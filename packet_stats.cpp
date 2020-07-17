#include "packet_stats.h"
#include <algorithm>
#include <ifaddrs.h>
#include <list>
#include "utils.h"


std::string packet_stats::to_string() const
{
	char src_buf[20], dst_buf[20];
	memset(src_buf, 0x0, sizeof(src_buf));
	memset(dst_buf, 0x0, sizeof(dst_buf));
	inet_ntop(AF_INET, (void *)&src.ip_data_, src_buf, sizeof(src_buf));
	inet_ntop(AF_INET, (void *)&dst.ip_data_, dst_buf, sizeof(dst_buf));
	//fprintf(stderr, "ip str:%s\n", mask_buf);
	std::string ret_str;
	ret_str += src_buf;
	ret_str += std::string(":");
	ret_str += std::to_string(p_src);

	ret_str += std::string("  --------  ");
	ret_str += dst_buf;
	ret_str += std::string(":");
	ret_str += std::to_string(p_dst);

	ret_str += std::string("  len: ");
	ret_str += std::to_string(len);
	ret_str += std::string("   type:");
	if (t == PACKET_TCP)
	{
		ret_str += std::string(" TCP");
	}
	else 
	{
		ret_str += std::string(" UDP");
	}
	return ret_str;
}

///////////////////////////////////////////////////////////////////

local_addr_mgr::local_addr_mgr() 
{
	struct ifaddrs	*ifaddr = 0, *ifa = 0;
    int n = 0;

	if(getifaddrs(&ifaddr) == -1)
	{
		throw runtime_error("Failure in getifaddrs");
	}
	for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) 
	{
		if (ifa->ifa_addr == NULL)
		{
            continue;
		}
		const int family = ifa->ifa_addr->sa_family;
		if (family == AF_INET) 
		{
			const struct sockaddr_in	*sa = (struct sockaddr_in*)ifa->ifa_addr;
			local_addrs_.insert(addr_t(sa->sin_addr));
		} else if(family == AF_INET6) 
		{
			const struct sockaddr_in6	*sa = (struct sockaddr_in6*)ifa->ifa_addr;
			local_addrs_.insert(addr_t(sa->sin6_addr));
		}
	}
	freeifaddrs(ifaddr);
}

bool local_addr_mgr::is_local(const addr_t& in) const 
{
	return local_addrs_.find(in) != local_addrs_.end();
}
