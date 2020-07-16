#include "packet_stats.h"
#include <algorithm>
#include <ifaddrs.h>
#include <list>
#include "utils.h"

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

