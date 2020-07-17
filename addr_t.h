#ifndef ADDR_T_H
#define ADDR_T_H

#include <netdb.h>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>

class addr_t
{

public:
	typedef union 
	{
		in_addr ipv4;
		in6_addr ipv6;
	} ip_data;

	int af_type_;
	ip_data ip_data_;

	static ip_data get_ip4_data(const void *b)
	{
		ip_data ret;
		ret.ipv4 = *(in_addr *)b;
		return ret;
	}

	static ip_data get_ip6_data(const void *b)
	{
		ip_data ret;
		ret.ipv6 = *(in6_addr *)b;
		return ret;
	}

	addr_t() : af_type_(0)
	{
		std::memset(&ip_data_, 0x00, sizeof(ip_data));
	}

	addr_t(const int af_type) : af_type_(af_type)
	{
		std::memset(&ip_data_, 0x00, sizeof(ip_data));
		switch (af_type_)
		{
		case AF_INET:
			ip_data_.ipv4.s_addr = INADDR_ANY;
			break;
		case AF_INET6:
			ip_data_.ipv6 = IN6ADDR_ANY_INIT;
			break;
		}
	}

	addr_t(const in_addr &ipv4) : af_type_(AF_INET), ip_data_(get_ip4_data(&ipv4))
	{
		// char mask_buf[20];
		// inet_ntop(AF_INET, (void *)&ip_data_, mask_buf, sizeof(mask_buf));
		// fprintf(stderr, "ip str:%s\n", mask_buf);
	}

	addr_t(const in6_addr &ipv6) : af_type_(AF_INET6), ip_data_(get_ip6_data(&ipv6))
	{
	}

	addr_t(const addr_t &rhs) : af_type_(rhs.af_type_), ip_data_(rhs.ip_data_)
	{
	}

	int get_af_type(void) const
	{
		return af_type_;
	}

	addr_t &operator=(const addr_t &rhs)
	{
		if (this != &rhs)
		{
			af_type_ = rhs.af_type_;
			ip_data_ = rhs.ip_data_;
		}
		return *this;
	}

	inline bool is_ipv6(void) const
	{
		return af_type_ == AF_INET6;
	}

	std::string to_str(const bool &full_name = false) const
	{
		const int gni_flags = (full_name) ? 0 : NI_NUMERICHOST | NI_NUMERICSERV;
		if (af_type_ == AF_INET)
		{
			struct sockaddr_in in;
			in.sin_family = AF_INET;
			in.sin_port = 123;
			in.sin_addr = ip_data_.ipv4;
			char hbuf[NI_MAXHOST];
			if (getnameinfo((const sockaddr *)&in, sizeof(struct sockaddr_in), hbuf, sizeof(hbuf), 0, 0, gni_flags))
				return "<invalid host>";
			return hbuf;
		}
		struct sockaddr_in6 in;
		in.sin6_family = AF_INET6;
		in.sin6_port = 123;
		in.sin6_flowinfo = 0;
		in.sin6_addr = ip_data_.ipv6;
		in.sin6_scope_id = 0;
		char hbuf[NI_MAXHOST];
		if (getnameinfo((const sockaddr *)&in, sizeof(struct sockaddr_in6), hbuf, sizeof(hbuf), 0, 0, gni_flags))
			return "<invalid host>";
		return hbuf;
	}

	friend bool operator==(const addr_t &lhs, const addr_t &rhs);

	friend bool operator<(const addr_t &lhs, const addr_t &rhs);
};

inline bool operator==(const addr_t &lhs, const addr_t &rhs)
{
	if (lhs.af_type_ == rhs.af_type_)
	{
		if (lhs.af_type_ == AF_INET)
		{
			return lhs.ip_data_.ipv4.s_addr == rhs.ip_data_.ipv4.s_addr;
		}
		return !std::memcmp(&lhs.ip_data_.ipv6, &rhs.ip_data_.ipv6, sizeof(in6_addr));
	}
	return false;
}

inline bool operator<(const addr_t &lhs, const addr_t &rhs)
{
	if (lhs.af_type_ == rhs.af_type_)
	{
		if (lhs.af_type_ == AF_INET)
		{
			return lhs.ip_data_.ipv4.s_addr < rhs.ip_data_.ipv4.s_addr;
		}
		return std::memcmp(&lhs.ip_data_.ipv6, &rhs.ip_data_.ipv6, sizeof(in6_addr)) < 0;
	}
	return lhs.af_type_ < rhs.af_type_;
}

#endif //ADDR_T_H
