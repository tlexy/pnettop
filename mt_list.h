#ifndef MT_LIST_H
#define MT_LIST_H

#include <mutex>
#include <list>
#include <algorithm>
#include <stdio.h>

template<typename T>
class mt_list 
{
	
	mt_list(const mt_list&) = delete;
	mt_list& operator=(const mt_list&) = delete;
	
	std::mutex	mtx_;
	std::list<T>	list_;
public:
	mt_list() {}

	~mt_list() {}

	void push(const T& in)
	{
		std::lock_guard<std::mutex>	lg(mtx_);
		list_.push_back(in);
	}

	void push_many(const std::list<T>& in) 
	{
		std::lock_guard<std::mutex>	lg(mtx_);
		std::for_each(in.begin(), in.end(), [&](const T& t){ list_.push_back(t); });
	}

	void swap(std::list<T>& out) 
	{
		std::lock_guard<std::mutex>	lg(mtx_);
		list_.swap(out);
	}
};

#endif //MT_LIST_H

