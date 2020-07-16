#ifndef UTILS_H
#define UTILS_H

#include <exception>
#include <string>
#include <sstream>
#include <sys/time.h>

class runtime_error : public std::exception
{
        std::ostringstream _oss;
        std::string _str;

public:
        runtime_error(const char *e) throw()
        {
                _oss << e;
                _str = _oss.str();
        }

        runtime_error(const runtime_error &rhs) throw()
        {
                _oss.str(rhs._oss.str());
                _str = _oss.str();
        }

        runtime_error &operator=(const runtime_error &rhs) throw()
        {
                _oss.str(rhs._oss.str());
                _str = _oss.str();

                return *this;
        }

        template <typename T>
        runtime_error &operator<<(const T &in)
        {
                _oss << in;
                _str = _oss.str();

                return *this;
        }

        virtual const char *what() const throw()
        {
                return _str.c_str();
        }

        virtual ~runtime_error() throw()
        {
        }
};

inline double tv_to_sec(const timeval &tv)
{
        return 1.0 * tv.tv_sec + (1.0 / 1000000000.0) * tv.tv_usec;
}

#endif //UTILS_H
