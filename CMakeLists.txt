cmake_minimum_required(VERSION 3.10.1)
project(pnettop)

set(CMAKE_CXX_STANDARD 11)

find_package(PkgConfig REQUIRED)
ADD_DEFINITIONS(-DDEBUG)

SET(SRC 
    main.cpp 
    packet_stats.cpp 
    proc.cpp 
    mt_list.h 
    pcap_mgr.cpp
)

add_executable(pnettop ${SRC})
target_link_libraries(pnettop pthread pcap)