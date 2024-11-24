cmake_minimum_required(VERSION 3.28)
project(WorkingOnIt C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

add_executable(WorkingOnIt
        bw_template_recv_approach_multi_shared_store.c
        linkedlist_pairs.c
        linkedlist_pairs.h
        bw_template_pd.c
        bw_template_pd_getreq.c)
