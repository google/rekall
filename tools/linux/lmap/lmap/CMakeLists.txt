cmake_minimum_required(VERSION 2.8)

add_executable(lmap lmap.c memory_map.c lkm_control.c)

target_link_libraries(lmap log elfrelink minpmem)
