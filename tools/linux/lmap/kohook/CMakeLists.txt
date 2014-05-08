cmake_minimum_required(VERSION 2.8)

add_executable(kohook kohook.c)
target_link_libraries(kohook log elfrelink)
