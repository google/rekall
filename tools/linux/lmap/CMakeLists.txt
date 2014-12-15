cmake_minimum_required(VERSION 2.8)

project(lmap C)

# Force static linking
SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
# Configure lmap version and symbol information
# =============================================
set(MODULE_OUTPUT_DIR ${CMAKE_BINARY_DIR}/modules)
# Replace '/' with '_' for symbol resolution of embedded pmem
string(REGEX REPLACE "/" "_" ESCAPED_OUTPUT_DIR ${MODULE_OUTPUT_DIR})
# Set up versioning
set(LMAP_VERSION_MAJOR 0)
set(LMAP_VERSION_MINOR 6)
# Set the symbol names for embedded minpmem
set(MINPMEM_START _binary_${ESCAPED_OUTPUT_DIR}_pmem_pte_ko_start)
set(MINPMEM_END _binary_${ESCAPED_OUTPUT_DIR}_pmem_pte_ko_end)
set(MINPMEM_SIZE _binary_${ESCAPED_OUTPUT_DIR}_pmem_pte_ko_size)
configure_file(
  "${PROJECT_SOURCE_DIR}/lmap/lmap_config.h.in"
  "${PROJECT_BINARY_DIR}/lmap_config.h"
)
# Prepare the README for release
configure_file(
  "${PROJECT_SOURCE_DIR}/lmap/README.in"
  "${PROJECT_BINARY_DIR}/lmap/README"
)
# Now do actual build
# ===================
# Enable make to find the configured header file
include_directories("${PROJECT_BINARY_DIR}")
# Include used libraries
include_directories("${PROJECT_SOURCE_DIR}/log")
include_directories("${PROJECT_SOURCE_DIR}/elfrelink")
# Set compiler flags
add_definitions(-std=gnu99 -Wall -static)

add_subdirectory(log)
add_subdirectory(elfrelink)
add_subdirectory(minpmem)
add_subdirectory(lmap)
add_subdirectory(kohook)
add_subdirectory(test)
