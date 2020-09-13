// This module uses obfuscated GetProcAddress calls to load certain functions
// which are usually only used by memory acquisition tools. This makes it a
// little bit harder to recognize us as an acquisition tool.
#ifndef _API_H_
#define _API_H_

#include <ntifs.h>
#include <wdmsec.h>
#include <initguid.h>
#include <stdarg.h>
#include <stdio.h>

// Select a better/different key or obfuscation scheme here.
#define OBFUSCATION_KEY "\x43\x73\x17\x54\x19\x3C\x42\xE5\xA2\x6B\x7C\x8A\x1C\x2E\x5C\x2C\x95\xCD\xC8\x3A\x68\x54\xEE\xC9\x36\x55\xCB\xE9\x4D\x98\x05\x04\x20\x5E\x77\x0F\xCD\x09\x35\xAF\x4C\xF8\x45\x22\x12\x30\x8F\xCB\x55\xC4"

#define X_MmGetPhysicalMemoryRanges "\x0E\x1E\x50\x31\x6D\x6C\x2A\x9C\xD1\x02\x1F\xEB\x70\x63\x39\x41\xFA\xBF\xB1\x68\x09\x3A\x89\xAC\x45\x55"
#define X_MmGetVirtualForPhysical "\x0E\x1E\x50\x31\x6D\x6A\x2B\x97\xD6\x1E\x1D\xE6\x5A\x41\x2E\x7C\xFD\xB4\xBB\x53\x0B\x35\x82\xC9"
#define X_MmMapIoSpace "\x0E\x1E\x5A\x35\x69\x75\x2D\xB6\xD2\x0A\x1F\xEF\x1C"
#define X_MmUnmapIoSpace "\x0E\x1E\x42\x3A\x74\x5D\x32\xAC\xCD\x38\x0C\xEB\x7F\x4B\x5C"

struct Pmem_KernelExports_t {
  PHYSICAL_MEMORY_RANGE *(*MmGetPhysicalMemoryRanges)();
  void *(*MmGetVirtualForPhysical)(PHYSICAL_ADDRESS);
  unsigned char *(*MmMapIoSpace)(LARGE_INTEGER, int, int);
  void (*MmUnmapIoSpace)(unsigned char *, int);
};

extern struct Pmem_KernelExports_t Pmem_KernelExports;

NTSTATUS PmemGetProcAddresses();

#endif _API_H_
