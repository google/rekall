//  MacPmem - Rekall Memory Forensics
//  Copyright (c) 2015 Google Inc. All rights reserved.
//
//  Implements the /dev/pmem device to provide read/write access to
//  physical memory.
//
//  Authors:
//   Adam Sindelar (adam.sindelar@gmail.com)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __MacPmem__logging__
#define __MacPmem__logging__

#ifdef KERNEL
#include <mach/mach_types.h>
#include <libkern/libkern.h>
#else
#include <stdio.h>
#include <stdarg.h>
#endif

typedef enum {
    kPmemDebug = 4,
    kPmemInfo = 3,
    kPmemWarn = 2,
    kPmemError = 1,
    kPmemFatal = 0,
} PmemLogLevel;

extern int pmem_logging_level;

#ifdef __cplusplus
extern "C" {
#endif

void pmem_log(PmemLogLevel lvl, const char *fmt, ...) __printflike(2, 3);
void pmem_logv(PmemLogLevel lvl, const char *fmt, va_list args);

void pmem_debug(const char *fmt, ...) __printflike(1, 2);
void pmem_info(const char *fmt, ...) __printflike(1, 2);
void pmem_warn(const char * fmt, ...) __printflike(1, 2);
void pmem_error(const char *fmt, ...) __printflike(1, 2);
void pmem_fatal(const char *fmt, ...) __printflike(1, 2);

#ifdef __cplusplus
}
#endif

#endif /* defined(__MacPmem__logging__) */
