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

#ifndef MacPmem_MacPmemTest_h
#define MacPmem_MacPmemTest_h

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/kext/KextManager.h>
#include <libkern/OSReturn.h>
#include <sys/cdefs.h>

#include "pmem_common.h"
#include "logging.h"

extern char *pmem_kext_path;
extern char *pmem_kext_id;

extern int do_check_perms;
extern int do_fix_perms;
extern int do_run_tests;
extern int do_unload_kext;

extern const int threadc;
extern const ssize_t read_cmp_frame_len;
extern const off_t read_cmp_frame_off;

extern const char *pmem_dev;
extern const char *pmem_infodev;

int load_kext();
int unload_kext();

#endif
