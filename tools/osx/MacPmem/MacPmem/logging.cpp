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

#include "logging.h"


#ifdef DEBUG
// Even in DEBUG, debug logging needs to be enabled, because it's annoying.
int pmem_logging_level = kPmemInfo;
#else
int pmem_logging_level = kPmemWarn;
#endif

extern "C" {

    void pmem_log(PmemLogLevel lvl, const char *fmt, ...) {
        va_list argptr;
        va_start(argptr, fmt);
        pmem_logv(lvl, fmt, argptr);
        va_end(argptr);
    }

    void pmem_logv(PmemLogLevel lvl, const char *fmt, va_list args) {
        if (lvl > pmem_logging_level) {
            return;
        }

        switch (lvl) {
            case kPmemDebug:
                printf("Debug: ");
                break;
            case kPmemInfo:
                printf("Info: ");
                break;
            case kPmemWarn:
                printf("Warning: ");
                break;
            case kPmemError:
                printf("Error: ");
                break;
            case kPmemFatal:
                printf("Fatal: ");
                break;
            default:
                break;
        }

        vprintf(fmt, args);
        printf("\n");
    }

    void pmem_debug(const char *fmt, ...) {
        va_list argptr;
        va_start(argptr, fmt);
        pmem_logv(kPmemDebug, fmt, argptr);
        va_end(argptr);
    }

    void pmem_info(const char *fmt, ...) {
        va_list argptr;
        va_start(argptr, fmt);
        pmem_logv(kPmemInfo, fmt, argptr);
        va_end(argptr);
    }

    void pmem_warn(const char * fmt, ...) {
        va_list argptr;
        va_start(argptr, fmt);
        pmem_logv(kPmemWarn, fmt, argptr);
        va_end(argptr);
    }

    void pmem_error(const char *fmt, ...) {
        va_list argptr;
        va_start(argptr, fmt);
        pmem_logv(kPmemError, fmt, argptr);
        va_end(argptr);
    }

    void pmem_fatal(const char *fmt, ...) {
        va_list argptr;
        va_start(argptr, fmt);
        pmem_logv(kPmemFatal, fmt, argptr);
        va_end(argptr);
    }

}