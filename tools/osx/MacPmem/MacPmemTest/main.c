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


// This file is here for two reasons. Firstly, it works as a primitive
// test-suite for the behavior of the kernel extension. Secondly, it provides
// example implementations of various userland components that cooperate with
// the extension.


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

#define PMEM_KEXT_PATH "./MacPmem.kext"
#define PMEM_KEXT_ID "com.google.MacPmem"

const int threadc = 16;
const ssize_t read_cmp_frame_len = 0x10;
const off_t read_cmp_frame_off = 0x2000;

const char *pmem_dev = "/dev/pmem";
const char *pmem_infodev = "/dev/pmem_info";


void *_test_contention_thread(__unused void *ctx) {
    char *buffer = malloc(read_cmp_frame_len);

    if (!buffer) {
        goto error;
    }

    int fd = open("/dev/pmem", O_RDONLY);

    if (fd < 0) {
        goto error;
    }

    lseek(fd, read_cmp_frame_off, SEEK_CUR);
    read(fd, buffer, read_cmp_frame_len);
    return buffer;

error:
    if (buffer) {
        free(buffer);
    }

    return 0;
}


// Tests /dev/pmem reads from multiple threads, ensuring consistent results.
int test_contention() {
    int ret = 0;
    pthread_t threadv[threadc];
    bzero(threadv, sizeof(threadv));
    void *curr_read = 0;
    void *prev_read = 0;

    // Create a bunch of threads that'll read /dev/pmem.
    for (int i = 0; i < threadc; ++i) {
        int ret = pthread_create(&threadv[i], 0,
                                 &_test_contention_thread,
                                 0);
        if (ret != 0) {
            pmem_error("Failed to create thread no %d to test contention.", i);
            break;
        }
    }

    // Join threads and compare their output.
    for (int i = 0; i < threadc; ++i) {
        if (!threadv[i]) {
            continue;
        }

        if (prev_read) {
            free(prev_read);
            prev_read = curr_read;
        }

        pthread_join(threadv[i], &curr_read);

        if (prev_read &&
            memcmp(prev_read, curr_read, read_cmp_frame_len) != 0) {
            pmem_warn("Thread read results %d and %d differ.", i, i - 1);
            ret = -1;
        }
    }

    if (curr_read) {
        free(curr_read);
    }

    if (prev_read) {
        free(prev_read);
    }

    pmem_debug("Joined %d threads.", threadc);

    return ret;
}


int load_kext() {
    int res = 0;
    pmem_debug("Going to load kext from %s.", PMEM_KEXT_PATH);

    CFStringRef kext_path = CFSTR(PMEM_KEXT_PATH);
    CFURLRef kext_url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault,
                                                      kext_path,
                                                      kCFURLPOSIXPathStyle,
                                                      true);
    if (KextManagerLoadKextWithURL(kext_url, 0) != kOSReturnSuccess) {
        pmem_error("Could not load %s. Try running kextutil on it to debug.",
                   PMEM_KEXT_PATH);
        res = -1;
    }

    CFRelease(kext_path);
    CFRelease(kext_url);

    return res;
}


int unload_kext() {
    int res = 0;
    pmem_debug("Unloading kext %s", PMEM_KEXT_ID);
    CFStringRef kext_id = CFSTR(PMEM_KEXT_ID);
    if (KextManagerUnloadKextWithIdentifier(kext_id) != kOSReturnSuccess) {
        pmem_error("Could not unload %s. Is it loaded?", PMEM_KEXT_ID);
        res = -1;
    }

    CFRelease(kext_id);

    return res;
}


int test_unload_with_open() {
    int res = 0;
    int fd = open("/dev/pmem", O_RDONLY);
    char buffer[read_cmp_frame_len];
    ssize_t bytes_read = 0;

    if (fd == -1) {
        pmem_error("Could not open /dev/pmem for reading.");
        return -1;
    }

    res = unload_kext();
    if (res != 0) {
        pmem_error("kext_unload failed with open fd.");
        return res;
    }

    lseek(fd, read_cmp_frame_off, SEEK_SET);
    bytes_read = read(fd, buffer, read_cmp_frame_len);
    close(fd);

    if (bytes_read > 0) {
        pmem_error("Read succeeded after kext_unload.!");
        return -1;
    } else {
        pmem_debug("Read after kext_unload failed as expected.");
    }

    res = load_kext();
    if (res != 0) {
        pmem_error("Could not reload the kext after unloading it.");
        return res;
    }

    return 0;
}


int test_phys_read() {
    int fd = open("/dev/pmem", O_RDONLY);
    int cres;
    const size_t len = 0x40;
    ssize_t rcv = 0;
    char buffer[len], buffer_[len];

    if (fd == -1) {
        pmem_error("Could not open /dev/pmem for reading.");
        return -1;
    }

    // Lets try reading a bit from the third page (should have some data).
    lseek(fd, 0x2000, SEEK_SET);
    rcv = read(fd, buffer, len);

    if (rcv != len) {
        pmem_error("Could not read from 0x2000 into /dev/pmem. Errno: %d",
                   errno);
        return -1;
    }

    // Non-page aligned reads should work.
    lseek(fd, 0x2002, SEEK_SET);
    rcv = read(fd, buffer_, len);

    if (rcv != len) {
        pmem_error("Could not read from 0x2000 into /dev/pmem. Errno: %d",
                   errno);
        return -1;
    }

    // Data should be making sense.
    cres = memcmp(buffer + 2, buffer_, 0x10);
    if (cres != 0) {
        pmem_error(("Page-aligned and non-aligned reads got different data: "
                    "%#016llx %#016llx != %#016llx %#016llx"),
                   *(uint64_t *)buffer, *(uint64_t *)(buffer + 0x8),
                   *(uint64_t *)buffer_, *(uint64_t *)(buffer_ + 0x8));
        return -1;
    }

    close(fd);
    return 0;
}


int test_info_read() {
    int fd = open("/dev/pmem_info", O_RDONLY);
    char buffer[0x1000];
    ssize_t rcv;
    int cres;
    const char *yml_header = "%YAML";

    if (fd == -1) {
        pmem_error("Could not open /dev/pmem_info for reading.");
        return -1;
    }

    rcv = read(fd, buffer, 0x1000);
    if (rcv < 0) {
        pmem_error("Could not read from /dev/pmem_info. Errno: %d",
                   errno);
        return -1;
    }

    cres = strncmp(buffer, yml_header, strlen(yml_header));

    if (cres != 0) {
        pmem_error("Expected /dev/pmem_info to start with '%s', not '%.*s'.",
                   yml_header, (int)strlen(yml_header), buffer);
        return -1;
    }

    close(fd);
    return 0;
}


int test_sysctl() {
    // This is how you get pmem_meta_t out using sysctl.
    int error = -1;
    pmem_meta_t *meta = 0;
    size_t metalen = 0;

    while (1) {
        // Get the required size of the meta struct (it varies).
        sysctlbyname(PMEM_SYSCTL_NAME, 0, &metalen, 0, 0);

        // Allocate the required number of bytes.
        meta = (pmem_meta_t *)malloc(metalen);
        error = sysctlbyname(PMEM_SYSCTL_NAME, meta, &metalen, 0, 0);
        if (error == 0 && metalen > 0) {
            break;
        }

        free(meta);
        if (errno != ENOMEM) {
            // If the call failed because the buffer was too small, we can
            // retry; bail otherwise.
            pmem_error("sysctlbyname() error: %d", errno);
            return -1;
        }
    }

    // We now have the meta struct. Print a couple of members.
    pmem_debug(("sysctl interface returned meta of size %u. Partial dump:\n"
                "  CR3: %#016llx\n"
                "  range_count: %u\n"
                "  first range (start+length): %#016llx+%llx\n"
                "  kernel_version: '%s'"),
               meta->size, meta->cr3, meta->range_count,
               meta->ranges[0].start, meta->ranges[0].length,
               meta->kernel_version);

    free(meta);
    return 0;
}


typedef int (*test_func_t)(void);
typedef struct {
    const char name[40];
    const test_func_t call;
} test_t;


const test_t tests[] = {
    {"test_sysctl", &test_sysctl},
    {"test_phys_read", &test_phys_read},
    {"test_info_read", &test_info_read},
    {"test_contention", &test_contention},
    {"test_unload_with_open", &test_unload_with_open},
};


int main(int argc, const char * argv[]) {
    pmem_logging_level = kPmemDebug;
    int error = 0;
    int test_count = sizeof(tests) / sizeof(test_t);

    error = load_kext();
    if (error != 0) {
        pmem_error("Could not load kernel extension from %s. Bailing.",
                   PMEM_KEXT_PATH);
        return -1;
    }

    for (int test = 0; test < test_count; ++test) {
        if(tests[test].call() == 0) {
            pmem_info("%s [PASS]", tests[test].name);
        } else {
            pmem_error("%s [FAIL]", tests[test].name);
            error |= (int) pow(2, test);
        }
    }

    if (error == 0) {
        pmem_info("All tests pass.");
    }

    unload_kext();
    return error;
}
