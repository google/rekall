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

#include "tests.h"
#include "MacPmemTest.h"

// Helper to the test_contention test.
static void *_test_contention_thread(__unused void *ctx) {
    char *buffer = malloc(read_cmp_frame_len);
    const char *yml_header = "%YAML";

    // We don't return the results of reading pmem_info, but we want to
    // stress test it anyway.
    int fd = open("/dev/pmem_info", O_RDONLY);
    if (fd < 0) {
        goto error;
    }

    read(fd, buffer, read_cmp_frame_len);

    // Validate that info is returning reasonable YAML.
    if (strncmp(yml_header, buffer, read_cmp_frame_len) != 0) {
        goto error;
    }

    close(fd);

    if (!buffer) {
        goto error;
    }

    fd = open("/dev/pmem", O_RDONLY);

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

    if (meta->pmem_api_version == PMEM_API_VERSION) {
        pmem_debug("MacPmem API version %d matches that of this test suite.",
                   PMEM_API_VERSION);
    } else {
        pmem_warn("MacPmem API version is %d; this test suite expects %d.",
                  meta->pmem_api_version, PMEM_API_VERSION);
    }

    if (meta->records_offset == __offsetof(pmem_meta_t, records)) {
        pmem_debug("Relative offset of meta struct's records array is %llu",
                  meta->records_offset);
    } else {
        pmem_warn(("Relative offset of records array mismatch: "
                   "%llu (actual) vs %lu (computed)."),
                  meta->records_offset,
                  __offsetof(pmem_meta_t, records));
    }

    pmem_meta_record_t *record = (pmem_meta_record_t *)meta->records;
    // We now have the meta struct. Print a couple of members.
    pmem_debug(("sysctl interface returned meta of size %u. Partial dump:\n"
                "  CR3: %#016llx\n"
                "  range_count: %u\n"
                "  first range (start+length): %#016llx+%llx\n"
                "  kernel_version: '%s'"),
               meta->size, meta->cr3, meta->record_count,
               record->efi_range.start, record->efi_range.length,
               meta->kernel_version);

    free(meta);
    return 0;
}


int test_kextload_stress() {
    // Let's see if we can break things by loading and unloading the kext
    // a lot of times.
    int res = 0;
    int fd_pmem, fd_info;
    char buffer[0x1000];

    // Disable logging for this exercise.
    int old_do_check_perms = do_check_perms;
    do_check_perms = 0;
    int old_loglevel;
    int old_userland_loglevel = pmem_logging_level;
    int new_loglevel = 1;
    size_t loglevel_size = sizeof(int);

    res = sysctlbyname("kern.pmem_logging",
                       &old_loglevel, &loglevel_size, 0, 0);
    if (loglevel_size != sizeof(int) || res != 0) {
        pmem_error("Failed to get kern.pmem_logging.");
        return -1;
    }

    pmem_debug(("Disabled debug logging and file permission checks for the "
                "stress test. Old log level: %d; check_perms: %d."),
               old_loglevel, old_do_check_perms);

    // Also set the userland log level.
    pmem_logging_level = new_loglevel;

    unload_kext();

    for (int i = 0; i < 30; ++i) {
        load_kext();

        // Disable debug logging.
        res = sysctlbyname("kern.pmem_logging", 0, 0, &new_loglevel,
                           sizeof(int));
        if (res != 0) {
            pmem_error("Failed to set kern.pmem_logging.");
            return -1;
        }

        fd_pmem = open("/dev/pmem", O_RDONLY);
        if (fd_pmem == -1) {
            return -1;
        }

        fd_info = open("/dev/pmem_info", O_RDONLY);
        if (fd_info == -1) {
            return -1;
        }

        lseek(fd_pmem, 0x2100, SEEK_SET);
        read(fd_pmem, buffer, 0x1000);
        lseek(fd_info, 0x20, SEEK_SET);
        read(fd_info, buffer, 0x1000);

        unload_kext();
        close(fd_pmem);
        close(fd_info);
    }

    load_kext();

    // Re-enable debug logging.
    pmem_logging_level = old_userland_loglevel;
    res = sysctlbyname("kern.pmem_logging", 0, 0, &old_loglevel, sizeof(int));
    if (res != 0) {
        pmem_error("Failed to restore kern.pmem_logging.");
        return -1;
    }

    do_check_perms = old_do_check_perms;

    return 0;
}


// Tests invalid reads to /dev/pmem_info and /dev/pmem.
int test_invalid_reads() {
    int res = 0;
    int fd = open("/dev/pmem_info", O_RDONLY);
    char buffer[0x1000];
    ssize_t bytes_read;

    if (fd < 0) {
        pmem_error("Could not open /dev/pmem_info for reading.");
        return -1;
    }

    lseek(fd, -1000, SEEK_CUR);
    bytes_read = read(fd, buffer, 500);
    if (bytes_read > 0) {
        pmem_warn(("Read %lu bytes from offset -1000 of /dev/pmem_info."
                   "Dump: %#016llx... (%.*s)"),
                  bytes_read, *(unsigned long long *)buffer,
                  0x8, buffer);
        res = -1;
    }

    lseek(fd, 0x10000, SEEK_SET);
    bytes_read = read(fd, buffer, 0x1000);
    if (bytes_read > 0) {
        pmem_warn(("Read %lu bytes from offset 0x10000 of /dev/pmem_info."
                   "Dump: %#016llx... (%.*s)"),
                  bytes_read, *(unsigned long long *)buffer,
                  0x8, buffer);
        res = -1;
    }

    close(fd);

    fd = open("/dev/pmem", O_RDONLY);
    if (fd < 0) {
        pmem_error("Could not open /dev/pmem for reading.");
        return -1;
    }

    lseek(fd, -1000, SEEK_CUR);
    bytes_read = read(fd, buffer, 500);
    if (bytes_read > 0) {
        pmem_warn(("Read %lu bytes from offset -1000 of /dev/pmem."
                   "Dump: %#016llx... (%.*s)"),
                  bytes_read, *(unsigned long long *)buffer,
                  0x8, buffer);
        res = -1;
    }

    return res;
}
