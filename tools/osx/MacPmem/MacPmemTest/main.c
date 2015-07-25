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


#include "MacPmemTest.h"
#include "tests.h"

#include <sys/stat.h>
#include <fts.h>

#define DEFAULT_PMEM_KEXT_PATH "./MacPmem.kext"
#define DEFAULT_PMEM_KEXT_ID "com.google.MacPmem"

const int threadc = 16;
const ssize_t read_cmp_frame_len = 0x10;
const off_t read_cmp_frame_off = 0x2000;

const char *pmem_dev = ("/dev/" PMEM_DEVNAME);
const char *pmem_infodev = ("/dev/" PMEM_DEVINFO);

// Options
int do_check_perms = 1;
int do_fix_perms = 1;
int do_run_tests = 1;
int do_test_writes = 0;
int do_test_kext = 1;
int do_unload_kext = 1;

char *pmem_kext_path = DEFAULT_PMEM_KEXT_PATH;
char *pmem_kext_id = DEFAULT_PMEM_KEXT_ID;


static int entcmp(const FTSENT **x, const FTSENT **y) {
    return strcmp((*x)->fts_name, (*y)->fts_name);
}


static int prepare_kext() {
    FTS *tree = 0;
    FTSENT *file = 0;
    int res = 0;
    int fixes_count = 0;
    struct stat *statp;

    char *tree_argv[] = {pmem_kext_path, 0};
    tree = fts_open(tree_argv, FTS_LOGICAL, entcmp);
    while ((file = fts_read(tree))) {
        switch (file->fts_info) {
        case FTS_ERR:
            pmem_warn("FTS error at path %s.", file->fts_path);
            break;
        case FTS_DNR:
            pmem_error("Could not open %s. Are you root?", file->fts_path);
            res = -1;
            goto bail;
        case FTS_NS:
            pmem_error("Could not stat %s. Are you root?", file->fts_path);
            res = -1;
            goto bail;
        case FTS_DP:
            continue;
        case FTS_DC:
            // Cycle.
            pmem_warn("Cycle at path %s.", file->fts_path);
            continue;
        case FTS_F:
        case FTS_D:
            statp = file->fts_statp;

            // Fix/validate ownership.
            if (statp->st_gid != 0 || statp->st_uid != 0) {
                if (!do_fix_perms) {
                    pmem_error("%s must be owned by root:wheel (is %d:%d).",
                               file->fts_path, statp->st_gid,
                               statp->st_uid);
                    res = -1;
                    goto bail;
                }

                res = chown(file->fts_path, 0, 0);
                if (res < 0) {
                    pmem_error("Could not chown %s. Are you root?",
                               file->fts_path);
                    goto bail;
                }

                ++fixes_count;
            }

            // Fix/validate chmod.
            if ((statp->st_mode & 0777) != 0700) {
                if (!do_fix_perms) {
                    pmem_error("Mode on %s must be 0700 (is %#03o).",
                               file->fts_path, statp->st_mode);
                    res = -1;
                    goto bail;
                }

                res = chmod(file->fts_path, 0700);
                if (res < 0) {
                    pmem_error("Could not chmod %s. Are you root?",
                               file->fts_path);
                    goto bail;
                }

                ++fixes_count;
            }

            break;
        }
    }

bail:
    if (tree) {
        fts_close(tree);
    }

    if (fixes_count) {
        pmem_debug("Made %d fixes to ownership/permissions on %s.",
                   fixes_count, pmem_kext_path);
    }

    return res;
}


int load_kext() {
    int res = 0;
    pmem_debug("Going to load kext from %s.", pmem_kext_path);

    res = prepare_kext();
    if (res < 0) {
        pmem_error("Could not validate kext %s.", pmem_kext_path);
        return res;
    }

    CFStringRef kext_path = CFStringCreateWithCString(kCFAllocatorDefault,
                                                      pmem_kext_path,
                                                      kCFStringEncodingASCII);
    CFURLRef kext_url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault,
                                                      kext_path,
                                                      kCFURLPOSIXPathStyle,
                                                      true);
    if (KextManagerLoadKextWithURL(kext_url, 0) != kOSReturnSuccess) {
        pmem_error("Could not load %s. Try running kextutil on it to debug.",
                   pmem_kext_path);
        res = -1;
    }

    CFRelease(kext_path);
    CFRelease(kext_url);

    return res;
}


int unload_kext() {
    int res = 0;
    pmem_debug("Unloading kext %s.", pmem_kext_id);
    CFStringRef kext_id = CFStringCreateWithCString(kCFAllocatorDefault,
                                                    pmem_kext_id,
                                                    kCFStringEncodingASCII);
    if (KextManagerUnloadKextWithIdentifier(kext_id) != kOSReturnSuccess) {
        pmem_error("Could not unload %s. Is it loaded?", pmem_kext_id);
        res = -1;
    }

    CFRelease(kext_id);

    return res;
}


int run_tests() {
    int error = 0;
    int test_count = sizeof(tests) / sizeof(test_t);

    for (int test = 0; test < test_count; ++test) {
        // Are we testing the kext?
        if (tests[test].flags & TEST_REQUIRE_KEXT && !do_test_kext) {
            continue;
        }

        // Are we testing write support, too?
        if (tests[test].flags & TEST_REQUIRE_WRITE && !do_test_writes) {
            continue;
        }

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

    return error;
}


int main(int argc, const char * argv[]) {
    pmem_logging_level = kPmemDebug;
    int error = 0;

    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd))) {
        pmem_debug("Current working directory: %s", cwd);
    }

    if (do_test_kext) {
        error = load_kext();
        if (error != 0) {
            pmem_warn("Could not load kernel extension from %s. Disabling "
                      "kext tests.", pmem_kext_path);
            do_test_kext = 0;
            do_test_writes = 0;
            do_unload_kext = 0;
        }
    }

    if (do_run_tests) {
        error = run_tests();
    }

    if (do_test_kext && do_unload_kext) {
        unload_kext();
    }

    return error;
}
