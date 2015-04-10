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

// This file starts and stops the extension and manages the lifecycle of both
// character devices created by the extension.

#include "MacPmem.h"
#include "logging.h"
#include "pmem_common.h"
#include "meta.h"
#include "pte_mmap.h"
#include "notifiers.h"

#include <libkern/libkern.h>
#include <sys/conf.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <miscfs/devfs/devfs.h>
#include <libkern/OSAtomic.h>


// Used to keep track of the number of active users. We can use this
// information to decide when to turn on autounload on idle.
int pmem_open_count = 0;

int pmem_majorno = PMEM_MAJOR;
OSKextLoadTag pmem_load_tag;

const char * const pmem_tagname = "pmem_tag";
OSMallocTag pmem_tag = 0;

lck_grp_t *pmem_rwlock_grp = 0;
lck_grp_attr_t *pmem_rwlock_grp_attr = 0;
lck_grp_t *pmem_mutex_grp = 0;
lck_grp_attr_t *pmem_mutex_grp_attr = 0;


// Switch table callbacks - forward declarations.
static kern_return_t pmem_open(dev_t dev, __unused int flags,
                               __unused int devtype,
                               __unused proc_t proc);
static kern_return_t pmem_read(dev_t dev, struct uio *uio,
                                    __unused int rw);
static kern_return_t pmem_close(dev_t dev, __unused int flags,
                                __unused int devtype,
                                __unused proc_t proc);

// /dev/pmem and /dev/pmem_info switch table.
// eno_ values mean the call is disabled.
// This is a character device.
static struct cdevsw pmem_cdevsw = {
    pmem_open,                            /* open */
    pmem_close,                           /* close */
    pmem_read,                            /* read */
    eno_rdwrt,                            /* write */
    eno_ioctl,                            /* ioctl */
    eno_stop,                             /* stop */
    eno_reset,                            /* reset */
    0,                                    /* tty's */
    eno_select,                           /* select */
    eno_mmap,                             /* mmap */
    eno_strat,                            /* strategy */
    eno_getc,                             /* getc */
    eno_putc,                             /* putc */
    D_TTY                                 /* type */
};


SYSCTL_INT(_kern, OID_AUTO, pmem_logging, CTLTYPE_INT | CTLFLAG_WR,
           &pmem_logging_level, 0, "Pmem logging level");
static int pmem_sysctl_needs_cleanup = 0;


#define PMEM_DEV_MINOR 1
static const char *pmem_devname = "pmem";
static void *pmem_infonode = 0;


#define PMEM_INFO_MINOR 2
static const char *pmem_infoname = "pmem_info";
static void *pmem_devnode = 0;

#ifdef DEBUG
#define PMEM_DEV_PERMS 0666
#else
#define PMEM_DEV_PERMS 0660
#endif


static kern_return_t pmem_open(dev_t dev, __unused int flags,
                               __unused int devtype,
                               __unused proc_t proc) {
    kern_return_t ret;
    switch (minor(dev)) {
        case PMEM_DEV_MINOR:
            ret = KERN_SUCCESS;
            OSIncrementAtomic(&pmem_open_count);
            break;
        case PMEM_INFO_MINOR:
            ret = pmem_openmeta();
            OSIncrementAtomic(&pmem_open_count);
            break;
        default:
            pmem_warn("Unknown minor device number %d.", minor(dev));
            ret = KERN_FAILURE;
    }

    return ret;
}


static kern_return_t pmem_close(dev_t dev, __unused int flags,
                                __unused int devtype,
                                __unused proc_t proc) {
    kern_return_t ret;
    switch (minor(dev)) {
        case PMEM_DEV_MINOR:
            ret =  KERN_SUCCESS;
            OSDecrementAtomic(&pmem_open_count);
            break;
        case PMEM_INFO_MINOR:
            ret = pmem_closemeta();
            OSDecrementAtomic(&pmem_open_count);
            break;
        default:
            pmem_warn("Unknown minor device number %d.", minor(dev));
            ret = KERN_FAILURE;
    }

    return ret;
}



static kern_return_t pmem_read(dev_t dev, struct uio *uio,
                               __unused int rw) {
    switch (minor(dev)) {
    case PMEM_DEV_MINOR:
        return pmem_read_rogue(uio);
    case PMEM_INFO_MINOR:
        // Reading from the info device is conceptually the same as calling
        // the sysctl to get the struct.
        return pmem_readmeta(uio);
    default:
        pmem_warn("Unknown minor device number %d.", minor(dev));
        return KERN_FAILURE;
    }
}


// Tries to free all resources; passes through any errors.
//
// args: 'error' will be returned unchanged if no further errors are
// encountered.
// return: value of 'error' if no further errors encountered; otherwise
//         KERN_FAILURE.
static kern_return_t pmem_cleanup(kern_return_t error) {
    if (pmem_devnode) {
        devfs_remove(pmem_devnode);
    }

    if (pmem_infonode) {
        devfs_remove(pmem_infonode);
    }

    if (pmem_majorno > 0) {
        int removed_idx = 0;
        removed_idx = cdevsw_remove(pmem_majorno, &pmem_cdevsw);
        if(removed_idx != pmem_majorno) {
            pmem_error("Failed to remove cdevsw! Major number is %d, "
                       "but cdevsw_remove() returned %d.",
                       pmem_majorno, removed_idx);
            error = KERN_FAILURE;
        }
    }

    if (pmem_tag) {
        OSMalloc_Tagfree(pmem_tag);
    }

    pmem_meta_cleanup();
    pmem_pte_cleanup();
//    pmem_sleep_cleanup(); // Disabled - see the start function.

    if (pmem_sysctl_needs_cleanup) {
        sysctl_unregister_oid(&sysctl__kern_pmem_logging);
    }

    // Free lock groups.
    lck_grp_attr_free(pmem_mutex_grp_attr);
    lck_grp_free(pmem_mutex_grp);

    lck_grp_attr_free(pmem_rwlock_grp_attr);
    lck_grp_free(pmem_rwlock_grp);

    return error;
}


// Creates both devices.
static kern_return_t pmem_init() {
    // Set up OSMalloc tag for everyone.
    pmem_tag = OSMalloc_Tagalloc(pmem_tagname, OSMT_DEFAULT);

    // Set up a pmem lock groups for mutexes and rw locks.
    pmem_rwlock_grp_attr = lck_grp_attr_alloc_init();
    lck_grp_attr_setstat(pmem_rwlock_grp_attr);
    pmem_rwlock_grp = lck_grp_alloc_init("pmem_rwlock", pmem_rwlock_grp_attr);

    pmem_mutex_grp_attr = lck_grp_attr_alloc_init();
    lck_grp_attr_setstat(pmem_mutex_grp_attr);
    pmem_mutex_grp = lck_grp_alloc_init("pmem_mutex", pmem_mutex_grp_attr);


    pmem_majorno = cdevsw_add(PMEM_MAJOR, &pmem_cdevsw);
    if (pmem_majorno < 0) {
        pmem_error("Failed to register a major number.");
        return KERN_FAILURE;
    }

    pmem_debug("Major number is %d.", pmem_majorno);

    // Make the info device.
    pmem_infonode = devfs_make_node(makedev(pmem_majorno, PMEM_INFO_MINOR),
                                    DEVFS_CHAR, UID_ROOT, GID_WHEEL,
                                    PMEM_DEV_PERMS,
                                    pmem_infoname);
    if (!pmem_infonode) {
        pmem_error("Failed to create /dev/%s", pmem_infoname);
        return KERN_FAILURE;
    }
    pmem_info("/dev/%s created for the info device.", pmem_infoname);

    // Make the physical memory device.
    pmem_devnode = devfs_make_node(makedev(pmem_majorno, PMEM_DEV_MINOR),
                                   DEVFS_CHAR, UID_ROOT, GID_WHEEL,
                                   PMEM_DEV_PERMS,
                                   pmem_devname);
    if (!pmem_devnode) {
        pmem_error("Failed to create /dev/%s", pmem_devname);
        return KERN_FAILURE;
    }
    pmem_info("/dev/%s created for the physical memory device.", pmem_devname);

    return KERN_SUCCESS;
}


kern_return_t com_google_MacPmem_start(kmod_info_t * ki, void *d) {
    pmem_info("Loaded MacPmem.");

    kern_return_t error = pmem_init();
    if (error != KERN_SUCCESS) {
        pmem_fatal("pmem_init() failed.");
        return pmem_cleanup(error);
    }

    error = pmem_meta_init();
    if (error != KERN_SUCCESS) {
        pmem_fatal("Could not initialize pmem meta.");
        return pmem_cleanup(error);
    }

    error = pmem_pte_init();
    if (error != KERN_SUCCESS) {
        pmem_fatal("Could not initialize PTE mmap module.");
        return pmem_cleanup(error);
    }

    // Sleep notifier is disabled because sleep notifications seem to be broken
    // on Yosemite.
    //
    // The documentation states that kIOMessageSystemWillSleep notification
    // will be delivered to listeners who register for priority sleep/wake
    // interest but this is not actually the case on OS X 10.10, where
    // IONotifier seems to be completely broken and always delivers
    // kIOMessageSystemCapabilityChange regardless of what the notification is
    // actually supposed to be about. Cursory look at dmesg output around sleep
    // seems to confirm that this is broken for everybody, including Apple's
    // own kexts, for example the webcam driver:
    //
    //   AppleCamIn::systemWakeCall - messageType = 0xE0000340
    //
    // (0x340 corresponds to kIOMessageSystemCapabilityChange).
    //
    // Because this message type gets delivered all the time, it may actually
    // be possible to work around the bug by looking at the context argument.
    // Unfortunately, that's not typed and the documentation doesn't
    // say anything about it.

//    error = pmem_sleep_init();
//    if (error != KERN_SUCCESS) {
//        pmem_fatal("Could not initialize sleep notifier.");
//        return pmem_cleanup(error);
//    }

    sysctl_register_oid(&sysctl__kern_pmem_logging);
    pmem_sysctl_needs_cleanup = 1;

    pmem_load_tag = OSKextGetCurrentLoadTag();
    pmem_debug("MacPmem load tag is %d.", pmem_load_tag);

    return error;
}


kern_return_t com_google_MacPmem_stop(kmod_info_t *ki, void *d) {
    pmem_info("Unloading MacPmem");
    return pmem_cleanup(KERN_SUCCESS);
}
