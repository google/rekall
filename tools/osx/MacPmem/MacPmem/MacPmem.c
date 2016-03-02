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
#include "safety.h"
#include "notifiers.h"

#include <libkern/libkern.h>
#include <sys/conf.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <miscfs/devfs/devfs.h>
#include <libkern/OSAtomic.h>


#ifndef PMEM_WRITE_ENABLED
// If set to 1, this will allow writes to actually go through to the combined
// rw handler and modify live memory. This is almost universally a bad idea
// because it bypasses any locking and, if the pages being written to have a
// corresponding virtual page with cache semantics then writing to the
// underlying physical page will have undefined results. You've been warned.
#define PMEM_WRITE_ENABLED 0

#endif


#if PMEM_WRITE_ENABLED
// This will put the string "PMEM_WRITE_MODE" in the binary if it's compiled
// with write support. We can use that to easily spot write-enabled extensions.
const char * const pmem_write_safety = "PMEM_WRITE_MODE";
#endif


// Used to keep track of the number of active users. We can use this
// information to decide when to turn on autounload on idle.
int pmem_open_count = 0;

// Owned by sysctl. Controls whether IO to the physical memory device will
// permit access to ranges that EFI considers unsafe.
int pmem_allow_unsafe_operations = 0;

int pmem_majorno = PMEM_MAJOR;
OSKextLoadTag pmem_load_tag;

const char * const pmem_tagname = "pmem_alloc_tag";
OSMallocTag pmem_alloc_tag = 0;

lck_grp_t *pmem_rwlock_grp = 0;
lck_grp_attr_t *pmem_rwlock_grp_attr = 0;
lck_grp_t *pmem_mutex_grp = 0;
lck_grp_attr_t *pmem_mutex_grp_attr = 0;


////////////////////////////////////////////////////////////////////////////////
// MARK: Shared character device switchtable and handlers
////////////////////////////////////////////////////////////////////////////////

// Opens the device - shared by info and pmem.
//
// Arguments:
//   dev - device object
//   devtype - unusued; safe to pass 0
//   proc_t - process accessing the device
//
// Returns:
//   KERN_SUCCESS if the device is valid. Otherwise fails.
static kern_return_t pmem_open(dev_t dev, __unused int flags,
                               __unused int devtype,
                               __unused proc_t proc);

// Reads from info or pmem.
//
// Arguments:
//   dev - the device to read from
//   uio - uio struct to read into (see man page for uio)
//   rw - this is ignored; pass any int
//
// Returns:
//   KERN_SUCCESS if read completed successfully. Note that if the safety is on
//   (see pmem_allow_unsafe_operations) then reading from an unsafe range WILL
//   NOT cause this call to fail. Instead, the read will be silently padded with
//   zeroed memory.
static kern_return_t pmem_write(dev_t dev, struct uio *uio,
                                __unused int rw);


// Reads to pmem.
//
// Arguments:
//   dev - the device to write to
//   uio - uio struct to read from (see man page for uio)
//   rw - this is ignored; pass any int
//
// Returns:
//   KERN_SUCCESS if write succeeded. Writes can fail due to the safety rangemap
//   or by attempting to write to an invalid offset.
static kern_return_t pmem_read(dev_t dev, struct uio *uio,
                               __unused int rw);

// Close the device - shared by info and pmem.
//
// Arguments:
//   dev - device object to close
//   devtype - unusuded; safe to pass 0
//   proc_t - the process that's closing this
//
// Returns:
//   KERN_SUCCESS (can't fail).
static kern_return_t pmem_close(dev_t dev, __unused int flags,
                                __unused int devtype,
                                __unused proc_t proc);


// /dev/pmem and /dev/pmem_info shared character device switch table.
static struct cdevsw pmem_cdevsw = {
    pmem_open,                            /* open */
    pmem_close,                           /* close */
    pmem_read,                            /* read */
    pmem_write,                           /* write */
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


////////////////////////////////////////////////////////////////////////////////
// MARK: sysctl handlers for configurable behavior
////////////////////////////////////////////////////////////////////////////////

// Controls whether unsafe reads are allowed.
SYSCTL_INT(_kern, OID_AUTO, pmem_allow_unsafe_operations,
           CTLTYPE_INT | CTLFLAG_WR,
           &pmem_allow_unsafe_operations, 0,
           "Allow writes and unsafe reads to pmem.");

// Controls the logging level (defined in logging.h).
SYSCTL_INT(_kern, OID_AUTO, pmem_logging,
           CTLTYPE_INT | CTLFLAG_WR,
           &pmem_logging_level, 0,
           "Pmem logging level.");

// Do we need to cleanup after sysctl when shutting down?
static int pmem_sysctl_needs_cleanup = 0;


////////////////////////////////////////////////////////////////////////////////
// MARK: Individual device names, numbers and objects
////////////////////////////////////////////////////////////////////////////////

// /dev/pmem minor number and name.
#define PMEM_DEV_MINOR 1
static const char *pmem_devname = PMEM_DEVNAME;
static void *pmem_infonode = 0;

// /dev/pmem_info minor number and name.
#define PMEM_INFO_MINOR 2
static const char *pmem_infoname = PMEM_DEVINFO;
static void *pmem_devnode = 0;

// Debug builds don't require root on the machine. It's not a good idea to
// distribute those.
#ifdef DEBUG
#define PMEM_DEV_PERMS 0666
#else
#define PMEM_DEV_PERMS 0660
#endif

////////////////////////////////////////////////////////////////////////////////
// MARK: Handler implementations
////////////////////////////////////////////////////////////////////////////////

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
        pmem_error("Unknown minor device number in pmem_open: %d.",
                   minor(dev));
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
        pmem_error("Unknown minor device number in pmem_close: %d.",
                   minor(dev));
        ret = KERN_FAILURE;
    }

    return ret;
}


static kern_return_t pmem_read(dev_t dev, struct uio *uio,
                               __unused int rw) {
    switch (minor(dev)) {
    case PMEM_DEV_MINOR:
        return pmem_readwrite_physmem(uio);
    case PMEM_INFO_MINOR:
        // Reading from the info device is conceptually the same as calling
        // the sysctl to get the struct.
        return pmem_readmeta(uio);
    default:
        pmem_error("Unknown minor device number in pmem_read: %d.",
                   minor(dev));
        return KERN_FAILURE;
    }
}


static kern_return_t pmem_write(dev_t dev, struct uio *uio,
                                __unused int rw) {
    switch (minor(dev)) {
    case PMEM_DEV_MINOR:
#if PMEM_WRITE_ENABLED
        if (!pmem_allow_unsafe_operations) {
            // RW safety has to be disabled before writes are allowed.
            pmem_warn("You must set kern.pmem_allow_unsafe_operations"
                      "to 1 before writing to %s", pmem_devname);
            return KERN_FAILURE;
        }

        return pmem_readwrite_physmem(uio);
#else
        return KERN_FAILURE;
#endif
    case PMEM_INFO_MINOR:
        // Writing the info device isn't supported.
        return KERN_FAILURE;
    default:
        pmem_error("Unknown minor device in pmem_write: %d.",
                   minor(dev));
        return KERN_FAILURE;
    }
}


////////////////////////////////////////////////////////////////////////////////
// MARK: MacPmem initialization and teardown
////////////////////////////////////////////////////////////////////////////////

// Tries to free all resources; passes through any errors.
//
// Arguments:
//   error: Will be returned unchanged if no further errors are encountered.
// Returns:
//   Value of 'error' if no further errors encountered; otherwise KERN_FAILURE.
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

    pmem_meta_cleanup();
    pmem_pte_cleanup();
    pmem_safety_cleanup();
//    pmem_sleep_cleanup(); // Disabled - see the start function.

    if (pmem_sysctl_needs_cleanup) {
        sysctl_unregister_oid(&sysctl__kern_pmem_logging);
        sysctl_unregister_oid(&sysctl__kern_pmem_allow_unsafe_operations);
    }

    lck_grp_attr_free(pmem_mutex_grp_attr);
    lck_grp_free(pmem_mutex_grp);

    lck_grp_attr_free(pmem_rwlock_grp_attr);
    lck_grp_free(pmem_rwlock_grp);

    // Needs to be the last thing because we still may need it above for frees.
    if (pmem_alloc_tag) {
        OSMalloc_Tagfree(pmem_alloc_tag);
    }

    return error;
}


// Creates both devices.
static kern_return_t pmem_init() {
    // This malloc tag is used by everyone - needs to be the first thing.
    pmem_alloc_tag = OSMalloc_Tagalloc(pmem_tagname, OSMT_DEFAULT);

#ifdef LOG_KERNEL_POINTERS
    // If we're going to log pointers we need to tell the logging system what
    // tag to use when it's formatting them.
    pmem_logging_malloc_tag = pmem_alloc_tag;
#endif

    // Same as the malloc tag, lock groups are shared and need to be setup
    // by the time we initialize other components.
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

    error = pmem_safety_init();
    if (error != KERN_SUCCESS) {
        pmem_fatal("Could not initialize RW safety module.");
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
    sysctl_register_oid(&sysctl__kern_pmem_allow_unsafe_operations);
    pmem_sysctl_needs_cleanup = 1;

    pmem_load_tag = OSKextGetCurrentLoadTag();
    pmem_debug("MacPmem load tag is %d.", pmem_load_tag);

    return error;
}


kern_return_t com_google_MacPmem_stop(kmod_info_t *ki, void *d) {
    pmem_info("Unloading MacPmem");
    return pmem_cleanup(KERN_SUCCESS);
}
