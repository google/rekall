//
//  notifiers.cpp
//  MacPmem
//
//  Created by Adam Sindelar on 4/8/15.
//  Copyright (c) 2015 Google. All rights reserved.
//

#include "notifiers.h"
#include "logging.h"

#include <IOKit/pwr_mgt/RootDomain.h>
#include <IOKit/pwr_mgt/IOPM.h>
#include <IOKit/IOService.h>
#include <IOKit/IONotifier.h>


static IONotifier *pmem_notifier = nullptr;

extern "C" {

IOReturn pmem_sleep_handler(void *target, void *refCon,
                            UInt32 messageType, IOService *provider,
                            void *messageArgument, vm_size_t argSize) {

    OSReturn osret = kOSReturnSuccess;

    if ((messageType == kIOMessageSystemWillSleep ||
        messageType == kIOMessageCanSystemSleep) &&
        pmem_open_count == 0) {

        // We got a sleep notification and our open count was zero. Let's
        // shut down, to avoid hanging around for too long.
        //
        // It is possible that someone will open a device while we're in this
        // branch and increase the pmem_open_count. That's fine - the kext
        // manager will invalidate any outstanding handles as it performs
        // shutdown.

        pmem_info("System is going to sleep. Dropping retain count and "
                  "unregistering notifier.");

        // We can trigger almost immediate shutdown by retaining ourselves and
        // then releasing right away. The retain causes the system to enable
        // autounload, and manual release causes a scan for autounload-enabled
        // kexts to begin immediately, which will likely preempt event the rest
        // of this routine.

        osret = OSKextRetainKextWithLoadTag(pmem_load_tag);
        if (osret == kOSReturnSuccess) {
            osret = OSKextReleaseKextWithLoadTag(pmem_load_tag);
        }
    }

    acknowledgeSleepWakeNotification(refCon);

    if (osret != kOSReturnSuccess) {
        pmem_warn(("Retaining or releasing the kext in sleep/wake handler"
                   "has failed."));
    }

    return kIOReturnSuccess;
}

kern_return_t pmem_sleep_init() {
    pmem_notifier = registerPrioritySleepWakeInterest(&pmem_sleep_handler, 0);
    return KERN_SUCCESS;
}

kern_return_t pmem_sleep_cleanup() {
    if (pmem_notifier) {
        pmem_notifier->remove();
        pmem_notifier = nullptr;
    }

    return KERN_SUCCESS;
}

}
