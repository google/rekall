//
//  notifiers.h
//  MacPmem
//
//  Created by Adam Sindelar on 4/8/15.
//  Copyright (c) 2015 Google. All rights reserved.
//

#ifndef __MacPmem__notifiers__
#define __MacPmem__notifiers__

#include "MacPmem.h"
#include <IOKit/IOLib.h>
#include <libkern/OSTypes.h>

#ifdef __cplusplus
extern "C" {
#endif

kern_return_t pmem_sleep_init();
kern_return_t pmem_sleep_cleanup();

#ifdef __cplusplus
}
#endif

#endif /* defined(__MacPmem__notifiers__) */
