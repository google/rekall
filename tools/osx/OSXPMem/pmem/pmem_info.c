// These symbols are needed by the kextloader to identify the start/stop
// routines.
//
// Copyright 2012 Google Inc. All Rights Reserved.
// Author: Johannes Stüttgen (johannes.stuettgen@gmail.com)
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

#include <mach/mach_types.h>

extern kern_return_t _start(kmod_info_t *ki, void *data);
extern kern_return_t _stop(kmod_info_t *ki, void *data);
__private_extern__ kern_return_t pmem_start(kmod_info_t *ki, void *data);
__private_extern__ kern_return_t pmem_stop(kmod_info_t *ki, void *data);

__attribute__((visibility("default"))) KMOD_EXPLICIT_DECL(volatility.driver.pmem
                                                          ,"1.0.0d1",
                                                          _start,
                                                          _stop)
__private_extern__ kmod_start_func_t *_realmain = pmem_start;
__private_extern__ kmod_stop_func_t *_antimain = pmem_stop;
__private_extern__ int _kext_apple_cc = __APPLE_CC__ ;
