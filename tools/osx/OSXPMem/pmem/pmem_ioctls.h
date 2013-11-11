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

#ifndef _VOLATILITY_DRIVER_PMEM_IOCTLS_H_
#define _VOLATILITY_DRIVER_PMEM_IOCTLS_H_


#define PMEM_GET_MMAP 0
#define PMEM_GET_MMAP_SIZE 1
#define PMEM_GET_MMAP_DESC_SIZE 2
#define PMEM_GET_DTB 3

#define PMEM_MMAP_TYPE uint64_t
#define PMEM_MMAP_SIZE_TYPE uint32_t
#define PMEM_MMAP_DESC_SIZE_TYPE uint32_t
#define PMEM_DTB_TYPE uint64_t

#define PMEM_IOCTL_BASE 'p'

#define PMEM_IOCTL_GET_MMAP           _IOW(PMEM_IOCTL_BASE, \
                                           PMEM_GET_MMAP, \
                                           PMEM_MMAP_TYPE)
#define PMEM_IOCTL_GET_MMAP_SIZE      _IOR(PMEM_IOCTL_BASE, \
                                           PMEM_GET_MMAP_SIZE, \
                                           PMEM_MMAP_SIZE_TYPE)
#define PMEM_IOCTL_GET_MMAP_DESC_SIZE _IOR(PMEM_IOCTL_BASE, \
                                           PMEM_GET_MMAP_DESC_SIZE, \
                                           PMEM_MMAP_DESC_SIZE_TYPE)
#define PMEM_IOCTL_GET_DTB            _IOR(PMEM_IOCTL_BASE, \
                                           PMEM_GET_DTB, \
                                           PMEM_DTB_TYPE)

#endif  // _VOLATILITY_DRIVER_PMEM_IOCTLS_H_
