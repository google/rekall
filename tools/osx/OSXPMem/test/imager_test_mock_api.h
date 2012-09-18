// These definitions replace file and ioctl related api's with mock functions.
// The mock functions are designed to work with imager.c only, so do not include
// this in any other file or you will break things!
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

#ifndef _VOLATILITY_PMEM_IMAGER_MOCK_API_H_
#define _VOLATILITY_PMEM_IMAGER_MOCK_API_H_

#include "imager_test_mock_fs.h"

#define ioctl(fd, request, outptr) mock_ioctl(fd, request, outptr)
#define open(path, flags, ...) mock_open(path, flags)
#define close(fd) mock_close(fd)
#define write(fd, buf, n) mock_write(fd, buf, n)
#define read(fd, buf, n) mock_read(fd, buf, n)
#define lseek(fd, offset, whence) mock_lseek(fd, offset, whence)
// the mocked imager does not need a main function
#define main(argc, argv) imager_main(argc, argv)

#endif  // _VOLATILITY_PMEM_IMAGER_MOCK_API_H_
