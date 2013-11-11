// Simple error logging macro to output function and line numbers together with
// error message and errno.
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

#ifndef _ERROR_LOG_H_
#define _ERROR_LOG_H_

#define ERROR_LOG(...) do { printf("%s(%d): ",          \
                                   __func__, __LINE__); \
                            printf(__VA_ARGS__);        \
                            printf(" (%s)\n",           \
                                   strerror(errno));    \
                       } while (0)

#endif  // _ERROR_LOG_H_
