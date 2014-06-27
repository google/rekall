// Enables debug logging in a debug build only
//
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

#ifndef _REKALL_DRIVER_DEBUG_H_
#define _REKALL_DRIVER_DEBUG_H_

// You can disable debug logging by commenting out this line,
// or defining DEBUG anywhere else in the code before including this.
//#define DEBUG

#ifdef DEBUG
#define DEBUG_LOG(...) \
  do { printk(__VA_ARGS__); } while (0)
#else
#define DEBUG_LOG(...)
#endif

#endif  // _REKALL_DRIVER_DEBUG_H_
