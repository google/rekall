// Simple logging functionality to prettify output and manage verbosity.
//
// Copyright 2013 Google Inc. All Rights Reserved.
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


#include <stdarg.h>
#include <stdio.h>

#include "log.h"

LOGLEVEL loglevel = LL_LOG;

void log_print(LOGLEVEL msglevel, char const*fmt, ...) {
  va_list argptr;

  if (msglevel > loglevel) {
    return;
  }
  va_start(argptr, fmt);
  switch (msglevel) {
    case LL_ERR:
      fprintf(stderr, "[-] ");
      vfprintf(stderr, fmt, argptr);
      fprintf(stderr, "\n");
      break;

    case LL_LOG:
      printf("[+] ");
      vprintf(fmt, argptr);
      printf("\n");
      break;

    case LL_DBG:
      printf("    ");
      vprintf(fmt, argptr);
      printf("\n");
      break;

    case LL_MSG:
      vprintf(fmt, argptr);
      printf("\n");
      break;

     case LL_NNL:
      printf("[+] ");
      vprintf(fmt, argptr);
      break;
  }
  va_end(argptr);
}
