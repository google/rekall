/*
Copyright 2014 Google Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.  You may obtain a copy of the
License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied.  See the License for the
specific language governing permissions and limitations under the License.
*/

#include "pmem.h"
#ifdef _WIN32
# include "win_pmem.h"
#define IMAGER_CLASS WinPmemImager

#elif defined(__linux__)
# include "linux_pmem.h"
#define IMAGER_CLASS LinuxPmemImager

#elif defined(__APPLE__) && defined(__MACH__)
# include "osxpmem.h"
#define IMAGER_CLASS OSXPmemImager
#endif

#include <glog/logging.h>
#include <signal.h>

AFF4Status PmemImager::Initialize() {
  AFF4Status res = BasicImager::Initialize();
  if (res != STATUS_OK)
    return res;

  // Add the memory namespace to the resolver.
  LOG(INFO) << "Adding the memory namespaces.";
  resolver.namespaces.push_back(
      std::pair<string, string>("memory", AFF4_MEMORY_NAMESPACE));

  return STATUS_OK;
}

AFF4Status PmemImager::ParseArgs() {
  // Process the baseclass first.
  AFF4Status result = BasicImager::ParseArgs();

  // When the user specifies elf we need to check for incompatible options.
  if (result == CONTINUE && Get("elf")->isSet()) {
    if (Get("input")->isSet() || Get("pagefile")->isSet()) {
      LOG(ERROR) << "--elf is incompatible with --input and --pagefile because "
          "we can not store multiple streams in an ELF file.\n";
      return INCOMPATIBLE_TYPES;
    }

    if (Get("compression")->isSet()) {
      LOG(ERROR) << "--elf files do not support any compression.";
      return INCOMPATIBLE_TYPES;
    }
  }

  return result;
}

AFF4Status PmemImager::ImagePhysicalMemoryToElf() {
  return NOT_IMPLEMENTED;
}


AFF4Status PmemImager::ProcessArgs() {
  // Add the memory namespace to the resolver.
  resolver.namespaces.push_back(
      std::pair<string, string>("memory", AFF4_MEMORY_NAMESPACE));

  AFF4Status result = BasicImager::ProcessArgs();
  if (result != CONTINUE) {
    return result;
  }

  // We automatically image memory if no other actions were given (unless the -m
  // flag was explicitly given).
  if ((actions_run.size() > 0) && !Get("acquire-memory")->isSet())
    return STATUS_OK;

  // The user forgot to specify an output file.
  if (!Get("output")->isSet()) {
    LOG(ERROR) << "You need to specify an output file with --output.";
    return INVALID_INPUT;
  }

  // Does the user want an elf format or aff4 format?
  if (Get("elf")->isSet()) {
    result = ImagePhysicalMemoryToElf();
  } else {
    result = ImagePhysicalMemory();
  }

  return result;
}


AFF4Status PmemImager::handle_pagefiles() {
  pagefiles = GetArg<TCLAP::MultiArgToNextFlag<string>>(
      "pagefile")->getValue();

  return CONTINUE;
}

#ifdef _WIN32
PmemImager::~PmemImager() {
  // Remove all files that need to be removed.
  for (URN it : to_be_removed) {
    string filename = it.ToFilename();
    if (!DeleteFile(filename.c_str())) {
      LOG(INFO) << "Unable to delete " << filename << ": " <<
          GetLastErrorMessage();

    } else {
      LOG(INFO) << "Removed " << filename;
    }
  }
}
#else
PmemImager::~PmemImager() {
}
#endif

IMAGER_CLASS imager;

#ifdef _WIN32
BOOL sigint_handler(DWORD dwCtrlType) {
  imager.Abort();

  return TRUE;
}
#else
#include <signal.h>
void sigint_handler(int s) {
  imager.Abort();
}
#endif

int main(int argc, char* argv[]) {
  // Initialize Google's logging library.
  google::InitGoogleLogging(argv[0]);

  google::LogToStderr();
  google::SetStderrLogging(google::GLOG_ERROR);

#ifdef _WIN32
  if (!SetConsoleCtrlHandler((PHANDLER_ROUTINE)sigint_handler, true)) {
    LOG(ERROR) << "Unable to set interrupt handler: " <<
        GetLastErrorMessage();
  }
#else
  signal(SIGINT, sigint_handler);
#endif

  AFF4Status res = imager.Run(argc, argv);
  if (res == STATUS_OK || res == CONTINUE)
    return 0;

  LOG(ERROR) << "Imaging failed with error: " << res;

  return res;
}
