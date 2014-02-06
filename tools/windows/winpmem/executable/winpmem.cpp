/*
  Copyright 2012-2014 Michael Cohen <scudette@gmail.com>

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/********************************************************************
   This is a single binary memory imager for Windows.

   Supported systems:
    - Windows XPSP2 to Windows 8 inclusive, both 32 bit and 64 bit.

*********************************************************************/
#include "winpmem.h"


int WinPmem::pad(__int64 length) {
  int count = 1;
  int start = 0;

  ZeroMemory(buffer_, buffer_size_);

  while(start < length) {
    DWORD to_write = (DWORD)min(buffer_size_, length);
    if(!WriteFile(out_fd_, buffer_, to_write, &to_write, NULL)) {
      Log(TEXT("Failed to write padding... Aborting\n"));
      goto error;
    };

    start += to_write;
    Log(TEXT("."));

    if(!(count % 60)) {
      Log(TEXT("\n0x%08llX "), start);
    }

    count ++;

  };

  return 1;

 error:
  return 0;
};

int WinPmem::copy_memory(unsigned __int64 start, unsigned __int64 end) {
  LARGE_INTEGER large_start;
  int count = 0;

  if (start > max_physical_memory_) {
    return 0;
  };

  // Clamp the region to the top of physical memory.
  if (end > max_physical_memory_) {
    end = max_physical_memory_;
  };

  while(start < end) {
    int to_write = (int)min(buffer_size_, end - start);
    DWORD bytes_read = 0;
    large_start.QuadPart = start;

    if(0xFFFFFFFF == SetFilePointer(fd_, large_start.LowPart,
                                    &large_start.HighPart, FILE_BEGIN)) {
      LogError(TEXT("Failed to seek in the pmem device.\n"));
      goto error;
    };

    if(!ReadFile(fd_, buffer_, to_write, &bytes_read, NULL)) {
      LogError(TEXT("Failed to Read memory."));
      goto error;
    };

    if(!WriteFile(out_fd_, buffer_, bytes_read, &bytes_read, NULL)) {
      Log(TEXT("Failed to write image file... Aborting.\n"));
      goto error;
    };

    if((count % 50) == 0) {
      Log(TEXT("\n%02lld%% 0x%08llX "), (start * 100) / max_physical_memory_,
          start);
    }

    Log(TEXT("."));

    start += to_write;
    count ++;
  };

  Log(TEXT("\n"));
  return 1;

 error:
  return 0;
};


// Turn on write support in the driver.
int WinPmem::set_write_enabled(void) {
  unsigned _int32 mode;
  DWORD size;

  if(!DeviceIoControl(fd_, PMEM_WRITE_ENABLE, &mode, 4, NULL, 0,
                      &size, NULL)) {
    LogError(TEXT("Failed to set write mode. Maybe these drivers do ")
             TEXT("not support this mode?\n"));
    return -1;
  };

  Log(TEXT("Write mode enabled! Hope you know what you are doing.\n"));
  return 1;
};

// Display information about the memory geometry.
void WinPmem::print_memory_info() {
  struct PmemMemoryInfo info;
  int i;
  DWORD size;

  // Get the memory ranges.
  if(!DeviceIoControl(fd_, PMEM_INFO_IOCTRL, NULL, 0, (char *)&info,
                      sizeof(info), &size, NULL)) {
    LogError(TEXT("Failed to get memory geometry,"));
    goto error;
  };


  Log(TEXT("CR3: 0x%010llX\n %d memory ranges:\n"), info.CR3.QuadPart,
      info.NumberOfRuns);

  for(i=0; i < info.NumberOfRuns.QuadPart; i++) {
    Log(TEXT("Start 0x%08llX - Length 0x%08llX\n"), info.Run[i].start,
        info.Run[i].length);
    max_physical_memory_ = info.Run[i].start + info.Run[i].length;
  };

  // When using the pci introspection we dont know the maximum physical memory,
  // we therefore make a guess based on the total ram in the system.
  Log(TEXT("Acquitision mode %X\n"), mode_);
  if (mode_ == PMEM_MODE_PTE_PCI) {
    ULONGLONG installed_memory = 0;
    MEMORYSTATUSEX statusx;

    statusx.dwLength = sizeof(statusx);

    if (GlobalMemoryStatusEx (&statusx)) {
      max_physical_memory_ = statusx.ullTotalPhys * 3 / 2;
      Log(TEXT("Max physical memory guessed at 0x%08llX\n"),
               max_physical_memory_);

    } else {
      Log(TEXT("Unable to guess max physical memory. Just Ctrl-C when ")
          TEXT("done.\n"));
    };
  };
  Log(TEXT("\n"));

 error:
  return;
};

int WinPmem::set_acquisition_mode(unsigned __int32 mode) {
  DWORD size;

  // Set the acquisition mode.
  if(!DeviceIoControl(fd_, PMEM_CTRL_IOCTRL, &mode, 4, NULL, 0,
                      &size, NULL)) {
    LogError(TEXT("Failed to set acquisition mode.\n"));
    return -1;
  };

  mode_ = mode;
  return 1;
};

int WinPmem::create_output_file(TCHAR *output_filename) {
  int status = 1;

  // The special file name of - means we should use stdout.
  if (!_tcscmp(output_filename, TEXT("-"))) {
    out_fd_ = GetStdHandle(STD_OUTPUT_HANDLE);
    suppress_output = TRUE;
    status = 1;
    goto exit;
  }

  // Create the output file.
  out_fd_ = CreateFile(output_filename,
                       GENERIC_WRITE,
                       FILE_SHARE_READ,
                       NULL,
                       CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL,
                       NULL);

  if (out_fd_ == INVALID_HANDLE_VALUE) {
    LogError(TEXT("Unable to create output file."));
    status = -1;
    goto exit;
  };

 exit:
  return status;
}

int WinPmem::write_crashdump() {
  // Somewhere to store the info from the driver;
  struct PmemMemoryInfo info;
  DWORD size;
  int i;
  int status = -1;

  if(out_fd_==INVALID_HANDLE_VALUE) {
    LogError(TEXT("Must open an output file first."));
    goto exit;
  };

  RtlZeroMemory(&info, sizeof(info));

  // Get the memory ranges.
  if(!DeviceIoControl(fd_, PMEM_INFO_IOCTRL, NULL, 0, (char *)&info,
                      sizeof(info), &size, NULL)) {
    LogError(TEXT("Failed to get memory geometry,"));
    status = -1;
    goto exit;
  };

  Log(TEXT("Will write a crash dump file\n"));
  print_memory_info();

  if(!write_crashdump_header_(&info)) {
    goto exit;
  };

  __int64 offset = 0;
  for(i=0; i < info.NumberOfRuns.QuadPart; i++) {
    copy_memory(info.Run[i].start, info.Run[i].start + info.Run[i].length);
    offset = info.Run[i].start + info.Run[i].length;
  };

 exit:
  CloseHandle(out_fd_);
  out_fd_ = INVALID_HANDLE_VALUE;
  return status;
};


int WinPmem::write_raw_image() {
  // Somewhere to store the info from the driver;
  struct PmemMemoryInfo info;
  DWORD size;
  int i;
  int status = -1;

  if(out_fd_==INVALID_HANDLE_VALUE) {
    LogError(TEXT("Must open an output file first."));
    goto exit;
  };

  RtlZeroMemory(&info, sizeof(info));

  // Get the memory ranges.
  if(!DeviceIoControl(fd_, PMEM_INFO_IOCTRL, NULL, 0, (char *)&info,
                      sizeof(info), &size, NULL)) {
    LogError(TEXT("Failed to get memory geometry,"));
    status = -1;
    goto exit;
  };

  Log(TEXT("Will generate a RAW image\n"));
  print_memory_info();

  __int64 offset = 0;
  for(i=0; i < info.NumberOfRuns.QuadPart; i++) {
    if(info.Run[i].start > offset) {
      Log(TEXT("Padding from 0x%08llX to 0x%08llX\n"), offset, info.Run[i].start);
      if(!pad(info.Run[i].start - offset)) {
        goto exit;
      }
    };

    copy_memory(info.Run[i].start, info.Run[i].start + info.Run[i].length);
    offset = info.Run[i].start + info.Run[i].length;
  };

  // All is well.
  status = 1;

 exit:
  CloseHandle(out_fd_);
  out_fd_ = INVALID_HANDLE_VALUE;
  return status;
};

WinPmem::WinPmem():
  fd_(INVALID_HANDLE_VALUE),
  buffer_size_(1024*1024),
  buffer_(NULL),
  suppress_output(FALSE),
  service_name(PMEM_SERVICE_NAME) {
  buffer_ = new char[buffer_size_];
  _tcscpy_s(last_error, TEXT(""));
  max_physical_memory_ = 0;
  }

WinPmem::~WinPmem() {
  if (fd_ != INVALID_HANDLE_VALUE) {
    CloseHandle(fd_);
  };

  if (buffer_) {
    delete [] buffer_;
  }
}

void WinPmem::LogError(TCHAR *message) {
  _tcsncpy_s(last_error, message, sizeof(last_error));
  if (suppress_output) return;

  wprintf(L"%s", message);
};

void WinPmem::Log(const TCHAR *message, ...) {
  if (suppress_output) return;

  va_list ap;
  va_start(ap, message);
  vwprintf(message, ap);
  va_end(ap);
};

int WinPmem::extract_file_(int driver_id) {
  TCHAR path[MAX_PATH + 1];

  // Locate the driver resource in the .EXE file.
  HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(driver_id), L"FILE");
  if (hRes == NULL) {
    LogError(TEXT("Could not locate driver resource."));
    goto error;
  }

  HGLOBAL hResLoad = LoadResource(NULL, hRes);
  if (hResLoad == NULL) {
    LogError(TEXT("Could not load driver resource."));
    goto error;
  }

  VOID *lpResLock = LockResource(hResLoad);
  if (lpResLock == NULL) {
    LogError(TEXT("Could not lock driver resource."));
    goto error;
  }

  DWORD size = SizeofResource(NULL, hRes);

  //  Gets the temp path env string (no guarantee it's a valid path).
  if(!GetTempPath(MAX_PATH, path)) {
    LogError(TEXT("Unable to determine temporary path."));
    goto error_resource;
  }

  GetTempFileName(path, service_name, 0, driver_filename);
  HANDLE out_fd = CreateFile(driver_filename, GENERIC_WRITE, 0, NULL,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if(out_fd == INVALID_HANDLE_VALUE) {
    LogError(TEXT("Can not create temporary file."));
    goto error_resource;
  };

  if(!WriteFile(out_fd, lpResLock, size, &size, NULL)) {
    LogError(TEXT("Can not write to temporary file."));
    goto error_file;
  }

  CloseHandle(out_fd);
  return 1;

 error_file:
  CloseHandle(out_fd);

 error_resource:
 error:
  return -1;
};

int WinPmem::install_driver() {
  SC_HANDLE scm, service;
  int status = -1;

  // Try to load the driver from the resource section.
  if (load_driver_() < 0)
    goto error;

  uninstall_driver();

  scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
  if (!scm) {
    LogError(TEXT("Can not open SCM. Are you administrator?\n"));
    goto error;
  }

  service = CreateService(scm,
                          service_name,
                          service_name,
                          SERVICE_ALL_ACCESS,
                          SERVICE_KERNEL_DRIVER,
                          SERVICE_DEMAND_START,
                          SERVICE_ERROR_NORMAL,
                          driver_filename,
                          NULL,
                          NULL,
                          NULL,
                          NULL,
                          NULL);

  if (GetLastError() == ERROR_SERVICE_EXISTS) {
    service = OpenService(scm, service_name, SERVICE_ALL_ACCESS);
  }

  if (!service) {
    goto error;
  };
  if (!StartService(service, 0, NULL)) {
    if (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
      LogError(TEXT("Error: StartService(), Cannot start the driver.\n"));
      goto service_error;
    }
  }

  Log(L"Loaded Driver %s.\n", driver_filename);

  fd_ = CreateFile(TEXT("\\\\.\\") TEXT(PMEM_DEVICE_NAME),
                   // Write is needed for IOCTL.
                   GENERIC_READ | GENERIC_WRITE,
                   FILE_SHARE_READ | FILE_SHARE_WRITE,
                   NULL,
                   OPEN_EXISTING,
                   FILE_ATTRIBUTE_NORMAL,
                   NULL);

  if(fd_ == INVALID_HANDLE_VALUE) {
    LogError(TEXT("Can not open raw device."));
    status = -1;
  };

  status = 1;

 service_error:
  CloseServiceHandle(service);
  CloseServiceHandle(scm);
  DeleteFile(driver_filename);

 error:
  return status;
}

int WinPmem::uninstall_driver() {
  SC_HANDLE scm, service;
  SERVICE_STATUS ServiceStatus;

  scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

  if (!scm) return 0;

  service = OpenService(scm, service_name, SERVICE_ALL_ACCESS);

  if (service) {
    ControlService(service, SERVICE_CONTROL_STOP, &ServiceStatus);
  };

  DeleteService(service);
  CloseServiceHandle(service);
  Log(TEXT("Driver Unloaded.\n"));

  return 1;

  CloseServiceHandle(scm);
  return 0;
}


// WinPmem64 - A 64 bit implementation of the imager.

int WinPmem64::write_crashdump_header_(struct PmemMemoryInfo *info) {
  DUMP_HEADER64 header;
  int i;
  __int32 *p = (__int32 *)&header;
  DWORD header_size = 0x2000;

  // Pad with PAGE.
  for(i=0; i<sizeof(header)/4; i++) {
    p[i] = DUMP_SIGNATURE64;
  }

  header.Signature = DUMP_SIGNATURE64;
  header.ValidDump = DUMP_VALID_DUMP64;

  header.KdDebuggerDataBlock = info->KDBG.QuadPart;
  header.PhysicalMemoryBlock.NumberOfRuns = 0;
  header.PhysicalMemoryBlock.NumberOfPages = 0;

  for(i=0; i < info->NumberOfRuns.QuadPart; i++) {
    header.PhysicalMemoryBlock.Run[i].BasePage = info->Run[i].start / PAGE_SIZE;
    header.PhysicalMemoryBlock.Run[i].PageCount = info->Run[i].length / PAGE_SIZE;
    header.PhysicalMemoryBlock.NumberOfRuns++;
    header.PhysicalMemoryBlock.NumberOfPages += info->Run[i].length / PAGE_SIZE;
  };

  header.DirectoryTableBase = info->CR3.QuadPart;
  header.MajorVersion = 0xf;
  header.MinorVersion = info->NtBuildNumber.LowPart;
  header.RequiredDumpSpace.QuadPart = (header.PhysicalMemoryBlock.NumberOfPages +
                                       header_size / PAGE_SIZE);
  header.DumpType = 1; // Full kernel dump.
  header.BugCheckCode = 0x00;
  header.Exception.ExceptionCode = 0;
  header.MachineImageType = 0x8664;

  // Count how many processors we have.
  for(i=0; info->KPCR[i].QuadPart; i++);
  header.NumberProcessors = i;

  header.PfnDataBase = info->PfnDataBase.QuadPart;
  header.PsActiveProcessHead = info->PsActiveProcessHead.QuadPart;
  header.PsLoadedModuleList = info->PsLoadedModuleList.QuadPart;

  if(!WriteFile(out_fd_, &header, header_size, &header_size, NULL)) {
    Log(TEXT("Failed to write header... Aborting.\n"));
    goto error;
  };

  return 1;

 error:
  return 0;
};

int WinPmem64::load_driver_() {
  return extract_file_(WINPMEM_64BIT_DRIVER);
}

// WinPmem32 - A 32 bit implementation of the imager.

int WinPmem32::write_crashdump_header_(struct PmemMemoryInfo *info) {
  DUMP_HEADER header;
  int i;
  __int32 *p = (__int32 *)&header;
  DWORD header_size = 0x1000;

  // Pad with PAGE.
  for(i=0; i<sizeof(header)/4; i++) {
    p[i] = DUMP_SIGNATURE32;
  }

  header.Signature = DUMP_SIGNATURE32;
  header.ValidDump = DUMP_VALID_DUMP32;

  header.KdDebuggerDataBlock = info->KDBG.LowPart;
  header.PhysicalMemoryBlock.NumberOfRuns = 0;
  header.PhysicalMemoryBlock.NumberOfPages = 0;

  for(i=0; i < info->NumberOfRuns.QuadPart; i++) {
    header.PhysicalMemoryBlock.Run[i].BasePage = (ULONG)info->Run[i].start /
      PAGE_SIZE;
    header.PhysicalMemoryBlock.Run[i].PageCount = (ULONG)info->Run[i].length /
      PAGE_SIZE;
    header.PhysicalMemoryBlock.NumberOfRuns++;
    header.PhysicalMemoryBlock.NumberOfPages += (ULONG)info->Run[i].length /
      PAGE_SIZE;
  };

  // Count how many processors we have.
  for(i=0; info->KPCR[i].QuadPart; i++);
  header.KeNumberOfProcessors = i;

  header.DirectoryTableBase = info->CR3.LowPart;
  header.MajorVersion = 0xf;
  header.MinorVersion = info->NtBuildNumber.LowPart;
  header.RequiredDumpSpace.QuadPart = (header.PhysicalMemoryBlock.NumberOfPages +
                                       header_size / PAGE_SIZE);
  header.DumpType = 1; // Full kernel dump.
  header.BugCheckCode = 0x00;
  // Ideally we check this from the kernel's image but the other types
  // are kind of weird and we wont see windows running on them.
  header.MachineImageType = 0x014c;  // See _IMAGE_FILE_HEADER.Machine

  header.PfnDataBase = (PULONG)(info->PfnDataBase.QuadPart);
  header.PsActiveProcessHead = (PLIST_ENTRY)(info->PsActiveProcessHead.QuadPart);
  header.PsLoadedModuleList = (PLIST_ENTRY)(info->PsLoadedModuleList.QuadPart);

  if(!WriteFile(out_fd_, &header, header_size, &header_size, NULL)) {
    Log(TEXT("Failed to write header... Aborting.\n"));
    goto error;
  };

  return 1;

 error:
  return 0;
}

int WinPmem32::load_driver_() {
  return extract_file_(WINPMEM_32BIT_DRIVER);
}
