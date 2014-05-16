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
#include <time.h>


__int64 WinPmem::pad(__int64 length) {
  __int64 count = 1;
  __int64 start = 0;

  ZeroMemory(buffer_, buffer_size_);

  while(start < length) {
    DWORD to_write = (DWORD)min(buffer_size_, length - start);
    DWORD bytes_written;

    if(!WriteFile(out_fd_, buffer_,
                  to_write, &bytes_written, NULL) ||
       bytes_written != to_write) {
      Log(TEXT("Failed to write padding... Aborting\n"));
      goto error;
    };

    start += bytes_written;
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

__int64 WinPmem::copy_memory(unsigned __int64 start, unsigned __int64 end) {
  LARGE_INTEGER large_start;
  __int64 count = 0;

  if (start > max_physical_memory_) {
    return 0;
  };

  // Clamp the region to the top of physical memory.
  if (end > max_physical_memory_) {
    end = max_physical_memory_;
  };

  while(start < end) {
    DWORD to_write = (DWORD)min(buffer_size_, end - start);
    DWORD bytes_read = 0;
    DWORD bytes_written = 0;

    large_start.QuadPart = start;

    if(0xFFFFFFFF == SetFilePointerEx(
       fd_, large_start, NULL, FILE_BEGIN)) {
      LogError(TEXT("Failed to seek in the pmem device.\n"));
      goto error;
    };

    if(!ReadFile(fd_, buffer_, to_write, &bytes_read, NULL) ||
       bytes_read != to_write) {
      LogError(TEXT("Failed to Read memory.\n"));
      goto error;
    };

    if(!WriteFile(out_fd_, buffer_, bytes_read,
                  &bytes_written, NULL) ||
       bytes_written != bytes_read) {
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
__int64 WinPmem::set_write_enabled(void) {
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


void WinPmem::print_mode_(unsigned __int32 mode) {
  switch(mode) {
  case PMEM_MODE_IOSPACE:
    Log(TEXT("MMMapIoSpace"));
    break;

  case PMEM_MODE_PHYSICAL:
    Log(TEXT("\\\\.\\PhysicalMemory"));
    break;

  case PMEM_MODE_PTE:
    Log(TEXT("PTE Remapping"));
    break;

  case PMEM_MODE_PTE_PCI:
    Log(TEXT("PTE Remapping with PCI introspection"));
    break;

  default:
    Log(TEXT("Unknown"));
  };
};


// Display information about the memory geometry.
void WinPmem::print_memory_info() {
  struct PmemMemoryInfo info;
  __int64 i;
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
  Log(TEXT("Acquitision mode "));
  print_mode_(mode_);
  Log(TEXT("\n"));

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

__int64 WinPmem::set_acquisition_mode(unsigned __int32 mode) {
  DWORD size;

  if (mode == PMEM_MODE_AUTO) {
    mode = default_mode_;
  }

  // Set the acquisition mode.
  if(!DeviceIoControl(fd_, PMEM_CTRL_IOCTRL, &mode, 4, NULL, 0,
                      &size, NULL)) {
    Log(TEXT("Failed to set acquisition mode %lu "), mode);
    print_mode_(mode);
    Log(TEXT("\n"));
    return -1;
  };

  mode_ = mode;
  return 1;
};

__int64 WinPmem::create_output_file(TCHAR *output_filename) {
  __int64 status = 1;

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

__int64 WinPmem::write_coredump() {
  // Somewhere to store the info from the driver;
  struct PmemMemoryInfo info;
  DWORD size;
  __int64 i;
  __int64 status = -1;

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

  Log(TEXT("Will write an elf coredump.\n"));
  print_memory_info();

  if(!write_coredump_header_(&info)) {
    goto exit;
  };

  __int64 offset = 0;
  for(i=0; i < info.NumberOfRuns.QuadPart; i++) {
    copy_memory(info.Run[i].start, info.Run[i].start + info.Run[i].length);
    offset = info.Run[i].start + info.Run[i].length;
  };

  if(!WriteFile(out_fd_, metadata_, metadata_len_, &metadata_len_, NULL)) {
    LogError(TEXT("Can not write metadata.\n"));
  }

 exit:
  CloseHandle(out_fd_);
  out_fd_ = INVALID_HANDLE_VALUE;
  return status;
};


__int64 WinPmem::write_raw_image() {
  // Somewhere to store the info from the driver;
  struct PmemMemoryInfo info;
  DWORD size;
  __int64 i;
  __int64 status = -1;

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
  mode_ = PMEM_MODE_AUTO;
  default_mode_ = PMEM_MODE_AUTO;
  metadata_ = NULL;
  metadata_len_ = 0;
  driver_filename_ = NULL;
  driver_is_tempfile_ = false;
  }

WinPmem::~WinPmem() {
  if (fd_ != INVALID_HANDLE_VALUE) {
    CloseHandle(fd_);
  };

  if (buffer_) {
    delete [] buffer_;
  }

  if (driver_filename_ && driver_is_tempfile_) {
    free(driver_filename_);
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

__int64 WinPmem::extract_file_(__int64 driver_id) {
  if (!driver_filename_) {
    TCHAR path[MAX_PATH + 1];
    TCHAR filename[MAX_PATH + 1];

    // Gets the temp path env string (no guarantee it's a valid path).
    if(!GetTempPath(MAX_PATH, path)) {
      LogError(TEXT("Unable to determine temporary path."));
      goto error;
    }

    GetTempFileName(path, service_name, 0, filename);
    set_driver_filename(filename);

    driver_is_tempfile_ = true;
  };

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

  // Now open the filename and write the driver image on it.
  HANDLE out_fd = CreateFile(driver_filename_, GENERIC_WRITE, 0, NULL,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

  Log(L"Extracting driver to %s\n", driver_filename_);

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


void WinPmem::set_driver_filename(TCHAR *driver_filename) {
  DWORD res;

  if(driver_filename_) {
    free(driver_filename_);
    driver_filename_ = NULL;
  };

  if (driver_filename) {
    driver_filename_ = (TCHAR *)malloc(MAX_PATH * sizeof(TCHAR));
    if (driver_filename_) {
      res = GetFullPathName(driver_filename, MAX_PATH,
                            driver_filename_, NULL);
    };
  };
}

__int64 WinPmem::install_driver() {
  SC_HANDLE scm, service;
  __int64 status = -1;

  // Try to load the driver from the resource section.
  if (extract_driver() < 0)
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
                          driver_filename_,
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

  Log(L"Loaded Driver %s.\n", driver_filename_);

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

 error:
  // Only remove the driver file if it was a temporary file.
  if (driver_is_tempfile_) {
    Log(L"Deleting %s\n", driver_filename_);
    DeleteFile(driver_filename_);
  };

  return status;
}

__int64 WinPmem::uninstall_driver() {
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

/* Create a YAML file describing the image encoded into a null terminated
   string. Caller will own the memory.
 */
char *store_metadata_(struct PmemMemoryInfo *info) {
  SYSTEM_INFO sys_info;
  struct tm newtime;
  __time32_t aclock;

  char time_buffer[32];
  errno_t errNum;
  char *arch = NULL;

  _time32( &aclock );   // Get time in seconds.
  _gmtime32_s( &newtime, &aclock );   // Convert time to struct tm form.

  // Print local time as a string.
  errNum = asctime_s(time_buffer, 32, &newtime);
  if (errNum) {
    time_buffer[0] = 0;
  }

  // Get basic architecture information (Note that we always write ELF64 core
  // dumps - even on 32 bit platforms).
  ZeroMemory(&sys_info, sizeof(sys_info));
  GetNativeSystemInfo(&sys_info);

  switch(sys_info.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64:
      arch = "AMD64";
      break;

    case PROCESSOR_ARCHITECTURE_INTEL:
      arch = "I386";
      break;

    default:
      arch = "Unknown";
  }

  return asprintf(// A YAML File describing metadata about this image.
                  "# PMEM\n"
                  "---\n"   // The start of the YAML file.
                  "acquisition_tool: 'WinPMEM " PMEM_VERSION "'\n"
                  "acquisition_timestamp: %s\n"
                  "CR3: %#llx\n"
                  "NtBuildNumber: %#llx\n"
                  "NtBuildNumberAddr: %#llx\n"
                  "KernBase: %#llx\n"
                  "Arch: %s\n"
                  "...\n",  // This is the end of a YAML file.
                  time_buffer,
                  info->CR3.QuadPart,
                  info->NtBuildNumber.QuadPart,
                  info->NtBuildNumberAddr.QuadPart,
                  info->KernBase.QuadPart,
                  arch
                  );
};


// WinPmem64 - A 64 bit implementation of the imager.
__int64 WinPmem::write_coredump_header_(struct PmemMemoryInfo *info) {
  Elf64_Ehdr header;
  DWORD header_size;
  Elf64_Phdr pheader;
  int i;

  if(!metadata_) {
    metadata_ = store_metadata_(info);
    if (!metadata_) goto error;

    metadata_len_ = strlen(metadata_);
  };

  // Where we start writing data.
  uint64 file_offset = (
      sizeof(Elf64_Ehdr) +
      // One Phdr for each run and one for the metadata.
      (info->NumberOfRuns.QuadPart + 1) * sizeof(Elf64_Phdr));

  // All values that are unset will be zero
  RtlZeroMemory(&header, sizeof(Elf64_Ehdr));

  // We create a 64 bit core dump file with one section
  // for each physical memory segment.
  header.ident[0] = ELFMAG0;
  header.ident[1] = ELFMAG1;
  header.ident[2] = ELFMAG2;
  header.ident[3] = ELFMAG3;
  header.ident[4] = ELFCLASS64;
  header.ident[5] = ELFDATA2LSB;
  header.ident[6] = EV_CURRENT;
  header.type     = ET_CORE;
  header.machine  = EM_X86_64;
  header.version  = EV_CURRENT;
  header.phoff    = sizeof(Elf64_Ehdr);
  header.ehsize   = sizeof(Elf64_Ehdr);
  header.phentsize= sizeof(Elf64_Phdr);

  // One more header for the metadata.
  header.phnum    = (uint32)info->NumberOfRuns.QuadPart + 1;
  header.shentsize= sizeof(Elf64_Shdr);
  header.shnum    = 0;

  header_size = sizeof(header);
  if(!WriteFile(out_fd_, &header, header_size, &header_size, NULL)) {
    Log(TEXT("Failed to write header... Aborting.\n"));
    goto error;
  };

  for(i=0; i<info->NumberOfRuns.QuadPart; i++) {
    PHYSICAL_MEMORY_RANGE range = info->Run[i];

    RtlZeroMemory(&pheader, sizeof(Elf64_Phdr));

    pheader.type = PT_LOAD;
    pheader.paddr = range.start;
    pheader.memsz = range.length;
    pheader.align = PAGE_SIZE;
    pheader.flags = PF_R;
    pheader.off = file_offset;
    pheader.filesz = range.length;

    // Move the file offset by the size of this run.
    file_offset += range.length;

    header_size = sizeof(pheader);
    if(!WriteFile(out_fd_, &pheader, header_size, &header_size, NULL)) {
      Log(TEXT("Failed to write header... Aborting.\n"));
      goto error;
    };

  };

  // Add a header for the metadata so it can be easily found in the file.
  RtlZeroMemory(&pheader, sizeof(Elf64_Phdr));
  pheader.type = PT_PMEM_METADATA;
  pheader.off = file_offset;
  pheader.filesz = metadata_len_;

  header_size = sizeof(pheader);
  if(!WriteFile(out_fd_, &pheader, header_size, &header_size, NULL)) {
    Log(TEXT("Failed to write header... Aborting.\n"));
    goto error;
  };

  return 1;

 error:
  return 0;
};

__int64 WinPmem::extract_driver(TCHAR *driver_filename) {
  set_driver_filename(driver_filename);
  return extract_driver();
};

__int64 WinPmem64::extract_driver() {
  // 64 bit drivers use PTE acquisition by default.
  default_mode_ = PMEM_MODE_PTE;
  return extract_file_(WINPMEM_64BIT_DRIVER);
}

__int64 WinPmem32::extract_driver() {
  // 32 bit acquisition defaults to physical device.
  default_mode_ = PMEM_MODE_PHYSICAL;
  return extract_file_(WINPMEM_32BIT_DRIVER);
}


#ifdef _WIN32
#define vsnprintf _vsnprintf
#endif

char *asprintf(const char *fmt, ...) {
  /* Guess we need no more than 1000 bytes. */
  int n, size = 1000;
  char *p, *np;
  va_list ap;

  p = (char *)malloc (size);
  if (!p)
    return NULL;

  while (1) {
    /* Try to print in the allocated space. */
    va_start(ap, fmt);
    n = vsnprintf (p, size, fmt, ap);
    va_end(ap);

    /* If that worked, return the string. */
    if (n > -1 && n < size)
      return p;

    /* Else try again with more space. */
    if (n > -1)    /* glibc 2.1 */
      size = n+1;  /* precisely what is needed */

    else           /* glibc 2.0 */
      size *= 2;   /* twice the old size */

    np = (char *)realloc (p, size);
    if (np == NULL) {
      free(p);
      return NULL;

    } else {
      p = np;
    }

  }
}
