/*
   Copyright 2012 Michael Cohen <scudette@gmail.com>

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
    - Windows XP to Windows 2012, both 32 bit and 64 bit.

*********************************************************************/

#include "windows.h"
#include "stdio.h"
#include "tchar.h"

// These numbers are set in the resource editor for the FILE resource.
#define WINPMEM_64BIT_DRIVER 104
#define WINPMEM_32BIT_DRIVER 105

// Executable version.
static TCHAR version[] = TEXT("20120927");

// This is the filename of the driver we drop.
static TCHAR driver_filename[MAX_PATH];

#define PMEM_DEVICE_NAME "pmem"

// ioctl to get memory ranges from our driver.
#define PMEM_INFO_IOCTRL CTL_CODE(0x22, 0x100, 0, 3)
#define PMEM_CTRL_IOCTRL CTL_CODE(0x22, 0x101, 0, 3)
#define PMEM_WRITE_ENABLE CTL_CODE(0x22, 0x102, 0, 3)

// Available modes
#define PMEM_MODE_IOSPACE 0
#define PMEM_MODE_PHYSICAL 1

#define PMEM_WRITE_MODE 1

#pragma pack(2)
struct pmem_info_runs {
	__int64 start;
	__int64 length;
};

#pragma pack(2)
struct pmem_info_ioctrl {
	__int64 cr3;
	__int64 kdbg;
	__int32 number_of_runs;
	struct pmem_info_runs runs[1];
};

void LogError(TCHAR *message) {
	wprintf(L"%s", message);
};

int extract_file(int driver_id) {
  TCHAR path[MAX_PATH];

  // Locate the driver resource in the .EXE file.
  HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(driver_id), L"FILE");
  if (hRes == NULL) {
    LogError(TEXT("Could not locate dialog box."));
    goto error;
  }

  HGLOBAL hResLoad = LoadResource(NULL, hRes);
  if (hResLoad == NULL) {
    LogError(TEXT("Could not load dialog box."));
    goto error;
  }

  VOID *lpResLock = LockResource(hResLoad);
  if (lpResLock == NULL) {
    LogError(TEXT("Could not lock dialog box."));
    goto error;
  }

  DWORD size = SizeofResource(NULL, hRes);

  //  Gets the temp path env string (no guarantee it's a valid path).
  if(!GetTempPath(MAX_PATH, path)) {
    LogError(TEXT("Unable to determine temporary path."));
    goto error_resource;
  }

  GetTempFileName(path, TEXT("winpmem"), 0, driver_filename);
  HANDLE out_fd = CreateFile(driver_filename, GENERIC_WRITE, 0, NULL,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if(out_fd == INVALID_HANDLE_VALUE) {
    LogError(TEXT("Can not create file."));
    goto error_resource;
  };

  if(!WriteFile(out_fd, lpResLock, size, &size, NULL)) {
    LogError(TEXT("Can not write to file."));
    goto error_file;
  }

  CloseHandle(out_fd);
  return 1;

 error_file:
  CloseHandle(out_fd);

 error_resource:

 error:
  return 0;
};

int load_driver() {
  SYSTEM_INFO sys_info;
  ZeroMemory(&sys_info, sizeof(sys_info));

  GetNativeSystemInfo(&sys_info);
  switch(sys_info.wProcessorArchitecture) {
  case PROCESSOR_ARCHITECTURE_AMD64:
    return extract_file(WINPMEM_64BIT_DRIVER);

  case PROCESSOR_ARCHITECTURE_INTEL:
    return extract_file(WINPMEM_32BIT_DRIVER);

  default:
    LogError(TEXT("Unsupported architecture"));
    return 0;
  }
}

int uninstall_driver() {
  SC_HANDLE scm, service;
  SERVICE_STATUS ServiceStatus;

  scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

  if (!scm) return 0;

  service = OpenService(scm, TEXT("winpmem"), SERVICE_ALL_ACCESS);

  if (!service) goto error;

  ControlService(service, SERVICE_CONTROL_STOP, &ServiceStatus);

  DeleteService(service);
  CloseServiceHandle(service);

  return 1;

error:
  CloseServiceHandle(scm);
  return 0;
}

int install_driver() {
  SC_HANDLE scm, service;

  uninstall_driver();

  scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
  if (!scm) {
    LogError(TEXT("Can not open SCM. Are you administrator?"));
    goto error;
  }

  service = CreateService(scm,
                          TEXT("winpmem"),
                          TEXT("winpmem"),
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
    service = OpenService(scm, L"winpmem", SERVICE_ALL_ACCESS);
  }

  if (!service) goto error;

  if (!StartService(service, 0, NULL)) {
    if (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
      LogError(TEXT("Error: StartService(), Cannot start the driver.\n"));
      goto service_error;
    }
  }

  CloseServiceHandle(service);
  CloseServiceHandle(scm);
  return 1;

service_error:
  CloseServiceHandle(service);

error:
  CloseServiceHandle(scm);
  return 0;
}


void help(TCHAR *ExeName)
{
  wprintf(L"Winpmem - A memory imager for windows.\n"
          L"Copyright Michael Cohen (scudette@gmail.com) 2012.\n\n");

  wprintf(L"Version %s\n", version);
  wprintf(L"Usage:\n");
  wprintf(L"  %s [option] [output path]\n", ExeName);

  wprintf(L"\nOption:\n");
  wprintf(L"  -l    Load the driver and exit.\n"
          L"  -u    Unload the driver and exit.\n"
          L"  -h    Display this help.\n"
#if PMEM_WRITE_MODE
          L"  -w    Turn on/off write mode.\n"
#endif
          L"  -1    Use MmMapIoSpace method.\n"
          L"  -2    Use \\\\Device\\PhysicalMemory method (Default).\n"
          L"\n");

  wprintf(L"\nSample:\n");
  wprintf(L"%s physmem.raw\nWrites an image to physmem.raw\n", ExeName);
}

#define BUFFER_SIZE 1024 * 1024
int pad(HANDLE out_fd, __int64 start, __int64 end) {
  char *buffer = (char *)malloc(BUFFER_SIZE + 10);
  int count = 1;

  wprintf(TEXT("Padding from 0x%08llX to 0x%08llX\n"), start, end);
  ZeroMemory(buffer, BUFFER_SIZE);

  while(start < end) {
    DWORD to_write = min(BUFFER_SIZE, end - start);
    WriteFile(out_fd, buffer, to_write, &to_write, NULL);
    start += to_write;
    wprintf(TEXT("."));

    if(!(count % 60)) {
      wprintf(TEXT("\n0x%08llX "), start);
    }

    count ++;

  };

  free(buffer);
  return 1;
};

int copy_memory(HANDLE out_fd, HANDLE in_fd, __int64 start, __int64 end) {
  char *buffer = (char *)malloc(BUFFER_SIZE + 10);
  LARGE_INTEGER large_start;
  int count = 1;

  wprintf(TEXT("Reading from 0x%08llX to 0x%08llX\n"), start, end);
  while(start < end) {
    int to_write = min(BUFFER_SIZE, end - start);
    DWORD bytes_read = 0;
    large_start.QuadPart = start;

    if(0xFFFFFFFF == SetFilePointer(in_fd, large_start.LowPart, &large_start.HighPart, FILE_BEGIN)) {
      LogError(TEXT("Failed to seek"));
      goto error;
    };

    if(!ReadFile(in_fd, buffer, to_write, &bytes_read, NULL)) {
      LogError(TEXT("Failed to Read memory."));
      goto error;
    };

    WriteFile(out_fd, buffer, bytes_read, &bytes_read, NULL);
    start += to_write;

    wprintf(TEXT("."));

    if(!(count % 60)) {
      wprintf(TEXT("\n0x%08llX "), start);
    }

    count ++;
  };

  free(buffer);
  return 1;

 error:
  free(buffer);
  return 0;
};


#if PMEM_WRITE_MODE
// Turn on write support in the driver.
int set_write_enabled(void) {
  _int32 mode;
  DWORD size;

  HANDLE pmem_fd = CreateFile(TEXT("\\\\.\\") TEXT(PMEM_DEVICE_NAME),
                              // Write is needed for IOCTL.
                              GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE,
                              NULL,
                              OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL,
                              NULL);

  if(pmem_fd == INVALID_HANDLE_VALUE) {
    LogError(TEXT("Can not open raw device."));
    goto error;
  }

  // Get the memory ranges.
  if(!DeviceIoControl(pmem_fd, PMEM_WRITE_ENABLE, &mode, 4, NULL, 0,
                      &size, NULL)) {
    LogError(TEXT("Failed to set write mode. Maybe these drivers do "
                  "not support this mode?\n"));
  };

  CloseHandle(pmem_fd);
  return 1;

 error:
  CloseHandle(pmem_fd);
  return -1;
};
#endif

int write_raw_image(TCHAR *output_filename, __int32 mode) {
  // Somewhere to store the info from the driver;
  char info_buffer[4096];
  struct pmem_info_ioctrl *info = (struct pmem_info_ioctrl *)info_buffer;
  DWORD size;
  int i;

  HANDLE pmem_fd = CreateFile(TEXT("\\\\.\\") TEXT(PMEM_DEVICE_NAME),
                              // Write is needed for IOCTL.
                              GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE,
                              NULL,
                              OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL,
                              NULL);
  if(pmem_fd == INVALID_HANDLE_VALUE) {
    LogError(TEXT("Can not open raw device."));
    goto error;
  }

  // Get the memory ranges.
  if(!DeviceIoControl(pmem_fd, PMEM_CTRL_IOCTRL, &mode, 4, NULL, 0,
                      &size, NULL)) {
    LogError(TEXT("Failed to set acquisition mode.\n"));
  };


  // Get the memory ranges.
  if(!DeviceIoControl(pmem_fd, PMEM_INFO_IOCTRL, NULL, 0, info_buffer, 4096,
                      &size, NULL)) {
    LogError(TEXT("Failed to get memory geometry,"));
    goto error_fd;
  };

  wprintf(TEXT("CR3: 0x%010llX\n %d memory ranges:\n"), info->cr3,
          info->number_of_runs);

  for(i=0; i<info->number_of_runs; i++) {
    wprintf(TEXT("Start 0x%08llX - Length 0x%08llX\n"), info->runs[i]);
  };

  // Create the output file.
  HANDLE out_fd = CreateFile(output_filename,
                             GENERIC_WRITE, // Write is needed for IOCTL.
                             FILE_SHARE_READ,
                             NULL,
                             CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL,
                             NULL);
  if (out_fd == INVALID_HANDLE_VALUE) {
    LogError(TEXT("Unable to create output file."));
    goto error_fd;
  };

  __int64 offset = 0;
  for(i=0; i<info->number_of_runs; i++) {
    if(info->runs[i].start > offset) {
      pad(out_fd, offset, info->runs[i].start);
    };

    copy_memory(out_fd, pmem_fd, info->runs[i].start,
                info->runs[i].start + info->runs[i].length);

    offset = info->runs[i].start + info->runs[i].length;
  };

  CloseHandle(out_fd);

 error_fd:
  CloseHandle(pmem_fd);
 error:
  return -1;

};


int _tmain(int argc, _TCHAR* argv[]) {
  int i;
  int mode = PMEM_MODE_PHYSICAL;
  int write_mode = 0;
  int only_load_driver = 0;
  int only_unload_driver = 0;

  if(argc < 2) {
    help(argv[0]);
    return -1;
  };

  for(i=1; i<argc; i++) {
    if(argv[i][0] == '-') {
      switch(argv[i][1]) {
      case 'l': {
        only_load_driver=1;
      }; break;

      case 'u': {
        only_unload_driver=1;
      };
      case '1': {
        mode = PMEM_MODE_IOSPACE;
        break;
      };
      case '2': {
        mode = PMEM_MODE_PHYSICAL;
        break;
      }
#if PMEM_WRITE_MODE
      case 'w': {
        wprintf(L"Will enable write mode\n");
        write_mode = 1;
      }; break;
#endif
      default: {
        help(argv[0]);
        return -1;
      }; break;

      };  // Switch.

    } else break;   //First option without - means end of options.
  };

  // Now run what the user wanted.
  if (only_load_driver) {
    if(load_driver() && install_driver()) {
      DeleteFile(driver_filename);
      wprintf(L"Loaded Driver.\n", argv[i]);

      if (write_mode) {
        set_write_enabled();
      }

      return 0;
    };
  } else if (only_unload_driver) {
    if(uninstall_driver()) {
      wprintf(L"Driver Unloaded.\n", argv[i]);
      return 0;
    };
    return -1;
  } else {
    wprintf(L"Will write to %s\n", argv[i]);
    load_driver() && install_driver();
    write_raw_image(argv[i], mode);
    DeleteFile(driver_filename);
    uninstall_driver();
    return 0;
  }
}
