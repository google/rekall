/*
  Copyright 2012-2013 Michael Cohen <scudette@gmail.com>

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

#define Log(x, ...) wprintf(x, __VA_ARGS__)


void help(TCHAR *ExeName)
{
  Log(L"Winpmem - A memory imager for windows.\n"
          L"Copyright Michael Cohen (scudette@gmail.com) 2012-2014.\n\n");

  Log(L"Version %s\n", version);
  Log(L"Usage:\n");
  Log(L"  %s [option] [output path]\n", ExeName);

  Log(L"\nOption:\n");
  Log(L"  -l    Load the driver and exit.\n"
      L"  -u    Unload the driver and exit.\n"
      L"  -d [filename]\n"
      L"        Extract driver to this file (Default use random name).\n"
      L"  -h    Display this help.\n"
      L"  -w    Turn on write mode.\n"
      L"  -0    Use MmMapIoSpace method.\n"
      L"  -1    Use \\\\Device\\PhysicalMemory method (Default for 32bit OS).\n"
      L"  -2    Use PTE remapping (AMD64 only - Default for 64bit OS).\n"
      L"  -3    Use PTE remapping with PCI instrospection (AMD64 Only).\n"
      L"  -e    Produce an ELF core dump.\n"
      L"\n");

  Log(L"NOTE: an output filename of - will write the image to STDOUT.\n");
  Log(L"\nExamples:\n");
  Log(L"%s physmem.raw\nWrites an image to physmem.raw\n", ExeName);
  Log(L"\n%s -e - | nc 192.168.1.1 80\n", ExeName);
  Log(L"Writes an elf coredump to netcat for network transport.\n");
}

/* Create the corrent WinPmem object. Currently this selects between
   32/64 bit implementations.
*/
WinPmem *WinPmemFactory() {
  SYSTEM_INFO sys_info;
  ZeroMemory(&sys_info, sizeof(sys_info));

  GetNativeSystemInfo(&sys_info);
  switch(sys_info.wProcessorArchitecture) {
  case PROCESSOR_ARCHITECTURE_AMD64:
    return new WinPmem64();

  case PROCESSOR_ARCHITECTURE_INTEL:
    return new WinPmem32();

  default:
    return NULL;
  }
};


int _tmain(int argc, _TCHAR* argv[]) {
  __int64 i, status;
  unsigned __int32 mode = PMEM_MODE_AUTO;
  __int64 write_mode = 0;
  __int64 only_load_driver = 0;
  __int64 only_unload_driver = 0;
  __int64 coredump_output = 0;

  WinPmem *pmem_handle = WinPmemFactory();
  TCHAR *driver_filename = NULL;

  if(argc < 2) {
    goto error;
  };

  for(i=1; i<argc; i++) {
    if(argv[i][0] == '-' && argv[i][1] != 0) {
      switch(argv[i][1]) {
      case 'l': {
        only_load_driver=1;
        break;
      };
      case 'u': {
        only_unload_driver=1;
        break;
      };
      case 'd': {
        i++;
        driver_filename = argv[i];
        if (!driver_filename) goto error;
      }; break;

      case '0': {
        mode = PMEM_MODE_IOSPACE;
        break;
      };
      case '1': {
        mode = PMEM_MODE_PHYSICAL;
        break;
      }
      case '2': {
        mode = PMEM_MODE_PTE;
        break;
      }
      case '3': {
        mode = PMEM_MODE_PTE_PCI;
        break;
      }
      case 'w': {
        Log(TEXT("Enabling write mode.\n"));
        write_mode = 1;
        break;
      };

      case 'e': {
        Log(TEXT("Will write an elf core dump.\n"));
        coredump_output = 1;
      }; break;

      default: {
        goto error;
      };

      };  // Switch.

    } else break;   //First option without - means end of options.
  };

  // Now run what the user wanted.
  if (driver_filename) {
    pmem_handle->set_driver_filename(driver_filename);
  }

  if (only_load_driver) {
    status = pmem_handle->install_driver();
    if (status > 0) {
      pmem_handle->set_acquisition_mode(mode);

      if(write_mode) {
	pmem_handle->set_write_enabled();
      };

      pmem_handle->print_memory_info();
    };

  } else if (only_unload_driver) {
    status = pmem_handle->uninstall_driver();

  } else if (argv[i]) {
    pmem_handle->set_driver_filename(driver_filename);

    status = pmem_handle->create_output_file(argv[i]);

    if (status > 0 &&
        pmem_handle->install_driver() > 0 &&
        pmem_handle->set_acquisition_mode(mode) > 0) {
      if (coredump_output) {
        status = pmem_handle->write_coredump();
      } else {
        status = pmem_handle->write_raw_image();
      };
    };

    pmem_handle->uninstall_driver();

    // Just extract the driver and exit.
  } else if (driver_filename) {
    status = pmem_handle->extract_driver(driver_filename);
  } else {
    goto error;
  };

  delete pmem_handle;

  return (int)status;

 error:
  if(pmem_handle) {
    delete pmem_handle;
  };
  help(argv[0]);
  return -1;
}
