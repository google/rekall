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
    - Windows XPSP2 to Windows 8 inclusive, both 32 bit and 64 bit.

*********************************************************************/
#include "winpmem.h"

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
          L"  -w    Turn on/off write mode.\n"
          L"  -1    Use MmMapIoSpace method.\n"
          L"  -2    Use \\\\Device\\PhysicalMemory method (Default).\n"
          L"  -d    Produce a crashdump file.\n"
          L"\n");

  wprintf(L"\nNOTE: an output filename of - will write the image to STDOUT.\n");
  wprintf(L"\nExamples:\n");
  wprintf(L"%s physmem.raw\nWrites an image to physmem.raw\n", ExeName);
  wprintf(L"\n%s -d - | nc 192.168.1.1 80\n", ExeName);
  wprintf(L"Writes a crashdump file to netcat for network transport.\n");
}


int _tmain(int argc, _TCHAR* argv[]) {
  int i;
  int mode = PMEM_MODE_PHYSICAL;
  int write_mode = 0;
  int only_load_driver = 0;
  int only_unload_driver = 0;
  int crashdump_output = 0;

  if(argc < 2) {
    help(argv[0]);
    return -1;
  };

  for(i=1; i<argc; i++) {
    if(argv[i][0] == '-' && argv[i][1] != 0) {
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
      case 'w': {
        write_mode = 1;
      }; break;

      case 'd': {
        crashdump_output = 1;
      }; break;

      default: {
        help(argv[0]);
        return -1;
      }; break;

      };  // Switch.

    } else break;   //First option without - means end of options.
  };

  WinPmem pmem_handle;

  // Now run what the user wanted.
  if (only_load_driver) {
    pmem_handle.install_driver();

    if (write_mode) {
      pmem_handle.set_write_enabled();
    }

    pmem_handle.print_memory_info();

    return 0;
  } else if (only_unload_driver) {
    return pmem_handle.uninstall_driver();
  } else {
    int status = pmem_handle.create_output_file(argv[i]);

    if (status > 0 &&
        pmem_handle.install_driver() > 0 &&
        pmem_handle.set_acquisition_mode(mode) > 0) {
      if (crashdump_output) {
        status = pmem_handle.write_crashdump();
      } else {
        status = pmem_handle.write_raw_image();
      };
    };

    pmem_handle.uninstall_driver();
    return status;
  }
}
