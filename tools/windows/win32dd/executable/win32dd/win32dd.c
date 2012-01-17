/*++
    Kernel Land Physical Memory Dumper - win32dd
    Copyright (C) 2008  Matthieu Suiche http://www.msuiche.net

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

Module Name:

    - win32dd.c

Abstract:

    - Here is the client side to run the win32dd.sys driver.


Environment:

    - User mode

Revision History:

    - Matthieu Suiche

--*/

#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>

#include <windows.h>

#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)

#define FILE_DEVICE_UNKNOWN 0x00000022

#define METHOD_BUFFERED 0

#define FILE_READ_DATA ( 0x0001 )    // file & pipe
#define FILE_WRITE_DATA ( 0x0002 )   // file & pipe

#define IOCTL_WRITE_RAW_DUMP CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_WRITE_CRSH_DUMP CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define STATUS_SUCCESS 'ENOD'
#define STATUS_UNSUCCESSFUL 'LIAF'

USHORT
GetConsoleTextAttribute(HANDLE hConsole)
{
CONSOLE_SCREEN_BUFFER_INFO csbi;

    GetConsoleScreenBufferInfo(hConsole, &csbi);
    return(csbi.wAttributes);
}

void Red(TCHAR *Format, ...)
{
HANDLE Handle;
USHORT Color;
va_list va;

    Handle = GetStdHandle(STD_OUTPUT_HANDLE);

    Color = GetConsoleTextAttribute(Handle);

    SetConsoleTextAttribute(Handle, FOREGROUND_RED | FOREGROUND_INTENSITY);
    va_start(va, Format);
    vwprintf(Format, va);
    va_end(va); 

    SetConsoleTextAttribute(Handle, Color);
}

void White(TCHAR *Format, ...)
{
HANDLE Handle;
USHORT Color;
va_list va;

    Handle = GetStdHandle(STD_OUTPUT_HANDLE);

    Color = GetConsoleTextAttribute(Handle);

    SetConsoleTextAttribute(Handle, 0xF);
    va_start(va, Format);
    vwprintf(Format, va);
    va_end(va); 

    SetConsoleTextAttribute(Handle, Color);
}


void Green(TCHAR *Format, ...)
{
HANDLE Handle;
USHORT Color;
va_list va;

    Handle = GetStdHandle(STD_OUTPUT_HANDLE);

    Color = GetConsoleTextAttribute(Handle);

    SetConsoleTextAttribute(Handle, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    va_start(va, Format);
    vwprintf(Format, va);
    va_end(va); 

    SetConsoleTextAttribute(Handle, Color);
}

ULONG UninstallDriver(void)
{
SC_HANDLE ServiceManager, Service;
SERVICE_STATUS ServiceStatus;

    //
    // Open service manager
    //
    ServiceManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

    if (!ServiceManager) return 0;

    //
    // Open win32dd service.
    //
    Service = OpenService(ServiceManager, L"win32dd", SERVICE_ALL_ACCESS);

    if (!Service) return 0;

    CloseServiceHandle(ServiceManager);

    //
    // Stop our service.
    //
    ControlService(Service, SERVICE_CONTROL_STOP, &ServiceStatus);

    //
    // Delete service.
    //
    DeleteService(Service);

    CloseServiceHandle(Service);

    return 1;
}

ULONG InstallDriver(void)
{
SC_HANDLE ServiceManager, Service;
WCHAR DriverPath[MAX_PATH];
LPTSTR FilePart;

    //
    // Uninstall driver/service.
    //
    UninstallDriver();

    //
    // Open services manager.
    //
    ServiceManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

    //
    // Catch error.
    //
    if (!ServiceManager)
    {
        Red(L"Error: OpenServiceManager()\n");
        return 0;
    }

    //
    // Get full path + filename.
    //
    GetFullPathName(L"win32dd.sys", MAX_PATH - 1, DriverPath, &FilePart);

    //
    // We register the service.
    //
    Service = CreateService(ServiceManager,
                            L"win32dd",
                            L"win32dd",
                            SERVICE_ALL_ACCESS,
                            SERVICE_KERNEL_DRIVER,
                            SERVICE_DEMAND_START,
                            SERVICE_ERROR_NORMAL,
                            DriverPath,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL);

    //
    // The service might already exist.
    //
    if (GetLastError() == ERROR_SERVICE_EXISTS)
    {
        //
        // Then, we open it and get its handle.
        //
        Service = OpenService(ServiceManager, L"win32dd", SERVICE_ALL_ACCESS);
    }

    //
    // We don't need to Services manager handle for the next part.
    //
    CloseServiceHandle(ServiceManager);

    //
    // Too bad!
    //
    if (!Service) return 0;

    //
    // We try to run the driver/service.
    //
    if (!StartService(Service, 0, NULL))
    {
        //
        // It might be already running or not.
        //
        if (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
        {
            Red(L"Error: StartService(), Cannot start the driver. %08X\n", GetLastError());
            return 0;
        }
    }

    //
    // Close handle.
    //
    CloseServiceHandle(Service);
    return 1;
}

void Help(_TCHAR *ExeName)
{
    White(L"Usage:\n");
    wprintf(L"  %s [option] [output path]\n", ExeName);

    White(L"\nOption:\n");
    wprintf(L"  -r    Create a raw memory dump/snapshot. (default)\n"
            L"  -l    Level for the mapping (with -r option only).\n"
            L"     l 0  Open \\\\Device\\\\PhysicalMemory device (default).\n"
            L"     l 1  Use Kernel API MmMapIoSpace()\n\n");

    wprintf(L"  -d    Create a Microsoft full memory dump file (WinDbg compliant).\n"
            L"  -t    Type of MSFT dump file (with -d option only).\n"
            L"     t 0  Original MmPhysicalMemoryBlock, like BSOD. (default).\n"
            L"     t 1  MmPhysicalMemoryBlock (with PFN 0).\n\n");

    wprintf(L"  -h    Display this help.\n\n");

    White(L"\nSample:\n");
    wprintf(L"Usage: %s -d physmem.dmp\n"
          L"Usage: %s -l 1 -r C:\\dump\\physmem.bin\n\n", ExeName, ExeName);
}

int _tmain(UINT argc, _TCHAR* argv[])
{
ULONG BytesReturned;
HANDLE Device;
WCHAR FullPathName[MAX_PATH];
WCHAR NtFullPathName[MAX_PATH];
LPWSTR FilePart;
ULONG StatusCode;
ULONG IoControlCode;
ULONG StartTime, EndTime;

ULONG RawDumpSelected, MSFTDumpSelected;
ULONG Level;
ULONG Type;

UINT i;

    White(L"\n"
          L"  Win32dd - v1.2.1.20090106 - Kernel land physical memory acquisition\n"
          L"  Copyright (c) 2007 - 2009, Matthieu Suiche <http://www.msuiche.net>\n"
          L"  Copyright (c) 2008 - 2009, MoonSols <http://www.moonsols.com>\n"
          L"\n");

    if (argc < 2)
    {
        Help(argv[0]);
        return 0;
    }

    Type = 0;
    Level = 0;
    IoControlCode = IOCTL_WRITE_RAW_DUMP;

    for (i = 0; i < argc; i++)
    {
        if (argv[i][0] == '-')
        {
            switch (argv[i][1])
            {
                case 'r':
                    RawDumpSelected = TRUE;
                    IoControlCode = IOCTL_WRITE_RAW_DUMP;
                break;
                case 'd':
                    MSFTDumpSelected = TRUE;
                    IoControlCode = IOCTL_WRITE_CRSH_DUMP;
                break;
                case 'h':
                    Help(argv[0]);
                    return 0;
                break;
                case 'l':
                    switch (argv[i][3])
                    {
                        case '0':
                            Level = 0;
                        break;
                        case '1':
                            Level = 1;
                        break;
                        default:
                            Level = 0;
                        break;
                    }
                break;
                case 't':
                    switch (argv[i][3])
                    {
                        case '0':
                            Type = 0;
                        break;
                        case '1':
                            Type = 1;
                        break;
                        default:
                            Type = 0;
                        break;
                    }
                break;

            }
        }
    }

    if (argv[argc - 1][0] == '-')
    {
        //
        // User is doing n'importe quoi
        //
        Help(argv[0]);
        return 0;
    }

    //
    // Set Level Engine.
    //
    printf("-> Arguments (Level = %d, Type = %d)\n\n", Level, Type);
    IoControlCode |= ((Level << 6) | (Type << 4)) & 0xF0;

    //
    // Convert Dos path to Nt Path
    //
    GetFullPathName(argv[argc - 1], MAX_PATH - 10, FullPathName, &FilePart);
    wsprintf(NtFullPathName, L"\\??\\%s", FullPathName);

    wprintf(L"[win32dd] Lets dump it!\n");
    wprintf(L"[win32dd] Destination: %s\n", NtFullPathName);
    //
    // We check if the service is already running.
    //
    Device = CreateFile(L"\\\\.\\win32dd", 
                        GENERIC_ALL, 
                        FILE_SHARE_READ | FILE_SHARE_WRITE, 
                        NULL, OPEN_EXISTING, 
                        FILE_ATTRIBUTE_NORMAL, 
                        NULL);

    //
    // Else we run it.
    //
    if (Device == INVALID_HANDLE_VALUE) InstallDriver();

    //
    // We check again.
    //
    Device = CreateFile(L"\\\\.\\win32dd", 
                    GENERIC_ALL, 
                    FILE_SHARE_READ | FILE_SHARE_WRITE, 
                    NULL, OPEN_EXISTING, 
                    FILE_ATTRIBUTE_NORMAL, 
                    NULL);

    //
    // We probably never reach this point.
    //
    if (Device == INVALID_HANDLE_VALUE)
    {
        Red(L"Error: Cannot open \\\\.\\win32dd.\n");
        return 0;
    }

    wprintf(L"[win32dd] ");
    Green(L"Processing.... ");

    StartTime = GetTickCount();
    StatusCode = 0;

    //
    // We send destination path to the driver.
    //
    if (!DeviceIoControl(Device, IoControlCode, NtFullPathName, (ULONG)(wcslen(NtFullPathName) + 1) * sizeof(WCHAR), &StatusCode, sizeof(ULONG), &BytesReturned, NULL))
    {
        Red(L"Error: DeviceIoControl(), Cannot send IOCTL.\n");
    }

    EndTime = GetTickCount();

    if (StatusCode == STATUS_SUCCESS)
    {
        Green(L"Done.\n\n");
        Green(L"[win32dd] Physical memory dumped.\n");
    }
    else if (StatusCode == STATUS_UNSUCCESSFUL)
    {
        Red(L"Failed.\n\n");
    }

    printf("\nTime elapsed is %d seconds.\n\n", (EndTime - StartTime) / 1000);

    printf("[win32dd] Leaving...\n");

    //
    // Leaving..
    //
    UninstallDriver();

    return 1;
}