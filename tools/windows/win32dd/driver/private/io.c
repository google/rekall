/*++
    Kernel Land Physical Memory Dumper
    Copyright (C) 2008 Matthieu Suiche http://www.msuiche.net 

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

    - io.c

Abstract:

    - 


Environment:

    - Kernel mode

Revision History:

    - Matthieu Suiche

--*/

#include "precomp.h"

/*++
Function Name: IoWriteRawDump

Overview:
        - 

Parameters:
        - DeviceObject: Pointer to DEVICE_OBJECT.

        - Context: Pointer to Context.

Return Values:
        - NTSTATUS
--*/
NTSTATUS 
IoWriteRawDump_Level0(IN PDEVICE_OBJECT DeviceObject, 
                      IN PUNICODE_STRING FilePath)
{
  PDEVICE_EXTENSION ext=(PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
  UNICODE_STRING PhysicalMemoryPath;
  OBJECT_ATTRIBUTES MemoryAttributes, DumpFileAttributes;
  HANDLE MemoryHandle, RawHandle;
  IO_STATUS_BLOCK IoStatusBlock;
  LARGE_INTEGER ViewBase;
  NTSTATUS NtStatus;
  ULONG PageIndex;
  ULONG TotalPhysicalPages;
  SIZE_T ViewSize;
  PUCHAR Buffer;
  PVOID Object = NULL;
  PCHAR NullPage;
  
  //
  // We copy both, path to PhysicalMemory and destination file into
  // UNICODE_STRING types.
  //
  RtlInitUnicodeString(&PhysicalMemoryPath,
                       L"\\Device\\PhysicalMemory");

  //
  // We initialize object attributes of Memory
  //
  InitializeObjectAttributes(&MemoryAttributes,
                             &PhysicalMemoryPath,
                             OBJ_KERNEL_HANDLE,
                             (HANDLE) NULL,
                             (PSECURITY_DESCRIPTOR) NULL);

  //
  // We initialize Memory's handle.
  //
  MemoryHandle = 0;

  //
  // We define Memory's handle through ZwOpenSection()
  //
  NtStatus = ZwOpenSection(&MemoryHandle,
                           SECTION_MAP_READ,
                           &MemoryAttributes);
  
  //
  // We're ready to catch errors!
  //
  if (!NT_SUCCESS(NtStatus))
  {
    DbgPrint("[win32dd] ZwOpenSection(MemoryHandle) => %08X\n", NtStatus);
    return NtStatus;
  }

  //
  // We provides access validation on Memory's handle.
  //
  NtStatus = ObReferenceObjectByHandle(MemoryHandle,
                                       SECTION_MAP_READ,
                                       (POBJECT_TYPE) NULL,
                                       KernelMode,
                                       &Object,
                                       (POBJECT_HANDLE_INFORMATION) NULL);
  
  //
  // We catch error if we cannot provide access.
  //
  if (!NT_SUCCESS(NtStatus))
  {
    DbgPrint("[win32dd] ObReferenceObjectByHandle(MemoryHandle) => %08X\n", NtStatus);
    ZwClose(MemoryHandle);
    return NtStatus;
  }

  // Retrieve the size of the physical memory. This is not the total pages, but
  // the base address of the last run and the number of pages in it.
  {
    PHYSICAL_MEMORY_RUN last_run = &ext->descriptor->Run[ext->descriptor->NumberOfRuns -1];
    TotalPhysicalPages = last_run->BasePage + last_run->PageCount;
  };

  NtStatus = wddCreateFile(FilePath, &RawHandle);
  if (!NT_SUCCESS(NtStatus)) {
    ZwClose(MemoryHandle);
    return NtStatus;
  }
  //
  // Physical Memory position is set to 0x00000000
  //
  ViewBase.LowPart = 0;
  ViewBase.HighPart = 0;

  //
  // Allocate a null page.
  //
  NullPage = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, NULL_TAG);

  //
  // We fill the buffer with null bytes.
  //
  RtlZeroMemory(NullPage, PAGE_SIZE);

  //
  // Here is the main loop, to copy pages.
  //
  for (PageIndex = 0; PageIndex < TotalPhysicalPages; PageIndex++) {
    // We initialize variables again, again and again.
    Buffer = NULL;
    ViewSize = PAGE_SIZE;

    // Get ready to read into Physical Memory device.
    // Note from the developper: DONT USE PAGE_NOCACHE flag!!
    NtStatus = ZwMapViewOfSection(MemoryHandle,
                                      (HANDLE) -1,
                                      &Buffer,
                                      0L,
                                      PAGE_SIZE,
                                      &ViewBase,
                                      &ViewSize,
                                      ViewUnmap,
                                      0,
                                      PAGE_READONLY);

        if (NT_SUCCESS(NtStatus))
        {
            //
            // We write current page into the output file.
            //
            NtStatus = ZwWriteFile(RawHandle, 0, 0, 0, &IoStatusBlock, Buffer, PAGE_SIZE, &ViewBase, 0);

            if (!NT_SUCCESS(NtStatus))
            {
                DbgPrint("[win32dd] ZwWriteFile(RawHandle) => %08X\n", NtStatus);

                //
                // We don't forget to unmap the page before leaving!
                //
                ZwUnmapViewOfSection((HANDLE)-1, Buffer);

                //
                // We leave the loop.
                //
                break;
            }

            //
            // We don't forget to unmap the page before continuing.
            //
            ZwUnmapViewOfSection((HANDLE)-1, Buffer);

            //
            // Next page!
            //
            ViewBase.LowPart += PAGE_SIZE;
        }
        else
        {
            DbgPrint("[win32dd] ZwMapViewOfSection(MemoryHandle) => %08X\n", NtStatus);

            //
            // Here is a specific case.
            //
            if (PageIndex > 0)
            {
                //
                // Notification
                //
                DbgPrint("[win32dd] Cannot access to page number %08X, this page will be filled with null bytes.\n", PageIndex);

                //
                // We write a null page. If we cannot access.
                //
                NtStatus = ZwWriteFile(RawHandle, 0, 0, 0, &IoStatusBlock, NullPage, PAGE_SIZE, &ViewBase, 0);

                //
                // Next page!
                //
                ViewBase.LowPart += PAGE_SIZE;

                //
                // Next.
                //
                continue;
            }

            //
            // We leave the loop.
            //
            break;
        }
    }

    //
    // Have we done good job?
    //
    if (PageIndex == TotalPhysicalPages) NtStatus = STATUS_SUCCESS;

    //
    // Dereferencing Physmem object
    //
    ObfDereferenceObject(Object);

    //
    // Free buffer
    //
    ExFreePoolWithTag(NullPage, NULL_TAG);

    wddCloseFile(RawHandle);
    
    //
    // Closing physical memory handle.
    //
    ZwClose(MemoryHandle);

    return NtStatus;
}

/*++
Function Name: IoWriteRawDump

Overview:
        - 

Parameters:
        - DeviceObject: Pointer to DEVICE_OBJECT.

        - Context: Pointer to Context.

Return Values:
        - NTSTATUS
--*/
NTSTATUS 
IoWriteRawDump_Level1(IN PDEVICE_OBJECT DeviceObject, 
                      IN PUNICODE_STRING FilePath)
{
OBJECT_ATTRIBUTES DumpFileAttributes;
HANDLE RawHandle;
IO_STATUS_BLOCK IoStatusBlock;
LARGE_INTEGER ViewBase;
NTSTATUS NtStatus;
ULONG PageIndex;
ULONG TotalPhysicalPages;
SIZE_T ViewSize;
PUCHAR Buffer;
PCHAR NullPage;

    //
    // Retrieve the size of the physical memory.
    //
    TotalPhysicalPages = MiGetTotalPhysicalPages();

    NtStatus = wddCreateFile(FilePath, &RawHandle);

    if (!NT_SUCCESS(NtStatus)) return NtStatus;

    //
    // Physical Memory position is set to 0x00000000
    //
    ViewBase.LowPart = 0;
    ViewBase.HighPart = 0;

    //
    // Allocate a null page.
    //
    NullPage = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, NULL_TAG);

    //
    // We fill the buffer with null bytes.
    //
    RtlZeroMemory(NullPage, PAGE_SIZE);

    //
    // Here is the main loop, to copy pages.
    //
    for (PageIndex = 0; PageIndex < TotalPhysicalPages; PageIndex++)
    {
        //
        // We initialize variables again, again and again.
        //
        Buffer = NULL;
        ViewSize = PAGE_SIZE;

        Buffer = MmMapIoSpace(ViewBase, PAGE_SIZE, MmNonCached);

        if (Buffer)
        {
            //
            // We write current page into the output file.
            //
            NtStatus = ZwWriteFile(RawHandle, 0, 0, 0, &IoStatusBlock, Buffer, PAGE_SIZE, &ViewBase, 0);

            if (!NT_SUCCESS(NtStatus))
            {
                DbgPrint("[win32dd] ZwWriteFile(RawHandle) => %08X\n", NtStatus);

                //
                // We don't forget to unmap the page before leaving!
                //
                MmUnmapIoSpace(Buffer, PAGE_SIZE);

                //
                // We leave the loop. Because we cannot write.
                //
                break;
            }
            
            //
            // We don't forget to unmap the page before continuing.
            //
            MmUnmapIoSpace(Buffer, PAGE_SIZE);

            //
            // Next page!
            //
            ViewBase.LowPart += PAGE_SIZE;
        }
        else
        {
            DbgPrint("[win32dd] ZwMapViewOfSection(MemoryHandle) => %08X\n", NtStatus);
            
            //
            // Here is a specific case.
            //
            if (PageIndex > 0)
            {
                //
                // Notification
                //
                DbgPrint("[win32dd] Cannot access to page number %08X, this page will be filled with null bytes.\n", PageIndex);

                //
                // We write a null page. If we cannot access.
                //
                NtStatus = ZwWriteFile(RawHandle, 0, 0, 0, &IoStatusBlock, NullPage, PAGE_SIZE, &ViewBase, 0);

                //
                // Next page!
                //
                ViewBase.LowPart += PAGE_SIZE;

                //
                // Next.
                //
                continue;
            }

            //
            // We leave the loop.
            //
            break;
        }
    }

    //
    // Have we done good job?
    //
    DbgPrint("PageIndex %08X - TotalPhysicalPages %08X",
        PageIndex, TotalPhysicalPages);
    if (PageIndex == TotalPhysicalPages) NtStatus = STATUS_SUCCESS;

    //
    // Free buffer
    //
    ExFreePoolWithTag(NullPage, NULL_TAG);

    wddCloseFile(RawHandle);

    DbgPrint("NtStatus: %08X \n", NtStatus);
    return NtStatus;
}

NTSTATUS
IoWriteCrashDump(IN PUNICODE_STRING FullDosPath,
                 IN ULONG BugCheckCode,
                 IN ULONG_PTR BugCheckParameter1,
                 IN ULONG_PTR BugCheckParameter2,
                 IN ULONG_PTR BugCheckParameter3,
                 IN ULONG_PTR BugCheckParameter4,
                 IN PCONTEXT Context)
{
EXCEPTION_RECORD Exception;
PDUMP_CONTROL_BLOCK Dcb;
ULONG_PTR MemoryAddress;
ULONG_PTR DirBasePage;
ULONG BytesRemaining;
PDUMP_HEADER Header;

PPFN_NUMBER Page;
PFN_NUMBER PageOffset;
ULONG RunIndex, PageIndex, BasePage;
ULONG ByteOffset;
ULONG ByteCount;
PVOID CurrentPage, CurrentPage2;

PHYSICAL_ADDRESS PhysicalAddress, RawAddress;

HANDLE DmpHandle;
NTSTATUS NtStatus;

IO_STATUS_BLOCK IoStatusBlock;

PUCHAR NullPage;

    NtStatus = wddCreateFile(FullDosPath, &DmpHandle);

    if (!NT_SUCCESS(NtStatus))
    {
        return NtStatus;
    }

    Dcb = IopDumpControlBlock;

    if (!Dcb)
    {
        DbgPrint("[win32dd] !Dcb\n");
        wddCloseFile(DmpHandle);
        return STATUS_UNSUCCESSFUL;
    }

    DbgPrint("Lets starts it\n");
    if (Dcb->Flags & DCB_DUMP_ENABLED)
    {

        //
        // IopFillDumpHeader()
        //
        Header = Dcb->HeaderPage;

        RtlFillMemoryUlong(Header, PAGE_SIZE, 'EGAP');
        Header->ValidDump = 'PMUD';

        Header->BugCheckCode = BugCheckCode;

        Header->BugCheckParameter1 = BugCheckParameter1;
        Header->BugCheckParameter2 = BugCheckParameter2;
        Header->BugCheckParameter3 = BugCheckParameter3;
        Header->BugCheckParameter4 = BugCheckParameter4;

        //
        // 32bits
        //
        //
        // TODO: KdGetDebuggerDataBlock() check pointer.
        //
        Header->DirectoryTableBase = MiGetPdeBase();
        Header->PfnDataBase = (PULONG)*((PULONG)KdGetDebuggerDataBlock()->MmPfnDatabase);
        Header->PsLoadedModuleList = (PLIST_ENTRY)((PULONG)KdGetDebuggerDataBlock()->PsLoadedModuleList);
        Header->PsActiveProcessHead = (PLIST_ENTRY)((PULONG)KdGetDebuggerDataBlock()->PsActiveProcessHead);
        Header->KeNumberOfProcessors = Dcb->KeNumberProcessors;
        Header->MajorVersion = Dcb->MajorVersion;
        Header->MinorVersion = Dcb->MinorVersion;
        Header->KdDebuggerDataBlock = KdGetDebuggerDataBlock();
        Header->PaeEnabled = PaeEnabled();

        Header->MachineImageType = CURRENT_IMAGE_TYPE();

        //
        // Version User
        //
        RtlCopyMemory(Header->VersionUser,
                      Dcb->VersionUser,
                      sizeof(Dcb->VersionUser));

        //
        // Memory descriptor
        //
        RtlCopyMemory(&Header->PhysicalMemoryBlock,
                      Dcb->MemoryDescriptor,
                      sizeof(PHYSICAL_MEMORY_DESCRIPTOR) +
                      ((Dcb->MemoryDescriptor->NumberOfRuns - 1) *
                      sizeof(PHYSICAL_MEMORY_RUN)));

        //
        // TODO: Check if there is enough space to copy KPROCESSOR_STATE
        // instead of only Context
        //
        //
        // Context
        //
        RtlCopyMemory(&Header->Context,
                      Context,
                      sizeof(CONTEXT));

        //
        // Exception record.
        //
        Exception.ExceptionCode = STATUS_BREAKPOINT;
        Exception.ExceptionRecord = (PEXCEPTION_RECORD) NULL;
        Exception.NumberParameters = 0;
        Exception.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
        Exception.ExceptionAddress = (PVOID)Context->Eip;

        RtlCopyMemory(&Header->ExceptionRecord,
                      &Exception,
                      sizeof(EXCEPTION_RECORD));

        //
        // Set up type of dump.
        //
        Header->DumpType = DUMP_TYPE_FULL;

        //
        // Set the timestamp
        //
        RtlCopyMemory(&Header->SystemTime,
                      (PCHAR)(&SharedUserData->SystemTime),
                      sizeof(LARGE_INTEGER));

        RtlZeroMemory(&Header->RequiredDumpSpace, sizeof(LARGE_INTEGER));

        //
        // Set size information
        //
        IopInitializeDumpSpaceAndType(Dcb, Header);

        ZERO_ADDR(PhysicalAddress);
        ZERO_ADDR(RawAddress);

        DbgPrint("Writting Header ....\n");
        NtStatus = ZwWriteFile(DmpHandle, 0, 0, 0, &IoStatusBlock, Header, PAGE_SIZE, &RawAddress, 0);
        if (!NT_SUCCESS(NtStatus))
        {
            DbgPrint("[win32dd] Error: Cannot write header page\n");
            wddCloseFile(DmpHandle);
            return NtStatus;
        }

        RawAddress.LowPart += PAGE_SIZE;
    }

    //
    // Allocate a null page.
    //
    NullPage = ExAllocatePoolWithTag(PagedPool, PAGE_SIZE, NULL_TAG);

    //
    // We fill the buffer with null bytes.
    //
    RtlZeroMemory(NullPage, PAGE_SIZE);

    //
    // Compute Total Pages
    //
    for (RunIndex = 0;
         RunIndex < Dcb->MemoryDescriptor->NumberOfRuns; 
         RunIndex++)
    {
        //
        // Next "Run"
        //
        BasePage = Dcb->MemoryDescriptor->Run[RunIndex].BasePage;

        for (PageIndex = 0; 
             PageIndex < Dcb->MemoryDescriptor->Run[RunIndex].PageCount; 
             PageIndex++)
        {
            //PageOffset = (BasePage * PAGE_SIZE) + (PageIndex * PAGE_SIZE);

            PhysicalAddress.LowPart = (BasePage * PAGE_SIZE) + (PageIndex * PAGE_SIZE);

            CurrentPage = MmMapIoSpace(PhysicalAddress, PAGE_SIZE, MmNonCached);

            if (CurrentPage != NULL)
            {
                NtStatus = ZwWriteFile(DmpHandle, 0, 0, 0, &IoStatusBlock, CurrentPage, PAGE_SIZE, &RawAddress, 0);
                MmUnmapIoSpace(CurrentPage, PAGE_SIZE);
            }
            else
            {
                NtStatus = ZwWriteFile(DmpHandle, 0, 0, 0, &IoStatusBlock, NullPage, PAGE_SIZE, &RawAddress, 0);
            }

            if (!NT_SUCCESS(NtStatus))
            {
                DbgPrint("[win32dd] Error: Cannot write page from %08X to %08X\n", 
                    PhysicalAddress.LowPart,
                    RawAddress.LowPart);
            }

            RawAddress.LowPart += PAGE_SIZE;
        }
    }

    ExFreePoolWithTag(NullPage, NULL_TAG);

    wddCloseFile(DmpHandle);

    return NtStatus;
}
