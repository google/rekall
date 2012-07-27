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

#include "read.h"

static LONG PhysicalMemoryPartialRead(IN PDEVICE_EXTENSION extension,
                                      LARGE_INTEGER offset, PCHAR buf,
                                      ULONG count) {
  ULONG page_offset = offset.QuadPart % PAGE_SIZE;
  ULONG to_read = min(PAGE_SIZE - page_offset, count);
  PUCHAR mapped_buffer = NULL;
  SIZE_T ViewSize = PAGE_SIZE;
  NTSTATUS NtStatus;


  /* Make sure we have a valid handle now. */
  if(!extension->MemoryHandle) {
    UNICODE_STRING PhysicalMemoryPath;
    OBJECT_ATTRIBUTES MemoryAttributes;

    RtlInitUnicodeString(&PhysicalMemoryPath, L"\\Device\\PhysicalMemory");

    InitializeObjectAttributes(&MemoryAttributes,
                               &PhysicalMemoryPath,
                               OBJ_KERNEL_HANDLE,
                               (HANDLE) NULL,
                               (PSECURITY_DESCRIPTOR) NULL);

    NtStatus = ZwOpenSection(&extension->MemoryHandle,
                             SECTION_MAP_READ, &MemoryAttributes);

    if (!NT_SUCCESS(NtStatus)) {
      WinDbgPrint("Failed ZwOpenSection(MemoryHandle) => %08X\n", NtStatus);
      return -1;
    }
  };

  /* Map page into the Kernel AS */
  NtStatus = ZwMapViewOfSection(extension->MemoryHandle, (HANDLE) -1,
                                &mapped_buffer, 0L, PAGE_SIZE, &offset,
                                &ViewSize, ViewUnmap, 0, PAGE_READONLY);

  if (NT_SUCCESS(NtStatus)) {
    RtlCopyMemory(buf, mapped_buffer + page_offset, to_read);
    ZwUnmapViewOfSection((HANDLE)-1, mapped_buffer);

  } else {
    WinDbgPrint("Failed to Map page at 0x%llX\n", offset.QuadPart);
    RtlZeroMemory(buf, to_read);
  };

  return to_read;
};


// Read a single page using MmMapIoSpace.
static LONG MapIOPagePartialRead(IN PDEVICE_EXTENSION extension,
                                 LARGE_INTEGER offset, PCHAR buf,
                                 ULONG count) {
  ULONG page_offset = offset.QuadPart % PAGE_SIZE;
  ULONG to_read = min(PAGE_SIZE - page_offset, count);
  PUCHAR mapped_buffer = NULL;
  SIZE_T ViewSize = PAGE_SIZE;
  NTSTATUS NtStatus;
  LARGE_INTEGER ViewBase;

  // Round to page size
  ViewBase.QuadPart = offset.QuadPart - page_offset;

  // Map exactly one page.
  mapped_buffer = MmMapIoSpace(ViewBase, PAGE_SIZE, MmNonCached);

  if (mapped_buffer) {
    RtlCopyMemory(buf, mapped_buffer + page_offset, to_read);
  } else {
    // Failed to map page, null fill the buffer.
    RtlZeroMemory(buf, to_read);
  };

  MmUnmapIoSpace(mapped_buffer, PAGE_SIZE);

  return to_read;
};


static NTSTATUS DeviceRead(IN PDEVICE_EXTENSION extension, LARGE_INTEGER offset,
                           PCHAR buf, ULONG *count,
                           LONG (*handler)(IN PDEVICE_EXTENSION, LARGE_INTEGER,
                                           PCHAR, ULONG)) {
  int remaining = *count;

  while(remaining > 0) {
    int result = handler(extension, offset, buf, remaining);

    /* Error Occured. */
    if(result < 0) return result;
    /* No data available. */
    if(result==0) break;

    offset.QuadPart += result;
    buf += result;
    remaining -= result;
  };

  return STATUS_SUCCESS;
};


NTSTATUS PmemRead(IN PDEVICE_OBJECT  DeviceObject, IN PIRP  Irp) {
  PVOID Buf;       //Buffer provided by user space.
  ULONG BufLen;    //Buffer length for user provided buffer.
  LARGE_INTEGER BufOffset; // The file offset requested from userspace.
  ULONG DataLen;  //Buffer length for Driver Data Buffer
  PIO_STACK_LOCATION pIoStackIrp;
  PDEVICE_EXTENSION extension = DeviceObject->DeviceExtension;
  NTSTATUS status = STATUS_SUCCESS;

  pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
  BufLen = pIoStackIrp->Parameters.Read.Length;
  BufOffset = pIoStackIrp->Parameters.Read.ByteOffset;
  Buf = (PCHAR)(Irp->AssociatedIrp.SystemBuffer);

  switch(extension->mode) {

    // Read using the physical memory handle.
  case ACQUISITION_MODE_PHYSICAL_MEMORY:
    status = DeviceRead(extension, BufOffset, Buf, &BufLen,
                        PhysicalMemoryPartialRead);
    Irp->IoStatus.Information = pIoStackIrp->Parameters.Read.Length;
    break;

  case ACQUISITION_MODE_MAP_IO_SPACE:
    status = DeviceRead(extension, BufOffset, Buf, &BufLen,
                        MapIOPagePartialRead);
    Irp->IoStatus.Information = pIoStackIrp->Parameters.Read.Length;
    break;

  default:
    WinDbgPrint("Acquisition mode %u not supported.\n", extension->mode);
    status = -1;
    BufLen = 0;
  }

  Irp->IoStatus.Status = status;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  return STATUS_SUCCESS;
}

