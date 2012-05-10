#include "read.h"

static LONG PhysicalMemoryPartialRead(IN PDEVICE_EXTENSION extension, LARGE_INTEGER offset, PCHAR buf, ULONG count) {
  ULONG page_offset = offset.QuadPart % PAGE_SIZE;
  ULONG to_read = min(PAGE_SIZE - page_offset, count);
  PUCHAR mapped_buffer = NULL;
  SIZE_T ViewSize = PAGE_SIZE;
  NTSTATUS NtStatus;


  /* Make sure we have a valid handle now. */
  if(extension->MemoryHandle == 0) {
    UNICODE_STRING PhysicalMemoryPath;
    OBJECT_ATTRIBUTES MemoryAttributes;

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
    // We define Memory's handle through ZwOpenSection()
    //
    NtStatus = ZwOpenSection(&extension->MemoryHandle,
                             SECTION_MAP_READ,
                             &MemoryAttributes);

    if (!NT_SUCCESS(NtStatus))
    {
        DbgPrint("Failed ZwOpenSection(MemoryHandle) => %08X\n", NtStatus);
        return -1;
    }
  };

  /* Map page into the Kernel AS */
  NtStatus = ZwMapViewOfSection(extension->MemoryHandle, (HANDLE) -1,
                                &mapped_buffer, 0L, PAGE_SIZE, &offset, &ViewSize, ViewUnmap,
                                0, PAGE_READONLY);

  if (NT_SUCCESS(NtStatus)) {
    RtlCopyMemory(buf, mapped_buffer + page_offset, to_read);
    ZwUnmapViewOfSection((HANDLE)-1, mapped_buffer);

  } else {
    DbgPrint("Failed to Map page at 0x%llX\n", offset.QuadPart);
    RtlZeroMemory(buf, to_read);
  };

  return to_read;
};


static NTSTATUS DeviceRead(IN PDEVICE_EXTENSION extension, LARGE_INTEGER offset, PCHAR buf, ULONG *count,
                           LONG (*handler)(IN PDEVICE_EXTENSION, LARGE_INTEGER, PCHAR, ULONG)
                           ) {
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

  //Get I/o Stack Location & Device Extension
  pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);

  //Get User Output Buffer & Length
  BufLen = pIoStackIrp->Parameters.Read.Length;
  BufOffset = pIoStackIrp->Parameters.Read.ByteOffset;
  Buf = (PCHAR)(Irp->AssociatedIrp.SystemBuffer);

  switch(extension->mode) {
    case ACQUISITION_MODE_PHYSICAL_MEMORY:
      status = DeviceRead(extension, BufOffset, Buf, &BufLen, PhysicalMemoryPartialRead);
      Irp->IoStatus.Information = pIoStackIrp->Parameters.Read.Length;
      break;

    default:
      DbgPrint("Acquisition mode %u not supported.\n", extension->mode);
      status = -1;
      BufLen = 0;
  }

  Irp->IoStatus.Status = status;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  return STATUS_SUCCESS;
}

