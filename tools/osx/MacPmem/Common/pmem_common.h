//  MacPmem - Rekall Memory Forensics
//  Copyright (c) 2015 Google Inc. All rights reserved.
//
//  Implements the /dev/pmem device to provide read/write access to
//  physical memory.
//
//  Authors:
//   Adam Sindelar (adam.sindelar@gmail.com)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef MacPmem_pmem_common_h
#define MacPmem_pmem_common_h

#include <pexpert/i386/efi.h>

// This comes from libkern/version.h but is redefined here because it affects
// the size of our struct and I want to be super duper sure it's the same size
// always.
#define PMEM_OSVERSIZE 256

// Size of the name of a memory range (purpose field in pmem_memdesc_t)
#define PMEM_NAMESIZE 40

#define PMEM_IOCTL_BASE 'p'
#define PMEM_API_VERSION ((char) 3)

#ifdef __LP64__
#define PMEM_PTRARG uint64_t
#else
#define PMEM_PTRARG uint32_t
#endif


// This sysctl control will copyout the meta struct. This is one of two ways
// of getting the data, the other being /dev/pmem_info.
//
// This is unlike the Linux version of pmem, which uses ioctl calls for the
// same purpose. I refer the reader to the Boundary Crossing section of Apple's
// XNU Kernel Programming Guide [1] for a discussion of the tradeoffs between
// different ways of communicating between kernel and userland.
//
// 1: https://developer.apple.com/library/mac/documentation/Darwin/Conceptual/KernelProgramming/boundaries/boundaries.html
#define PMEM_SYSCTL_NAME "kern.pmem_info"


// These are used for names of the physical memory device and the YAML device
// respectively.
#ifndef PMEM_DEVNAME
#define PMEM_DEVNAME "pmem"
#endif

#ifndef PMEM_DEVINFO
#define PMEM_DEVINFO "pmem_info"
#endif


////////////////////////////////////////////////////////////////////////////////
// MARK: Enums and their names to support metadata structs
////////////////////////////////////////////////////////////////////////////////

// This enum tells you whether the memory range is categorized using the
// EFI taxonomy or the PCI taxonomy, but it doesn't say where the information
// came from - you have the hardware informant flag for that.
typedef enum {
    pmem_efi_range_type,
    pmem_pci_range_type,
    pmem_struct_layout_type
} pmem_meta_record_type_t;


static const char *pmem_record_type_names[] = {
    "efi_range",
    "pci_range"
};


static const char *pmem_efi_type_names[] = {
    "EfiReservedMemoryType",
    "EfiLoaderCode",
    "EfiLoaderData",
    "EfiBootServicesCode",
    "EfiBootServicesData",
    "EfiRuntimeServicesCode",
    "EfiRuntimeServicesData",
    "EfiConventionalMemory",
    "EfiUnusableMemory",
    "EfiACPIReclaimMemory",
    "EfiACPIMemoryNVS",
    "EfiMemoryMappedIO",
    "EfiMemoryMappedIOPortSpace",
    "EfiPalCode",
    "EfiMaxMemoryType"
};


// Unlike the EFI enum, the below rigorously scientific taxonomy is my own
// invention. Now bear with me, because the number of options can get a little
// crazy.
typedef enum {
    pmem_PCIWiredMemory,   // Conventional RAM backs this.
    pmem_PCIDeviceMemory,  // Wired to the device.
    pmem_PCIUnknownMemory  // Unknown to me, that is.
} pmem_pci_mem_type_t;


static const char *pmem_pci_type_names[] = {
    "PCIWiredMemory",
    "PCIDeviceMemory",
    "PCIUnknownMemory"
};


////////////////////////////////////////////////////////////////////////////////
// MARK: Metadata record structs
////////////////////////////////////////////////////////////////////////////////

#pragma pack(push, 1)

typedef struct {
    pmem_pci_mem_type_t pci_type;
    unsigned long long start;
    unsigned long long length;
    unsigned int hw_informant  : 1;
    unsigned int unused_flags  : 31;
} pmem_pci_range_t;


typedef struct {
    EFI_MEMORY_TYPE efi_type;
    unsigned long long start;
    unsigned long long length;
    unsigned int hw_informant  : 1;
    unsigned int unused_flags  : 31;
} pmem_efi_range_t;


// Represents a memory range of some kind. It may be safe to read from, it may
// not. I don't know - it's up to you.
typedef struct {
    int subtype;
    unsigned long long start;
    unsigned long long length;
    unsigned int hw_informant  : 1;
    unsigned int unused_flags  : 31;
} pmem_generic_range_t;


// Represents any type of thing pmem may want to communicate more than one
// instance of. Currently, they are memory ranges, but other objects may be
// returned in the future.
typedef struct {
    pmem_meta_record_type_t type;

    // This array is tightly packed, so this is also the offset from the head
    // of this record to the head of the next record.
    unsigned int size;

    // Description of what this record is for, e.g. name of a PCI device.
    char purpose[PMEM_NAMESIZE];

    union {
        pmem_generic_range_t generic_range;
        pmem_efi_range_t efi_range;
        pmem_pci_range_t pci_range;
    };
} pmem_meta_record_t;

////////////////////////////////////////////////////////////////////////////////
// MARK: Main metadata struct
////////////////////////////////////////////////////////////////////////////////

typedef struct {
    // Always set. Reserved is zeroed.
    unsigned int size; // Size of this struct, including the ranges array.
    unsigned int pmem_api_version     : 8;
    unsigned int reserved             : 24;

    // Offset, relative to beginning of struct, to the records[] array.
    unsigned long long records_offset;

    // Set from boot args:
    unsigned int kernel_poffset; // Physical offset of the kernel.
    unsigned int kaslr_slide; // Constant KASLR offset.
    unsigned int mmap_poffset; // Physical offset of the EFI physmap.
    unsigned int mmap_desc_version; // EFI standard version.
    unsigned int mmap_size; // Size of the physmap (in bytes).
    unsigned int mmap_desc_size; // Size of each EFI physmap struct.
    unsigned long long phys_mem_size; // Size of the physical memory.
    unsigned long long pci_config_space_base;

    // Dumped from the CR3 register. It should be noted that, on 64bit systems,
    // these are just the values of some process whose context the machine
    // happened to be in when we dumped this. It'll probably be different each
    // time you dump it, and yet still valid (magic).
    unsigned long long cr3; // The value of the CR3 register, such as it was.
    unsigned long long dtb_poffset; // The physical address of a (some) DTB.

    // Copied from the kernel version banner.
    char kernel_version[PMEM_OSVERSIZE];

    // Chosen symbol offsets, so analysis tools don't have to scan for them.
    unsigned long long version_poffset; // The physical offset of the version.

    // The records array holds all kinds of things, such as PCI and EFI memory
    // ranges.
    unsigned int record_count;

    // Used size of the records array (allocated may be more).
    unsigned int records_end;

    // Model-specific registers.
    unsigned long long msr_ia32_sysenter_eip;
    unsigned long long msr_ia32_gs_base;

    // Reserved so we don't need to up the API version every time we add an MSR.
    unsigned long long msr_reserved[6];

    // CPUID information.
    //
    // 'cpuid' is not a privileged instruction, but the information it returns
    // in ring 0 can be subtly different from ring 3. For example, some VMs
    // return different version strings (e.g. VMWare lies to userland about
    // being an Intel CPU).
    char cpuid_vendor_string[12]; // Not null-termed!

    // Records are variable length, so naive users just see a byte array.
    char records[];
} pmem_meta_t;

#pragma pack(pop)

////////////////////////////////////////////////////////////////////////////////
// MARK: Metadata struct request flags
////////////////////////////////////////////////////////////////////////////////

#define PMEM_INFO_CR3              0x1  // Dump the CR3 register.
#define PMEM_INFO_BOOTARGS         0x2  // Parse the boot args struct.
#define PMEM_INFO_KERNEL_VERSION   0x4  // Copy the kernel version string.
#define PMEM_INFO_LIST_PCI         0x8  // Get PCI memory ranges.
#define PMEM_INFO_LIST_PHYSMAP     0x10 // Get the physical map ranges from EFI.
#define PMEM_INFO_LIST_SYMBOLS     0x20 // List select symbols' offsets.
#define PMEM_INFO_MSRS             0x40 // Dump model-specific registers.
#define PMEM_INFO_CPUID            0x80 // Dump CPUID information. (See above.)

#define PMEM_INFO_ALL 0xFFFFFFFF // Every flag, even some that don't exist yet.

#endif
