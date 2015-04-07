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
#define PMEM_IOCTL_VERSION ((char) 1)

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


// This enum tells you whether the memory range is categorized using the
// EFI taxonomy or the PCI taxonomy, but it doesn't say where the information
// came from - you have the hardware informant flag for that.
typedef enum {
    pmem_efi_type,
    pmem_pci_type
} pmem_range_type_t;


static const char *pmem_range_type_names[] = {
    "efi_type",
    "pci_type"
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
    pmem_PCIWiredMemory, // Conventional RAM backs this.
    pmem_PCIDeviceMemory, // Wired to the device.
    pmem_PCIUnknownMemory // Unknown to me, that is.
} pmem_pci_mem_type_t;


static const char *pmem_pci_mem_type_names[] = {
    "PCIWiredMemory",
    "PCIDeviceMemory",
    "PCIUnknownMemory"
};

#pragma pack(push, 1)

// Represents a memory range of some kind. It may be safe to read from, it may
// not. I don't know - it's up to you.
typedef struct {
    unsigned int pmem_api_version      : 8;
    unsigned int reserved              : 23;
    unsigned int hw_informant_flag     : 1; // Set to 1 if informant was HW.
    pmem_range_type_t type;
    union {
        EFI_MEMORY_TYPE efi_type;
        pmem_pci_mem_type_t pci_type;
    } subtype;
    unsigned long long start;
    unsigned long long length;
    // Description of what this range is for, e.g. name of PCI device.
    char purpose[PMEM_NAMESIZE];
} pmem_memdesc_t;


typedef struct {
    // Always set. Yes, reserved is also set (to zeroes).
    unsigned int size; // Size of this struct, including the ranges array.
    unsigned int pmem_api_version     : 8;
    unsigned int reserved             : 24;

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

    // Populated by listing PCI and EFI physmap ranges - this null-terminated
    // array will contain both kinds of ranges. range_count will tell you how
    // many objects follow, because, on the off-chance that we ever run into
    // a range starting at zero, of size zero and also change the PMEM IOCTL
    // version from a positive integer to zero (bet you weren't expecting that)
    // you're going to need some way of knowing when the array stops.
    unsigned int range_count;
    pmem_memdesc_t ranges[];
} pmem_meta_t;

#pragma pack(pop)

// Info I/O flags
#define PMEM_INFO_CR3              0x1  // Dump the CR3 register.
#define PMEM_INFO_BOOTARGS         0x2  // Parse the boot args struct.
#define PMEM_INFO_KERNEL_VERSION   0x4  // Copy the kernel version string.
#define PMEM_INFO_LIST_PCI         0x8  // Get PCI memory ranges.
#define PMEM_INFO_LIST_PHYSMAP     0x10 // Get the physical map ranges from EFI.

#define PMEM_INFO_ALL 0xFFFFFFFF // Every flag, even some that don't exist yet.

// Commands:
#define PMEM_GET_INFO 10

#endif
