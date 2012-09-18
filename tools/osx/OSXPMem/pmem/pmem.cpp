// This driver implements a character device that can be used to read physical
// memory from user space. It creates a node "/dev/pmem", which can be read by
// user "root" and group "wheel".
//
// Copyright 2012 Google Inc. All Rights Reserved.
// Author: Johannes Stüttgen (johannes.stuettgen@gmail.com)
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

#include "pmem.h"

// Toggle this flag to enable/disable debug logging.
static const boolean_t pmem_debug_logging = TRUE;

// Tagname for memory allocations in the kernel.
static const char * const pmem_tagname = "PMEM";

// Constant offset to kernel memory for pointers stored in uint32_t on x86-64.
// On x86-32 kernel virtual addresses are mapped to physical addresses so this
// is not needed.
#ifdef __LP64__
  static const uint64_t pmem_kernel_voffset = 0xFFFFFF8000000000ULL;
#else
  static const uint32_t pmem_kernel_voffset = 0x00000000UL;
#endif

// Name of the physical memory device in '/dev/'.
static const char * const pmem_pmem_devname = "pmem";
// Minor numbers for devfs files
static const int pmem_dev_pmem_minor = 0;
// Node <-> Driver mappings.
static int pmem_devmajor = 0;
static void *pmem_devpmemnode = NULL;

// Tagname to use with the kernel malloc functions.
static OSMallocTag pmem_tag = NULL;
// Global buffer to cache physical pages.
static uint8_t *pmem_zero_page = NULL;

// This is the switch table for the character device.
// It registers callbacks for the device file.
// See: xnu/bsd/sys/conf.h
static struct cdevsw pmem_cdevsw = {
  reinterpret_cast<d_open_t *>(&nulldev),   // d_open
  reinterpret_cast<d_close_t *>(&nulldev),  // d_close
  pmem_read,                                // d_read
  eno_rdwrt,                                // d_write
  pmem_ioctl,                               // d_ioctl
  eno_stop,                                 // d_stop
  eno_reset,                                // d_reset
  0,                                        // d_ttys
  eno_select,                               // handler for select()
  eno_mmap,                                 // handler for mmap()
  eno_strat,                                // d_strategy
  eno_getc,                                 // putc()
  eno_putc,                                 // getc()
  D_TTY                                     // d_type
};

// Kernel directory table base
static uint64_t pmem_dtb;
// Absolute size of physical memory as reported by EFI.
static uint64_t pmem_physmem_size;
// Pointer to the start of the physical memory map.
static EfiMemoryRange *pmem_mmap;
// Size of an individual memory map segment descriptor.
static uint32_t pmem_mmap_desc_size;
// Number of entries in the memory map.
static uint32_t pmem_mmap_size;

// This function is called whenever a program in user space tries to read from
// the device file. It will dispatch the appropriate function for the file that
// is read by inspecting the given minor number.
//
// args:
//  dev: Device struct [minor(dev) returns minor number]
//  uio: Structure representing the I/O request
//  r:   This will always be UIO_READ, as we only register this function for
//       reads. Do not register for writes, your buffer will get overwritten.
//
// return: KERN_SUCCESS, always.
//
// This function will always succeed, in case of errors the uio is zero padded.
static kern_return_t pmem_read(dev_t dev, struct uio *uio, __unused int rw) {
  if (minor(dev) == pmem_dev_pmem_minor) {
    return pmem_read_memory(uio);
  } else {
    return EFAULT;
  }
}

// This function uses as many pmem_partial_read() calls as necessary,
// to copy uio->resid bytes of physical memory from the physical address, as
// specified in uio->offset to the buffer in the uio.
static kern_return_t pmem_read_memory(struct uio *uio) {
  size_t read_bytes = 0;

  while (uio_resid(uio) > 0) {
    uio_update(uio, 0);
    // Try to read as many times as necessary until the uio is full.
    read_bytes = pmem_partial_read(uio, uio_offset(uio),
                                   uio_offset(uio) + uio_curriovlen(uio));
    uio_update(uio, read_bytes);
  }
  return KERN_SUCCESS;
}

// Copy the requested amount to userspace if it doesn't cross page boundaries
// or memory mapped io. If it does, stop at the boundary. Will copy zeroes
// if the given physical address is not backed by physical memory.
//
// args: uio is the userspace io request object
// return: number of bytes copied successfully
//
static uint64_t pmem_partial_read(struct uio *uio, addr64_t start_addr,
                                  addr64_t end_addr) {
  // Separate page and offset
  uint64_t page_offset = start_addr & PAGE_MASK;
  addr64_t page = trunc_page_64(start_addr);
  // don't copy across page boundaries
  uint32_t chunk_len = (uint32_t)MIN(PAGE_SIZE - page_offset,
                                     end_addr - start_addr);
  // Prepare the page for IOKit
  IOMemoryDescriptor *page_desc = (
      IOMemoryDescriptor::withPhysicalAddress(page, PAGE_SIZE, kIODirectionIn));
  if (page_desc == NULL) {
    pmem_error("Can't read from %#016llx, address not in physical memory range",
               start_addr);
    // Skip this range as it is not even in the physical address space
    return chunk_len;
  } else {
    // Map the page containing address into kernel address space.
    IOMemoryMap *page_map = (
        page_desc->createMappingInTask(kernel_task, 0, kIODirectionIn, 0, 0));
    // Check if the mapping succeded.
    if (!page_map) {
      pmem_error("page %#016llx could not be mapped into the kernel, "
               "zero padding return buffer", page);
      // Zero pad this chunk, as it is not inside a valid page frame.
      uiomove64((addr64_t)pmem_zero_page + page_offset,
                (uint32_t)chunk_len, uio);
    } else {
      // Successfully mapped page, copy contents...
      uiomove64(page_map->getAddress() + page_offset, (uint32_t)chunk_len, uio);
      page_map->release();
    }
    page_desc->release();
  }
  return chunk_len;
}

// Handles ioctl's from userspace. See all defined ioctl codes in pmem_ioctls.h.
static kern_return_t pmem_ioctl(dev_t dev, u_long cmd, caddr_t data, int flag,
                                struct proc *p) {
  int error = 0;

  switch (cmd) {
    case PMEM_IOCTL_GET_MMAP_SIZE:
      pmem_log("Passing size of memory map to user space");
      // copyout() is handled by the kernel, as we get passed an integral value
      *(reinterpret_cast<int32_t *>(data)) = pmem_mmap_size;
      break;

    case PMEM_IOCTL_GET_MMAP_DESC_SIZE:
      pmem_log("Passing size of memory map descriptor to user space");
      // copyout() is handled by the kernel, as we get passed an integral value
      *(reinterpret_cast<int32_t *>(data)) = pmem_mmap_desc_size;
      break;

    case PMEM_IOCTL_GET_MMAP:
      // Boot arguments are obtained through the platform expert,
      // which in turn got them handed by the EFI.

      pmem_log("Copying memory map to user space");
      // in this case we get a pointer so we must use copyout()
      error = copyout(pmem_mmap, *(reinterpret_cast<uint64_t *>(data)),
                      pmem_mmap_size);
      if (error != 0) {
        pmem_error("Error %d, copyout failed for memory map", error);
        return EFAULT;
      }
      break;

    case PMEM_IOCTL_GET_DTB:
      *(reinterpret_cast<int64_t *>(data)) = pmem_dtb;
      break;

    default:
      pmem_error("Illegal ioctl %08lx", cmd);
      return EFAULT;
  }
  return KERN_SUCCESS;
}

// Converts a given kernel virtual address to an actual physical address.
// The page needs to be mapped into the kernel_map for this to work.
//
// args: addr is the kernel virtual address
// return: physical address if successful, otherwise 0
//
// This was adapted from xnu/osfmk/i386/phys.c to work from within the
// restricted symbol set available to a kext.
static addr64_t pmem_kernel_virt_to_phys(addr64_t addr) {
  addr64_t phys_addr;

  // pmap_find_phys returns a pfn so we have to shift it
  phys_addr = (pmap_find_phys(kernel_pmap, addr)) << PAGE_SHIFT;
  if (phys_addr != 0) {
    // Add the offset back in
    phys_addr |= (addr & PAGE_MASK);
  }
  return phys_addr;
}

// Determines if a given physical address is inside a valid page frame.
static boolean_t pmem_page_valid(addr64_t page) {
  // Make sure its inside the physical address range.
  if (page > (pmem_physmem_size - PAGE_SIZE)) {
    pmem_log("Warning, page %#016llx is not inside valid range", page);
    return FALSE;
  }
  return TRUE;
}

// Prints debug messages to the kernel log buffer (Read with dmesg).
// This function will only be active if pmem_debug_logging is set to TRUE.
//
// args: fmt must be a format string.
// ...: an arbitrary amount of arguments for the format string may follow.
static void pmem_log(const char *fmt, ...) {
  va_list argptr;

  if (pmem_debug_logging) {
    va_start(argptr, fmt);
    vprintf(fmt, argptr);
    printf("\n");
    va_end(argptr);
  }
}

// Prints errors to the kernel log buffer (read with dmesg).
//
// args: fmt musst be a format string.
// ...: an arbitrary amount of arguments for the format string may follow.
static void pmem_error(const char *fmt, ...) {
  va_list argptr;

  va_start(argptr, fmt);
  printf("Error: ");
  vprintf(fmt, argptr);
  printf("\n");
  va_end(argptr);
}

// Tries to free all resources and also passes through any errors
//
// args: the error arg will be overwritten with KERN_FAILURE in case of an error
//       or returned unmodified in case everything went well.
// return: the given error argument or KERN_FAILURE if anything went wrong
static int pmem_cleanup(int error) {
  if (pmem_zero_page) {
    OSFree(pmem_zero_page, PAGE_SIZE, pmem_tag);
  }
  if (pmem_tag) {
    OSMalloc_Tagfree(pmem_tag);
  }
  if (pmem_devpmemnode) {
    devfs_remove(pmem_devpmemnode);
  }
  if (pmem_devmajor != -1) {
    int devindex = 0;
    devindex = cdevsw_remove(pmem_devmajor, &pmem_cdevsw);
    if (devindex != pmem_devmajor) {
      pmem_error("Failed to remove cdevsw, cdevsw_remove() returned %d,"
                 "should be %d", devindex, pmem_devmajor);
      pmem_error("Kext will not be unloaded as an uio could result"
                 " in calling non-existent code");
      error = KERN_FAILURE;
    }
  }
  return error;
}

// Driver entry point. Initializes globals and registers driver node in /dev.
kern_return_t pmem_start(kmod_info_t * ki, void *d) {
  int error = 0;

  pmem_log("Loading /dev/%s driver", pmem_pmem_devname);
  // Memory allocations are tagged to prevent leaks
  pmem_tag = OSMalloc_Tagalloc(pmem_tagname, OSMT_DEFAULT);
  // Allocate one page for zero padding of illegal read requests
  pmem_zero_page = static_cast<uint8_t *>(OSMalloc(PAGE_SIZE, pmem_tag));
  if (pmem_zero_page == NULL) {
    pmem_error("Failed to allocate memory for page buffer");
    return pmem_cleanup(KERN_FAILURE);
  }
  bzero(pmem_zero_page, PAGE_SIZE);
  // Access the boot arguments through the platform export,
  // and parse the systems physical memory configuration.
  boot_args * ba = reinterpret_cast<boot_args *>(PE_state.bootArgs);
  pmem_physmem_size = ba->PhysicalMemorySize;
  pmem_mmap = reinterpret_cast<EfiMemoryRange *>(ba->MemoryMap +
                                                 pmem_kernel_voffset);
  pmem_mmap_desc_size = ba->MemoryMapDescriptorSize;
  pmem_mmap_size = ba->MemoryMapSize;
  pmem_log("Size of physical memory:%lld", pmem_physmem_size);
  pmem_log("Size of physical pages:%d (PAGE_SHIFT=%d, PAGE_MASK=%#016x)",
           PAGE_SIZE, PAGE_SHIFT, PAGE_MASK);
  pmem_log("Phys. Memory map at:%#016llx (size:%lld desc_size:%d)",
           pmem_mmap, pmem_mmap_size, pmem_mmap_desc_size);
  pmem_log("Number of segments in memory map: %d",
           pmem_mmap_size / pmem_mmap_desc_size);
  // Install switch table
  pmem_devmajor = cdevsw_add(-1, &pmem_cdevsw);
  if (pmem_devmajor == -1) {
    pmem_error("Failed to create character device");
    return pmem_cleanup(KERN_FAILURE);
  }
  // Create physical memory device file
  pmem_log("Adding node /dev/%s", pmem_pmem_devname);
  pmem_devpmemnode = devfs_make_node(makedev(pmem_devmajor,
                                             pmem_dev_pmem_minor),
                                     DEVFS_CHAR,
                                     UID_ROOT,
                                     GID_WHEEL,
                                     0660,
                                     pmem_pmem_devname);
  if (pmem_devpmemnode == NULL) {
    pmem_error("Failed to create /dev/%s node", pmem_pmem_devname);
    return pmem_cleanup(KERN_FAILURE);
  }
  pmem_log("obtaining kernel dtb pointer");
  __asm__ __volatile__("movq %%cr3, %0" :"=r"(pmem_dtb));
  // Only bits 51-12 (inclusive) in cr3 are part of the dtb pointer
  pmem_dtb &= ~PAGE_MASK;
  pmem_log("kernel dtb: %#016llx", pmem_dtb);
  pmem_log("pmem driver loaded, physical memory available in /dev/%s",
           pmem_pmem_devname);
  return error;
}

// Driver cleanup function, frees all memory and removes device nodes.
kern_return_t pmem_stop(kmod_info_t *ki, void *d) {
  pmem_log("Unloading /dev/%s driver", pmem_pmem_devname);
  return pmem_cleanup(KERN_SUCCESS);
}
