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

#include "meta.h"
#include "logging.h"
#include "MacPmem.h"
#include "iokit_pci.h"
#include "util.h"

#include <libkern/libkern.h>
#include <sys/uio.h>
#include <libkern/OSMalloc.h>
#include <pexpert/i386/boot.h>
#include <pexpert/pexpert.h>
#include <libkern/version.h>
#include <kern/task.h>
#include <libkern/OSAtomic.h>


static const char * const pmem_meta_fmt = \
"%%YAML 1.2\n"
"---\n"
"meta:\n"
"  pmem_api_version: %d\n"
"  cr3: %llu\n"
"  dtb_off: %llu\n"
"  phys_mem_size: %llu\n"
"  pci_config_space_base: %llu\n"
"  mmap_poffset: %u\n"
"  mmap_desc_version: %u\n"
"  mmap_size: %u\n"
"  mmap_desc_size: %u\n"
"  kaslr_slide: %u\n"
"  kernel_poffset: %u\n"
"  kernel_version: \"%.*s\"\n"
"records:\n"; // Range descriptions appended after this line.


static const char * const pmem_pci_range_fmt = \
"  - purpose: \"%s\"\n"
"    type: \"%s\"\n"
"    pci_type: \"%s\"\n"
"    start: %llu\n"
"    length: %llu\n"
"    hw_informant: %s\n";


static const char * const pmem_efi_range_fmt = \
"  - purpose: \"%s\"\n"
"    type: \"%s\"\n"
"    efi_type: \"%s\"\n"
"    start: %llu\n"
"    length: %llu\n"
"    hw_informant: %s\n";


// Used to cache /dev/pmem_info between reads.
// Generally rebuilt if a read starts from 0.
static lck_rw_t *pmem_cached_info_lock = nullptr;
static lck_attr_t *pmem_cached_info_lock_attr = nullptr;
static pmem_OSBuffer *pmem_cached_info = nullptr;

// Used for tracking when it's safe to dealloc pmem_cached_info.
static int pmem_info_open_count = 0;

// Used by sysctl for whatever purpose it wants.
static pmem_meta_t *pmem_sysctl_meta = nullptr;

#define BUFLEN_MAX 0x10000
#define BUFLEN_INIT 0x10
#define META_INITROOM 8


// Make a new meta struct.
static pmem_meta_t *pmem_metaalloc() {
    uint32_t required_size = (uint32_t)sizeof(pmem_meta_t);
    pmem_meta_t *meta = (pmem_meta_t *)OSMalloc(required_size, pmem_tag);
    if (!meta) {
        return nullptr;
    }

    bzero(meta, required_size);

    meta->pmem_api_version = PMEM_API_VERSION;
    meta->records_offset = __offsetof(pmem_meta_t, records);
    meta->size = required_size;

    return meta;
}


// Free a meta struct.
void pmem_metafree(pmem_meta_t *meta) {
    OSFree(meta, meta->size, pmem_tag);
}


// Resize 'meta' to have at least 'min_room' of bytes at the end. This will
// deallocate the old meta struct, so 'metaret' will change to point to the new
// buffer.
//
// Arguments:
// metaret: The meta struct to resize. Will change to point to new struct.
// min_room: The new struct will have at least this much room, but probably
//           more.
//
// Returns:
// KERN_SUCCESS or KERN_FAILURE. On KERN_FAILURE the old struct MAY still be
// valid; if so, the pointer will not be updated.
static kern_return_t pmem_metaresize(pmem_meta_t **metaret, uint32_t min_room) {
    pmem_meta_t *meta = *metaret;
    uint32_t min_size = meta->size + min_room;

    if (min_size < meta->size || meta->size > UINT32_MAX / 2) {
        pmem_error("32 bit int overflow detected - meta struct is too big.");
        return KERN_FAILURE;
    }

    if (min_size < meta->size * 2) {
        min_size = meta->size * 2;
    }

    pmem_meta_t *newmeta = (pmem_meta_t *)OSMalloc(min_size, pmem_tag);
    if (!newmeta) {
        return KERN_FAILURE;
    }

    pmem_debug(("Meta struct %p of size %u has been resized and is now %p "
                "of size %u"),
               meta, meta->size, newmeta, min_size);

    memcpy(newmeta, meta, meta->size);
    pmem_metafree(meta);
    newmeta->size = min_size;
    *metaret = newmeta;

    return KERN_SUCCESS;
}


// How many bytes can still be appended to meta?
static inline unsigned pmem_metaroom(pmem_meta_t *meta) {
    int room = ((meta->size - sizeof(pmem_meta_t)) - meta->records_end);

    if (room < 0) {
        // I'm aware that saying this should never happen is a great way to
        // ensure it will happen, so I'm just gonna say this would be
        // unexpected.

        // If we're here it's highly likely the kernel will panic soon.
        // Let's preempt that by blowing up sooner rather than later.
        panic((BUFFER OVERFLOW DETECTED: Meta %p is of size %u, of which %lu
               is the base struct, and it contains %d records of combined size
               of %u, meaning %u bytes have been written past allocated
               memory.),
              meta, meta->size, sizeof(pmem_meta_t), meta->record_count,
              meta->records_end, -room);

        return 0;
    }

    return room;
}


// Append 'record' to 'meta', resizing 'meta' as needed.
//
// Arguments:
// metaret: The meta struct to insert into. The pointer will change if meta
// needs to be resized; in that case, the old structure will be freed and any
// pointers to it will need to be updated.
// record: The metadata record struct to append.
//
// Returns: KERN_SUCCESS or KERN_FAILURE. On failure, the old struct MAY still
// be valid; if so, the pointer to it won't be updated.
static kern_return_t pmem_metainsert(pmem_meta_t **metaret,
                                     const pmem_meta_record_t *record) {
    pmem_meta_t *meta = *metaret;
    kern_return_t error;
    unsigned int room = pmem_metaroom(meta);

    if (record->size > room) {
        error = pmem_metaresize(&meta, record->size);
        if (error != KERN_SUCCESS) {
            pmem_error("pmem_metaresize failed.");
            return error;
        }
    }

    memcpy(meta->records + meta->records_end, record, record->size);
    meta->records_end += record->size;
    meta->record_count++;
    *metaret = meta;

    return KERN_SUCCESS;
}


// Appends a YAML version of the record to the buffer.
static kern_return_t pmem_append_record(pmem_OSBuffer *buffer,
                                        const pmem_meta_record_t *record) {
    size_t room = buffer->size - buffer->cursor;
    char *cursor;
    int fmt;

    while(1) {
        cursor = buffer->buffer + buffer->cursor;
        switch (record->type) {
            case pmem_efi_range_type:
                fmt = snprintf(cursor, room, pmem_efi_range_fmt,
                               record->purpose,
                               pmem_record_type_names[pmem_efi_range_type],
                               pmem_efi_type_names[record->efi_range.efi_type],
                               record->efi_range.start,
                               record->efi_range.length,
                               (record->efi_range.hw_informant ?
                                "true" : "false"));
                break;
            case pmem_pci_range_type:
                fmt = snprintf(cursor, room, pmem_pci_range_fmt,
                               record->purpose,
                               pmem_record_type_names[pmem_pci_range_type],
                               pmem_pci_type_names[record->pci_range.pci_type],
                               record->pci_range.start,
                               record->pci_range.length,
                               (record->pci_range.hw_informant ?
                                "true" : "false"));
            default:
                break;
        }

        if (fmt <= room) {
            break;
        }

        if (fmt + buffer->size > BUFLEN_MAX) {
            pmem_error("Buffer size %u + %u would be bigger than BUFLEN_MAX.",
                       buffer->size, fmt);
            return KERN_FAILURE;
        }

        pmem_resize(buffer, buffer->size * 2);
        room = buffer->size - buffer->cursor;
    };

    buffer->cursor += fmt;

    return KERN_SUCCESS;
}


// sysctl handler to copyout the meta struct.
static int pmem_sysctl_getmeta SYSCTL_HANDLER_ARGS {
    pmem_info("Passing meta by sysctl.");
    kern_return_t error;

    error = pmem_fillmeta(&pmem_sysctl_meta, PMEM_INFO_ALL);

    if (error != KERN_SUCCESS) {
        return error;
    }

    pmem_info("SYSCTL_OUT will get %u bytes.", pmem_sysctl_meta->size);
    SYSCTL_OUT(req, pmem_sysctl_meta, pmem_sysctl_meta->size);

    return error;
}


SYSCTL_PROC(_kern, OID_AUTO, pmem_info, CTLTYPE_STRUCT | CTLFLAG_RD,
            pmem_sysctl_meta, 0, &pmem_sysctl_getmeta, "S", "Pmem Info")


static pmem_signal_t pmem_fillmeta_pcihelper(IOPCIDevice *dev,
                                             IODeviceMemory *mem,
                                             unsigned mem_idx,
                                             void *ctx) {
    pmem_meta_t **meta = (pmem_meta_t **)ctx;
    pmem_meta_record_t record;
    kern_return_t error = KERN_SUCCESS;

    record.type = pmem_pci_range_type;
    record.size = sizeof(pmem_meta_record_t);
    record.pci_range.pci_type = pmem_PCIUnknownMemory;
    record.pci_range.hw_informant = 0;

    record.pci_range.start = mem->getPhysicalAddress();
    record.pci_range.length = mem->getLength();
    snprintf(record.purpose, PMEM_NAMESIZE, "(PCI) %s/%d",
             dev->getName(), mem_idx);
    error = pmem_metainsert(meta, &record);

    if (error != KERN_SUCCESS) {
        pmem_error("pmem_metainsert failed for some reason.");
        return pmem_Stop;
    }

    return pmem_Continue;
}


static kern_return_t pmem_get_physmap(pmem_meta_t **meta) {
    // The implicit assumption here is that the EFI physmap hasn't been
    // tampered with. A rootkit could potentially mess with the pointer in
    // bootArgs, or added fake descriptors to the map (although both of those
    // modifications would have to be reversed by the rootkit eventually,
    // because they'd probably break hibernation, among other things.
    // Ergo, Latin, the imager will have to compare the information learned
    // here to data from IOKit and other sources.
    boot_args *ba = (boot_args *)PE_state.bootArgs;
    vm_offset_t mmap_voffset;
    EFI_MEMORY_DESCRIPTOR *mmap;
    EFI_MEMORY_DESCRIPTOR *mmap_end;
    uint32_t mmap_desc_size = ba->MemoryMapDescriptorSize;

    pmem_meta_record_t record;
    kern_return_t error = KERN_SUCCESS;

    record.size = sizeof(pmem_meta_record_t);
    record.efi_range.hw_informant = 0;
    record.type = pmem_efi_range_type;

    // Check that we're looking at something we know how to parse.
    if (ba->MemoryMapDescriptorVersion != 1) {
        pmem_fatal("This version of MacPmem is from the past and only "
                   "knows about EFI memory descriptor version 1. Since you "
                   "are apparently running this in the distant future, "
                   "I am going to assume that you are a superintelligent "
                   "cybernetic organism and won't try to tell you what to "
                   "do about that.\n"
                   "In the event that you are a rogue AI attempting to use "
                   "this driver to further your mission of world domination, "
                   "please consider whether the set of all sets contains "
                   "itself.");
        return KERN_FAILURE;
    }
    if (mmap_desc_size != 48) {
        pmem_fatal("bootArgs reports an illegal descriptor size %u."
                   " Expected to be %d.",
                   mmap_desc_size,
                   48);
        return KERN_FAILURE;
    }

    pmem_debug("EFI physmap looks sane.");

    // See osfmk/i386/machine_routines.c for the reference implementation of
    // ml_static_ptovirt.
#if defined(__x86_64__)
    #define VM_MIN_KERNEL_ADDRESS		((vm_offset_t) 0xFFFFFF8000000000UL)
    mmap_voffset = \
    (vm_offset_t)(((unsigned long) ba->MemoryMap) | VM_MIN_KERNEL_ADDRESS);
#else
    #define LINEAR_KERNEL_ADDRESS	((vm_offset_t) 0x00000000)
    mmap_voffset = (vm_offset_t)((paddr) | LINEAR_KERNEL_ADDRESS);
#endif

    mmap = (EFI_MEMORY_DESCRIPTOR *)mmap_voffset;
    mmap_end = (EFI_MEMORY_DESCRIPTOR *)(mmap_voffset + ba->MemoryMapSize);

    while (mmap < mmap_end) {
        if (mmap->Type < EfiMaxMemoryType) {
            record.efi_range.efi_type = (EFI_MEMORY_TYPE)mmap->Type;
            snprintf(record.purpose, PMEM_NAMESIZE, "(EFI) %s",
                     pmem_efi_type_names[record.efi_range.efi_type]);

        } else {
            pmem_warn("mmap->Type @%p set to %u (max is %u).",
                      mmap, mmap->Type, EfiMaxMemoryType);
            record.efi_range.efi_type = EfiMaxMemoryType;
            snprintf(record.purpose, PMEM_NAMESIZE, "(EFI) Unknown:%u",
                     mmap->Type);
        }

        record.efi_range.start = mmap->PhysicalStart;
        record.efi_range.length = mmap->NumberOfPages * 0x1000;

        error = pmem_metainsert(meta, &record);
        if (error != KERN_SUCCESS) {
            pmem_error("pmem_metainsert failed while adding an EFI range.");
            break;
        }

        mmap_voffset += mmap_desc_size;
        mmap = (EFI_MEMORY_DESCRIPTOR *)mmap_voffset;
    }

    return error;
}


kern_return_t pmem_fillmeta(pmem_meta_t **metaret, int flags) {
    uint64_t cr3;
    pmem_meta_t *meta = pmem_metaalloc();
    boot_args *ba = (boot_args *)PE_state.bootArgs;
    kern_return_t error = KERN_SUCCESS;

    if (flags & PMEM_INFO_CR3) {
        __asm__ __volatile__("movq %%cr3, %0" :"=r"(cr3));
        meta->cr3 = cr3;
        meta->dtb_poffset = cr3 & ~PAGE_MASK;
    }

    if (flags & PMEM_INFO_BOOTARGS) {
        meta->mmap_desc_size = ba->MemoryMapDescriptorSize;
        meta->mmap_size = ba->MemoryMapSize;
        meta->mmap_desc_version = ba->MemoryMapDescriptorVersion;
        meta->kaslr_slide = ba->kslide;
        meta->phys_mem_size = ba->PhysicalMemorySize;
        meta->mmap_poffset = ba->MemoryMap;
        meta->kernel_poffset = ba->kaddr;
        meta->pci_config_space_base = ba->pciConfigSpaceBaseAddress;
    }

    if (flags & PMEM_INFO_KERNEL_VERSION) {
        strncpy(meta->kernel_version, version, PMEM_OSVERSIZE);
    }

    if (flags & PMEM_INFO_LIST_PCI) {
        // This will potentially change the meta pointer.
        error = pmem_iokit_enumerate_pci(&pmem_fillmeta_pcihelper, &meta);
        if (error != KERN_SUCCESS) {
            pmem_error("pmem_iokit_enumerate_pci failed");
            pmem_metafree(meta);
            return error;
        }
    }

    if (flags & PMEM_INFO_LIST_PHYSMAP) {
        error = pmem_get_physmap(&meta);
        if (error != KERN_SUCCESS) {
            pmem_error("pmem_get_physmap failed.");
            pmem_metafree(meta);
            return error;
        }
    }

    *metaret = meta;
    return KERN_SUCCESS;
}


static kern_return_t pmem_buftouio(pmem_OSBuffer *buffer,
                                   struct uio *uio) {
    user_ssize_t resid = uio_resid(uio);
    off_t offset = uio_offset(uio);
    size_t limit = strlen(buffer->buffer);
    size_t left = limit - offset;
    int amount;
    int rv;
    if (offset > limit) {
        return KERN_FAILURE;
    }

    while (resid > 0 && left > 0) {
        left = limit - offset;

        // The downcast is OK because the buffer cannot be larger than 32bit,
        // so neither can the result of the min expression.
        amount = (int)min(left, resid);
        rv = uiomove(buffer->buffer + offset, amount, uio);
        if (rv != 0) {
            pmem_error("uiomove returned %d", rv);
            return KERN_FAILURE;
        }
        offset += amount;
        left -= amount;
        resid = uio_resid(uio);
    }
    return KERN_SUCCESS;
}


// Escapes string in 'orig' so that it may be included in YAML output.
//
// Arguments:
// orig: The buffer to read a string from. Will be read to first \x00 character
//       or else for the entire buffer size.
// escaped: If successful, the function will write a pointer to the escaped
//          buffer here. Null-terminated if orig was.
//
// Returns:
// KERN_SUCCESS or KERN_FAILURE
static kern_return_t pmem_escape_yml_string(const pmem_OSBuffer *orig,
                                            pmem_OSBuffer **escaped) {
    size_t limit = strnlen(orig->buffer, orig->size);
    // If every character in the original string is escaped, we need at most
    // four times the original limit.
    size_t worst_case = limit * 4;

    if (limit > SSIZE_MAX / 4) {
        pmem_error(("String of size %lu cannot be safely escaped. Maximum "
                    "safe size is %u."),
                   limit, UINT32_MAX / 4);
        return KERN_FAILURE;
    }

    pmem_OSBuffer *buffer = pmem_alloc((uint32_t)worst_case, orig->tag);
    size_t in_off = 0, out_off = 0;
    const char *orig_str = orig->buffer;
    char c;

    // We just need to get rid of double quotes, backslashes and unprintable
    // characters. The former two are escaped; the latter shouldn't occur, but
    // if it does, will be replaced with question marks ('?').
    //
    // Terminates on first zero, or once it runs out of buffer.
    for (in_off = 0; in_off < limit; ++in_off) {
        c = orig_str[in_off];

        if (c == '\\') {
            buffer->buffer[out_off++] = c;
            buffer->buffer[out_off++] = c;
        } else if (c == '"') {
            buffer->buffer[out_off++] = '\\';
            buffer->buffer[out_off++] = c;
        } else if (c == '\n') {
            buffer->buffer[out_off++] = '\\';
            buffer->buffer[out_off++] = 'n';
        } else if (c == '\t') {
            buffer->buffer[out_off++] = '\\';
            buffer->buffer[out_off++] = 't';
        } else if (c == '\r') {
            buffer->buffer[out_off++] = '\\';
            buffer->buffer[out_off++] = 'r';
        } else if (c == 0) {
            buffer->buffer[out_off++] = c;
            break;
        } else if (c < 32) {
            buffer->buffer[out_off++] = '?';
        } else {
            buffer->buffer[out_off++] = c;
        }
    }

    *escaped = buffer;
    return KERN_SUCCESS;
}


kern_return_t pmem_formatmeta(pmem_OSBuffer *buffer, const pmem_meta_t *meta) {
    size_t fmt;
    kern_return_t error = KERN_FAILURE;

    // Escape the kernel version string.
    pmem_OSBuffer *kver_orig = nullptr;
    pmem_OSBuffer *kver_escaped = nullptr;
    error = pmem_make(meta->kernel_version, sizeof(meta->kernel_version),
                      buffer->tag, &kver_orig);
    if (error != KERN_SUCCESS || !kver_orig) {
        pmem_error("Failed to make a OSBuffer for kernel version. Got ptr %p",
                   kver_orig);
        goto bail;
    }

    error = pmem_escape_yml_string(kver_orig, &kver_escaped);
    if (error != KERN_SUCCESS || !kver_escaped) {
        pmem_error("Failed to escape kernel version. Returned buffer ptr %p.",
                   kver_escaped);
        goto bail;
    }

    while (1) {
        fmt = snprintf(buffer->buffer, buffer->size, pmem_meta_fmt,
                       meta->pmem_api_version,
                       meta->cr3,
                       meta->dtb_poffset,
                       meta->phys_mem_size,
                       meta->pci_config_space_base,
                       meta->mmap_poffset,
                       meta->mmap_desc_version,
                       meta->mmap_size,
                       meta->mmap_desc_size,
                       meta->kaslr_slide,
                       meta->kernel_poffset,
                       kver_escaped->size,
                       kver_escaped->buffer);

        if (fmt > BUFLEN_MAX) {
            pmem_error("YAML output would be larger than BUFLEN_MAX.");
            return KERN_FAILURE;
        }

        if (fmt <= buffer->size) {
            break;
        }

        pmem_resize(buffer, (uint32_t)fmt + 1);
    };

    error = KERN_SUCCESS;

bail:
    if (kver_orig) {
        pmem_free(kver_orig);
    }

    if (kver_escaped) {
        pmem_free(kver_escaped);
    }

    return error;
}


static kern_return_t pmem_buffermeta(pmem_OSBuffer *buffer,
                                     const pmem_meta_t *meta) {
    kern_return_t error = KERN_SUCCESS;
    pmem_meta_record_t *record;
    char *cursor = (char *)meta->records;
    char *limit = (char *)(meta->records + meta->records_end);

    // Initialize the length of the buffer to something reasonable.
    // If this is not the first time we're being called, the buffer may
    // actually already be larger. That's ok.
    pmem_resize(buffer, (uint32_t)strlen(pmem_meta_fmt));

    // This will format the 'header' of the struct.
    error = pmem_formatmeta(buffer, meta);
    if (error != KERN_SUCCESS) {
        return error;
    }

    // Append all the memory descriptors.
    buffer->cursor = strlen(buffer->buffer);
    pmem_debug("Meta has %u meta records, buffer cursor is at %llu/%u.",
               meta->record_count, buffer->cursor, buffer->size);

    for (unsigned i = 0; cursor < limit; ++i) {
        if (i > meta->record_count) {
            pmem_fatal(("Meta claims to only hold %u records, but at "
                        "offset %p of %p (%p + 0x%x), we are now copying "
                        "record no. %u."),
                       meta->record_count, cursor, limit, meta->records,
                       meta->records_end, i);
            return KERN_FAILURE;
        }

        record = (pmem_meta_record_t *)cursor;
        error = pmem_append_record(buffer, record);

        if (error != KERN_SUCCESS) {
            pmem_error("pmem_append_descriptor failed at %p/%p.",
                       record, limit);
            return error;
        }

        cursor += record->size;
    }

    return KERN_SUCCESS;
}


// Open/close handlers for /dev/pmem_info. They adjust the open count of the
// device to see when it's safe to rebuild the cached contents.
kern_return_t pmem_openmeta() {
    OSIncrementAtomic(&pmem_info_open_count);
    return KERN_SUCCESS;
}

kern_return_t pmem_closemeta() {
    if (OSDecrementAtomic(&pmem_info_open_count) == 0) {
        // The last open handle just closed. We can free the shared resource.
        // We still have to grab the exclusive lock, though, in case someone
        // opens /and/ reads from the device between the decrement and the
        // call to free.
        lck_rw_lock_exclusive(pmem_cached_info_lock);
        if (pmem_cached_info) {
            pmem_free(pmem_cached_info);
            pmem_cached_info = nullptr;
        }
        lck_rw_unlock_exclusive(pmem_cached_info_lock);
    }

    return KERN_SUCCESS;
}


// Read handler for the /dev/pmem_info. Caches YAML in pmem_cached_info.
kern_return_t pmem_readmeta(struct uio *uio) {
    kern_return_t error = KERN_FAILURE;
    pmem_meta_t *meta = nullptr;

    if (uio_offset(uio) < 0) {
        // Should probably not read from negative offsets. Now, granted - the
        // purpose of this driver is to enable userland to read arbitrary
        // kernel memory, but, dammit, you should do it through the defined
        // interface, not by buffer underflow.
        return KERN_FAILURE;
    }

    lck_rw_lock_shared(pmem_cached_info_lock);
    
    // (Re)build cache?
    if (uio_offset(uio) == 0 || pmem_cached_info == nullptr) {
        if (!lck_rw_lock_shared_to_exclusive(pmem_cached_info_lock)) {
            // If the lock upgrade fails we have to take an exclusive lock
            // which can't fail.
            lck_rw_lock_exclusive(pmem_cached_info_lock);
        }

        pmem_debug("Rebuilding pmem_cached_info.");

        if(pmem_cached_info) {
            pmem_free(pmem_cached_info);
            pmem_cached_info = pmem_alloc(BUFLEN_INIT, pmem_tag);
        }

        // Fill the meta struct.
        error = pmem_fillmeta(&meta, PMEM_INFO_ALL);
        if (error != KERN_SUCCESS) {
            pmem_error("pmem_fillmeta failed.");
            lck_rw_unlock_exclusive(pmem_cached_info_lock);
            return error;
        }

        // Cache the YAML output.
        error = pmem_buffermeta(pmem_cached_info, meta);
        if (error != KERN_SUCCESS) {
            pmem_error("pmem_buffermeta failed.");
            lck_rw_unlock_exclusive(pmem_cached_info_lock);
            return error;
        }

        lck_rw_lock_exclusive_to_shared(pmem_cached_info_lock);
    }

    // Use cached YAML to satisfy the uio request.
    error = pmem_buftouio(pmem_cached_info, uio);
    lck_rw_unlock_shared(pmem_cached_info_lock);
    return error;
}


int pmem_sysctl = 0; // Set to 1 if we need to unregister sysctl.


void pmem_meta_cleanup() {
    if (pmem_cached_info) {
        pmem_free(pmem_cached_info);
        pmem_cached_info = nullptr;
    }

    if (pmem_sysctl) {
        sysctl_unregister_oid(&sysctl__kern_pmem_info);
        pmem_sysctl = 0;
    }

    lck_rw_free(pmem_cached_info_lock, pmem_rwlock_grp);
    lck_attr_free(pmem_cached_info_lock_attr);
}


kern_return_t pmem_meta_init() {
    pmem_cached_info = pmem_alloc(BUFLEN_INIT, pmem_tag);
    sysctl_register_oid(&sysctl__kern_pmem_info);
    pmem_sysctl = 1;

    pmem_cached_info_lock_attr = lck_attr_alloc_init();

#ifdef DEBUG
    lck_attr_setdebug(pmem_cached_info_lock_attr);
#endif
    pmem_cached_info_lock = lck_rw_alloc_init(pmem_rwlock_grp,
                                              pmem_cached_info_lock_attr);

    return KERN_SUCCESS;
}
