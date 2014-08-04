/*
 * pmem.c - physical memory driver
 * Copyright 2011: Michael Cohen, (scudette@gmail.com)
 *
 * *****************************************************************************
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 675 Mass
 * Ave, Cambridge, MA 02139, USA.
 *
 * *****************************************************************************
 *
 * This code is also available under Apache 2.0 License
 * Copyright 2011 Michael Cohen (scudette@gmail.com)
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *******************************************************************************
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/miscdevice.h>
#include <linux/init.h>
#include <asm/page.h>
#include <asm/smp.h>
#include <linux/io.h>
#include <asm/uaccess.h>
#include <asm/types.h>
#include <asm-generic/mman-common.h>
#include <linux/thread_info.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/kallsyms.h>
#include <linux/highmem.h>
#include <asm/mmzone.h>

#include "debug.h"
#include "pte_mmap_linux.h"

MODULE_LICENSE("GPL");

// These types are defined in OS specific headers, however to remain independent
// of them we define our own here:

#define PFN_TO_PAGE(pfn) (pfn << PAGE_SHIFT)
#define PAGE_TO_PFN(pfn) (pfn >> PAGE_SHIFT)

/* Empty page for zero padding. */
static unsigned char zero_page[PAGE_SIZE];
static loff_t physical_offset = 0;
/* pte_mmap implementation */
PTE_MMAP_OBJ *pte_mmap;
/* Driver ID for unregistering */
int major;

/* Implement seeking behaviour. For whence=2 we need to figure out the
   size of RAM which is the end address of the last "System RAM"
   resource.
*/
loff_t pmem_llseek(struct file *file, loff_t offset, int whence) {
  switch (whence) {
  case 0: {
    physical_offset = offset;
    break;
  };

  case 1: {
    physical_offset += offset;
    break;
  };

  case 2: {
    // There is no way we can know this without calling kernel api's
    return -EINVAL;
    break;
  };

  default:
    return -EINVAL;
  }

  return physical_offset;
}

/* This function reads as much of the page as possible - it may return
   a short read. If the page is invalid (e.g. the page could not be
   mapped in or its not in a valid memory resource we null pad the
   buffer and log to syslog.
*/
static ssize_t pmem_read_partial(struct file *file, char *buf, size_t count,
                                 loff_t *poff) {
  unsigned long page_offset = *poff % PAGE_SIZE;
  unsigned long page_physaddr = *poff & PAGE_MASK;
  size_t to_read = min(PAGE_SIZE - page_offset, count);
  /* disable preemption to make sure we stay on the cpu where the page is
   * remapped. If we don't do this we risk being preempted and scheduled on
   * another cpu with an invalid mapping, returning wrong data. */
  //pte_mmap->disable_interrupts_();
  /* Manually remap the rogue page to the target offset */
  if (pte_mmap->remap_page(pte_mmap, page_physaddr) !=
      PTE_SUCCESS) {
    DEBUG_LOG("Failed to remap rogue page to %#016lx", page_physaddr);
    goto invalid_page;
  }

  /* Copy the data into the user buffer. */
  if (_copy_to_user(
      buf, (void *)((pte_mmap->rogue_page.value + page_offset)),
                   to_read)) {
    DEBUG_LOG("Failed to copy page %#016llx to user space", *poff);
    goto error_copy;
  }

error_copy:
  /* Increment the file offset. */
  *poff += to_read;
  //pte_mmap->enable_interrupts_();
  return to_read;

invalid_page:
  DEBUG_LOG("%016llx is invalid, zero padding...", *poff);
  if (_copy_to_user(buf, (const void *)zero_page, to_read)) {
    DEBUG_LOG("Failed to copy zero page for adress %#016llx to user "
            "space.", *poff);
  }
  /* Increment the file offset. */
  *poff += to_read;
  //pte_mmap->enable_interrupts_();
  return to_read;
};

/* Read the buffer requested by copying as much as needed from each
   page. Invalid pages will be replaced with NULLs.
*/
ssize_t pmem_read(struct file *file, char *buf, size_t count,
                         loff_t *poff) {
  size_t to_read, remaining;
  to_read = count;
  remaining = to_read;
  /* Just keep going until the full buffer is copied. Due to the null
     padding on error its impossible to fail here.
  */
  while(remaining > 0) {
    remaining -= pmem_read_partial(file, buf + (to_read - remaining),
                                   remaining, &physical_offset);
  };
  return to_read;
}

struct file_operations pmem_fops = {
  .llseek = pmem_llseek,
  .read = pmem_read,
};

int __init pmem_init(void) {
  pte_mmap = pte_mmap_linux_new();
  if (pte_mmap == NULL) {
    DEBUG_LOG("Failed to initialize pte mmap, unloading module\n");
    return -EFAULT;
  }
  DEBUG_LOG("pmem driver initialized\n");
  major = register_chrdev(0, "pmem", &pmem_fops);
  if (major) {
    DEBUG_LOG("pmem major number is %d\n", major);
    return 0;
  } else {
    // We need a registered major number to communicate with user space
    return -1;
  }
}

void __exit pmem_cleanup(void) {
  pte_mmap_linux_delete(pte_mmap);
  DEBUG_LOG("pmem driver unloading\n");
  unregister_chrdev(major, "pmem");
}

