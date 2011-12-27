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
#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/types.h>

#include <linux/mm.h>
#include <linux/highmem.h>
#include <asm/mmzone.h>

static char pmem_devname[32] = "pmem";

/* Checks to make sure that the page is valid. For now just checks the
   resource list for "System RAM", which is a very naive approach.
*/
static int is_page_valid(loff_t paddr) {
  struct resource *p = &iomem_resource;

  /* We should really grab the resource lock here but it is not
     exported. The iomem_resource is the root of the resource tree. We
     only care about the top level of the tree here because we just
     need to avoid DMA regions.
  */
  for (p = p->child; p; p = p->sibling) {
    if(p->end > paddr && p->start < paddr) {
      if (!strcmp(p->name, "System RAM")) {
	return 1;
      };
      break;
    };
  };

  return 0;
};

/* Implement seeking behaviour. For whence=2 we need to figure out the
   size of RAM which is the end address of the last "System RAM"
   resource.
*/
static loff_t pmem_llseek(struct file *file, loff_t offset, int whence) {
  switch (whence) {
  case 0: {
    file->f_pos = offset;

    return file->f_pos;
  };

  case 1: {
    file->f_pos += offset;

    return file->f_pos;
  };

  case 2: {
    /* The size of memory is the end address of the last
       resource.
    */
    struct resource *p = &iomem_resource;
    struct resource *last_resource = NULL;
    for(p=p->child;p;p=p->sibling) {
      if (!strcmp(p->name, "System RAM")) {
	last_resource=p;
      };
    }
    
    /* This should not happen - something has to be marked as
       allocated.
    */
    if(!last_resource) {
      printk(KERN_WARNING "No valid resources found.");

      return -EINVAL;
    } else {
      file->f_pos = offset + last_resource->end;
      return file->f_pos;
    };
  };
    
  default:
    return -EINVAL;
  }
}

/* This function reads as much of the page as possible - it may return
   a short read. If the page is invalid (e.g. the page could not be
   mapped in or its not in a valid memory resource we null pad the
   buffer and log to syslog.   
*/
static ssize_t pmem_read_partial(struct file *file, char *buf, size_t count,
				 loff_t *poff) {
  void *vaddr;
  unsigned long page_offset = count % PAGE_SIZE;
  size_t to_read = min(PAGE_SIZE - page_offset, count);
  unsigned long pfn = (unsigned long)(*poff >> PAGE_SHIFT);
  struct page *page;

  /* Refuse to read from invalid pages. */
  if(!is_page_valid(*poff) || !pfn_valid(pfn)) goto error;

  /* Map the page in the the kernel AS and get the address for it. */
  page = pfn_to_page(pfn);
  vaddr = kmap(page);
  if (!vaddr) goto error;
  
  /* Copy the data into the user buffer. */
  if (copy_to_user(buf, vaddr + page_offset, to_read)) {
    goto unmap_error;
  }

  kunmap(page);
  /* Increment the file offset. */
  *poff += to_read;

  return to_read;

 unmap_error:
  kunmap(page);
 error:
  /* Error occured we zero pad the result. */
  memset(buf, 0, to_read);
  return to_read;
};

/* Read the buffer requested by copying as much as needed from each
   page. Invalid pages will be replaced with NULLs.
*/
static ssize_t pmem_read(struct file *file, char *buf, size_t count,
			 loff_t *poff) {
  size_t remaining = count;

  /* Just keep going until the full buffer is copied. Due to the null
     padding on error its impossible to fail here.
  */
  while(remaining > 0) {
    remaining -= pmem_read_partial(file, buf, remaining, poff);
  };

  return count;
}

/* Set up the module methods. */
static struct file_operations pmem_fops = {
	.owner = THIS_MODULE,
	.llseek = pmem_llseek,
	.read = pmem_read,
};

static struct miscdevice pmem_dev = {
	MISC_DYNAMIC_MINOR,
	pmem_devname,
	&pmem_fops
};


static int __init pmem_init(void)
{
  return misc_register(&pmem_dev);
}

static void __exit pmem_cleanup_module(void)
{
  misc_deregister(&pmem_dev);
}

module_init(pmem_init);
module_exit(pmem_cleanup_module);

MODULE_LICENSE("GPL");
