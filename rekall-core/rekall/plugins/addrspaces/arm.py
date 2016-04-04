# Rekall Memory Forensics
#
# Copyright 2015 Google Inc. All Rights Reserved.

# Authors:
# Michael Cohen <scudette@google.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

"""An address space to read ARM memory images.

References:

ARM1176JZ-S Technical Reference Manual
Revision: r0p7
http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0333h/ch06s11s01.html
http://infocenter.arm.com/help/topic/com.arm.doc.ddi0333h/DDI0333H_arm1176jzs_r0p7_trm.pdf

ARM926EJ-S Revision: r0p5 Technical Reference Manual
Chapter 3.2 Address translation
http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0198e/Babjcchb.html
http://infocenter.arm.com/help/topic/com.arm.doc.ddi0198e/DDI0198E_arm926ejs_r0p5_trm.pdf
"""

import struct

from rekall import addrspace
from rekall.plugins.addrspaces import intel


class ArmPagedMemory(addrspace.PagedReader):
    """An address space to read virtual memory on ARM systems.

    The ARM manual refers to the "Translation Table Base Register" (TTBR) as the
    equivalent of the Intel CR3 register. We just refer to it as the DTB
    (Directory Table Base) to be consistent with the other Rekall address
    spaces.

    This implementation is guided by Figure 6.6 of ARM1176JZ-S Technical
    Reference Manual, Revision: r0p7.
    http://infocenter.arm.com/help/topic/com.arm.doc.ddi0333h/DDI0333H_arm1176jzs_r0p7_trm.pdf
    """
    # The following are some masks we will need and pre-calculate.

    # First 19 bits are the section index.
    section_index_mask = (1 << 20) - 1
    section_base_address_mask = ~section_index_mask

    # Supersections.
    # If bit 18 in the first_level_descriptor is set this is a supersection.
    super_section_mask = 1 << 18

    # bits 24-31 are the super_section base address.
    super_section_index_mask = (2 << 24) - 1
    super_section_base_address_mask = ~super_section_index_mask

    # bits 20-31 are the table_index.
    table_index_mask = ~section_index_mask

    # Bits 12 to 20 are the l2 table index.
    l2_table_index_mask = ((1 << 20) -1) ^ ((1 << 12) - 1)

    # Bits 10 - 31 are the coarse_page_table_base_address.
    coarse_page_table_base_address_mask = ~((1 << 10) - 1)

    # Bits 12 are the fine page table base address.
    fine_page_table_base_address_mask = ~((1 << 12) - 1)
    fine_l2_table_index_mask = ((1 << 20) -1) ^ ((1 << 10) - 1)

    # Fine page tables contain 1024 entries splitting the physical memory into
    # 1kb blocks.
    fine_page_table_index_mask = ((1 << 2) - 1) << 10

    # bits 0 - 15 are the page index.
    large_page_index_mask = (1 << 16) - 1
    large_page_base_address_mask = ~large_page_index_mask

    # bits 0-12 are page indexes for small pages.
    small_page_index_mask = (1 << 12) - 1
    small_page_base_address_mask = ~small_page_index_mask

    # bit 0-10 are pages indexes for tiny pages.
    tiny_page_index_mask = (1 << 10) - 1
    tiny_page_base_address_mask = ~tiny_page_index_mask

    def __init__(self, name=None, dtb=None, **kwargs):
        super(ArmPagedMemory, self).__init__(**kwargs)

        if not self.base:
            raise TypeError("No base Address Space")

        # If the underlying address space already knows about the dtb we use it.
        self.dtb = dtb or self.session.GetParameter("dtb")

        if not self.dtb != None:
            raise TypeError("No valid DTB specified. Try the find_dtb"
                            " plugin to search for the dtb.")
        self.name = (name or 'Kernel AS') + "@%#x" % self.dtb

        # Clear the bottom 14 bits from the TTBR.
        self.dtb &= ~ ((1 << 14) - 1)

    def read_long_phys(self, addr):
        """Read an unsigned 32-bit integer from physical memory.

        Note this always succeeds - reads outside mapped addresses in the image
        will simply return 0.
        """
        string = self.base.read(addr, 4)
        return struct.unpack("<I", string)[0]

    def vtop(self, vaddr):
        """Translates virtual addresses into physical offsets.

        The function should return either None (no valid mapping)
        or the offset in physical memory where the address maps.

        This function is simply a wrapper around describe_vtop() which does all
        the hard work. You probably never need to override it.
        """
        vaddr = int(vaddr)

        collection = self.describe_vtop(
            vaddr, intel.PhysicalAddressDescriptorCollector(self.session))

        return collection.physical_address

    def describe_vtop(self, vaddr, collection=None):
        if collection is None:
            collection = intel.DescriptorCollection(self.session)

        l1_descriptor_addr = (self.dtb | (
            (vaddr & self.table_index_mask) >> 18))
        l1_descriptor = self.read_long_phys(l1_descriptor_addr)
        collection.add(intel.AddressTranslationDescriptor,
                       object_name="l1 descriptor",
                       object_value=l1_descriptor,
                       object_address=l1_descriptor_addr)

        l1_descriptor_type = l1_descriptor & 0b11
        if l1_descriptor_type == 0b00:
            collection.add(intel.InvalidAddress, "Invalid L1 descriptor")
            return collection

        # l1_descriptor is a Section descriptor. See Figure 3.8.
        if l1_descriptor_type == 0b10:

            # Super section. Figure 6.6.
            # http://infocenter.arm.com/help/topic/com.arm.doc.ddi0333h/DDI0333H_arm1176jzs_r0p7_trm.pdf
            if l1_descriptor & self.super_section_mask:
                collection.add(
                    intel.CommentDescriptor,
                    "Super section base @ {0:#x}\n",
                    l1_descriptor & self.super_section_base_address_mask)

                collection.add(
                    intel.PhysicalAddressDescriptor,
                    address=(l1_descriptor &
                             self.super_section_base_address_mask) | (
                                 vaddr & self.super_section_index_mask))
            else:
                # Regular section descriptor.
                collection.add(intel.CommentDescriptor,
                               "Section base @ {0:#x}\n",
                               l1_descriptor & self.section_base_address_mask)

                collection.add(
                    intel.PhysicalAddressDescriptor,
                    address=(l1_descriptor &
                             self.section_base_address_mask) | (
                                 vaddr & self.section_index_mask))

        # l1_descriptor is a coarse page table descriptor. Figure 3.10.
        elif l1_descriptor_type == 0b01:
            collection.add(
                intel.CommentDescriptor, "Coarse table base @ {0:#x}\n",
                address=(l1_descriptor &
                         self.coarse_page_table_base_address_mask))

            l2_addr = (
                (l1_descriptor &
                 self.coarse_page_table_base_address_mask) |
                ((vaddr & self.l2_table_index_mask) >> 10))

            l2_descriptor = self.read_long_phys(l2_addr)

            collection.add(intel.AddressTranslationDescriptor,
                           object_name="2l descriptor",
                           object_value=l2_descriptor,
                           object_address=l2_addr)

            self._desc_l2_descriptor(collection, l2_descriptor, vaddr)

        # Fine page table descriptor. Section 3.2.6.
        elif l1_descriptor_type == 0b11:
            collection.add(
                intel.CommentDescriptor, "Fine table base @ {0:#x}\n",
                address=(l1_descriptor &
                         self.fine_page_table_base_address_mask))

            l2_addr = (
                (l1_descriptor &
                 self.fine_page_table_base_address_mask) |
                ((vaddr & self.fine_l2_table_index_mask) >> 12))

            l2_descriptor = self.read_long_phys(l2_addr)

            collection.add(intel.AddressTranslationDescriptor,
                           object_name="2l descriptor",
                           object_value=l2_descriptor,
                           object_address=l2_addr)

            self._desc_l2_descriptor(collection, l2_descriptor, vaddr)

        return collection

    def _desc_l2_descriptor(self, collection, l2_descriptor, vaddr):
        l2_descriptor_type = l2_descriptor & 0b11

        # Large page table.
        if l2_descriptor_type == 0b01:
            collection.add(
                intel.CommentDescriptor, "Coarse table base @ {0:#x}\n",
                l2_descriptor & self.large_page_base_address_mask)

            collection.add(
                intel.PhysicalAddressDescriptor,
                address=(l2_descriptor &
                         self.large_page_base_address_mask) | (
                             vaddr & self.large_page_index_mask))

        # Small page translation. Figure 3-11.
        elif l2_descriptor_type == 0b10 or l2_descriptor_type == 0b11:
            collection.add(
                intel.CommentDescriptor, "Coarse table base @ {0:#x}\n",
                l2_descriptor & self.small_page_base_address_mask)

            collection.add(
                intel.PhysicalAddressDescriptor,
                address=(l2_descriptor &
                         self.small_page_base_address_mask) | (
                             vaddr & self.small_page_index_mask))

        # Tiny pages. Figure 3-12.
        elif l2_descriptor_type == 0b11:
            collection.add(
                intel.CommentDescriptor, "Coarse table base @ {0:#x}\n",
                l2_descriptor & self.tiny_page_base_address_mask)

            collection.add(
                intel.PhysicalAddressDescriptor,
                address=(l2_descriptor &
                         self.tiny_page_base_address_mask) | (
                             vaddr & self.tiny_page_index_mask))

        elif l2_descriptor_type == 0b00:
            collection.add(intel.InvalidAddress, "Invalid L2 descriptor")


    def page_fault_handler(self, descriptor, vaddr):
        """A placeholder for handling page faults."""
        _ = descriptor, vaddr
        return None

    def get_mappings(self, start=0, end=2**64):
        """Generate all valid addresses.

        Note that ARM requires page table entries for large sections to be
        duplicated (e.g. a supersection first_level_descriptor must be
        duplicated 16 times). We don't actually check for this here.
        """
        vaddr = 0
        while vaddr < end:
            l1_descriptor = self.read_long_phys(self.dtb | (
                (vaddr & self.table_index_mask) >> 18))

            l1_descriptor_type = l1_descriptor & 0b11

            # Page is invalid, skip the entire range.
            if l1_descriptor_type == 0b00:
                vaddr += 1 << 20
                continue

            if l1_descriptor_type == 0b10:
                # A valid super section is 16mb (1<<24) large.
                if l1_descriptor & self.super_section_mask:
                    yield addrspace.Run(
                        start=vaddr,
                        end=vaddr + (1 << 24),
                        file_offset=(l1_descriptor &
                                     self.super_section_base_address_mask),
                        address_space=self.base)

                    vaddr += 1 << 24
                    continue

                # Regular sections is 1mb large.
                yield addrspace.Run(
                    start=vaddr,
                    end=vaddr + (1 << 20),
                    file_offset=l1_descriptor & self.section_base_address_mask,
                    address_space=self.base)
                vaddr += 1 << 20
                continue

            # Coarse page table contains a secondary fetch summing up to 1Mb.
            if l1_descriptor_type == 0b01:
                for x in self._generate_coarse_page_table_addresses(
                        vaddr, l1_descriptor &
                        self.coarse_page_table_base_address_mask):
                    yield x

                vaddr += 1 << 20
                continue

            raise RuntimeError("Unreachable")

    def _generate_coarse_page_table_addresses(self, base_vaddr,
                                              coarse_page_base):
        vaddr = base_vaddr
        while vaddr < base_vaddr + (1 << 20):
            l2_addr = (coarse_page_base |
                       (vaddr & self.l2_table_index_mask) >> 10)

            l2_descriptor = self.read_long_phys(l2_addr)
            l2_descriptor_type = l2_descriptor & 0b11

            # 64kb Large (coarse) page table.
            if l2_descriptor_type == 0b01:
                yield addrspace.Run(
                    start=vaddr,
                    end=vaddr + (1 << 16),
                    file_offset=(l2_descriptor &
                                 self.large_page_base_address_mask),
                    address_space=self.base)
                vaddr += 1 << 16
                continue

            # 4kb small page.
            if l2_descriptor_type == 0b10 or l2_descriptor_type == 0b11:
                yield addrspace.Run(
                    start=vaddr,
                    end=vaddr + (1 << 12),
                    file_offset=(l2_descriptor &
                                 self.small_page_base_address_mask),
                    address_space=self.base)
                vaddr += 1 << 12
                continue

            # Invalid page.
            if l2_descriptor_type == 0b00:
                vaddr += 1 << 10
                continue

            raise RuntimeError("Unreachable")


    def end(self):
        return (2 ** 32) - 1
