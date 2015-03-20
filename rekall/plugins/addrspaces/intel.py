# Rekall Memory Forensics
#
# Copyright 2013 Google Inc. All Rights Reserved.

# Authors:
# {npetroni,awalters}@4tphi.net (Nick Petroni and AAron Walters)
# Jesse Kornblum
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

""" This is Jesse Kornblum's patch to clean up the standard AS's.
"""
import struct

from rekall import addrspace
from rekall import config
from rekall import utils

config.DeclareOption(
    "dtb", group="Autodetection Overrides",
    type="IntParser", help="The DTB physical address.")

PAGE_SHIFT = 12
PAGE_MASK = ~ 0xFFF


class TranslationLookasideBuffer(utils.FastStore):
    """An implementation of a TLB."""

    def Get(self, vaddr):
        result = super(TranslationLookasideBuffer, self).Get(
            vaddr >> PAGE_SHIFT)

        if result is not None:
            return result + (vaddr & 0xFFF)

    def Put(self, vaddr, paddr):
        if paddr is not None:
            paddr = paddr & PAGE_MASK

        super(TranslationLookasideBuffer, self).Put(
            vaddr >> PAGE_SHIFT, paddr)


class IA32PagedMemory(addrspace.PagedReader):
    """ Standard x86 32 bit non PAE address space.

    Provides an address space for IA32 paged memory, aka the x86
    architecture, without Physical Address Extensions (PAE). Allows
    callers to map virtual address to offsets in physical memory.

    Create a new IA32 address space without PAE to sit on top of
    the base address space and a Directory Table Base (CR3 value)
    of 'dtb'.

    Comments in this class mostly come from the Intel(R) 64 and IA-32
    Architectures Software Developer's Manual Volume 3A: System Programming
    Guide, Part 1, revision 031, pages 4-8 to 4-15. This book is available
    for free at http://www.intel.com/products/processor/manuals/index.htm.
    Similar information is also available from Advanced Micro Devices (AMD)
    at http://support.amd.com/us/Processor_TechDocs/24593.pdf.

    This is simplified from previous versions of rekall, by removing caching
    and automated DTB searching (which is now performed by specific plugins in
    an OS specific way).
    """
    order = 70

    def __init__(self, name=None, dtb=None, **kwargs):
        """Instantiate an Intel 32 bit Address space over the layered AS.

        Args:
          dtb: The dtb address.
        """
        super(IA32PagedMemory, self).__init__(**kwargs)

        # We must be stacked on someone else:
        if not self.base:
            raise TypeError("No base Address Space")

        # If the underlying address space already knows about the dtb we use it.
        # Allow the dtb to be specified in the session.
        self.dtb = dtb or self.session.GetParameter("dtb")

        if not self.dtb != None:
            raise TypeError("No valid DTB specified. Try the find_dtb"
                            " plugin to search for the dtb.")
        self.name = (name or 'Kernel AS') + "@%#x" % self.dtb

        # Use a TLB to make this faster.
        self._tlb = TranslationLookasideBuffer(1000)

        # Our get_available_addresses() refers to the base address space we
        # overlay on.
        self.phys_base = self.base

        self._cache = utils.FastStore(100)

    def pde_entry_present(self, entry):
        '''
        Returns whether or not the 'P' (Present) flag is on
        in the given entry
        '''
        return entry & 1

    def pte_entry_present(self, entry):
        '''
        Returns whether or not the 'P' (Present) flag is on
        in the given entry
        '''
        return entry & 1

    def page_access_flag(self, entry):
        '''
        Returns the user/supervisor bit of the entry.
        '''
        return entry & (1 << 2)

    def page_size_flag(self, entry):
        '''
        Returns whether or not the 'PS' (Page Size) flag is on
        in the given entry
        '''
        return entry & (1 << 7)

    def pde_index(self, vaddr):
        '''
        Returns the Page Directory Entry Index number from the given
        virtual address. The index number is in bits 31:22.
        '''
        return vaddr >> 22

    def get_pde(self, vaddr):
        '''
        Return the Page Directory Entry for the given virtual address.

        Bits 31:12 are from CR3
        Bits 11:2 are bits 31:22 of the linear address
        Bits 1:0 are 0.
        '''
        pde_addr = (self.dtb & 0xfffff000) | ((vaddr & 0xffc00000) >> 20)
        return self.read_long_phys(pde_addr)

    def pte_paddr(self, pte):
        '''
        Return the physical address for the given PTE.
        This should return:
           (pte >> pfn_shift) << page_shift
        '''
        return pte

    def get_pte(self, vaddr, pde_value):
        '''
        Return the Page Table Entry for the given virtual address and
        Page Directory Entry.

        Bits 31:12 are from the PDE
        Bits 11:2 are bits 21:12 of the linear address
        Bits 1:0 are 0
        '''
        pte_addr = (pde_value & 0xfffff000) | ((vaddr & 0x3ff000) >> 10)
        return self.read_long_phys(pte_addr)

    def get_phys_addr(self, vaddr, pte_value):
        '''
        Return the offset in a 4KB memory page from the given virtual
        address and Page Table Entry.

        Bits 31:12 are from the PTE
        Bits 11:0 are from the original linear address
        '''
        if not self.pte_entry_present(pte_value):
            return None

        return (self.pte_paddr(pte_value) & 0xfffff000) | (vaddr & 0xfff)

    def get_four_meg_paddr(self, vaddr, pde_value):
        '''
        Bits 31:22 are bits 31:22 of the PDE
        Bits 21:0 are from the original linear address
        '''
        return (pde_value & 0xffc00000) | (vaddr & 0x3fffff)

    def vaddr_access(self, vaddr):
        """Is the access bit set on the page for the vaddr?"""
        pde_value = self.get_pde(vaddr)
        if not self.pde_entry_present(pde_value):
            return None

        pte_value = self.get_pte(vaddr, pde_value)
        if not self.pte_entry_present(pte_value):
            return None

        return (self.page_access_flag(pte_value) and
                self.page_access_flag(pde_value))

    def vtop(self, vaddr):
        '''
        Translates virtual addresses into physical offsets.
        The function should return either None (no valid mapping)
        or the offset in physical memory where the address maps.
        '''
        try:
            return self._tlb.Get(vaddr)
        except KeyError:
            pde_value = self.get_pde(vaddr)
            if not self.pde_entry_present(pde_value):
                return None

            if self.page_size_flag(pde_value):
                return self.get_four_meg_paddr(vaddr, pde_value)

            pte_value = self.get_pte(vaddr, pde_value)
            if not self.pte_entry_present(pte_value):
                return None
            res = self.get_phys_addr(vaddr, pte_value)

            self._tlb.Put(vaddr, res)
            return res

    def read_long_phys(self, addr):
        '''
        Returns an unsigned 32-bit integer from the address addr in
        physical memory. If unable to read from that location, returns None.
        '''
        string = self.base.read(addr, 4)
        return struct.unpack('<I', string)[0]

    def get_available_addresses(self, start=0):
        """Enumerate all valid memory ranges.

        Yields:
          tuples of (starting virtual address, size) for valid the memory
          ranges.
        """
        # Pages that hold PDEs and PTEs are 0x1000 bytes each.
        # Each PDE and PTE is four bytes. Thus there are 0x1000 / 4 = 0x400
        # PDEs and PTEs we must test
        for pde in range(0, 0x400):
            vaddr = pde << 22
            next_vaddr = (pde + 1) << 22
            if start > next_vaddr:
                continue

            pde_value = self.get_pde(vaddr)
            if not self.pde_entry_present(pde_value):
                continue

            if self.page_size_flag(pde_value):
                yield (vaddr,
                       self.get_four_meg_paddr(vaddr, pde_value),
                       0x400000)
                continue

            # This reads the entire PTE table at once - On
            # windows where IO is extremely expensive, its
            # about 10 times more efficient than reading it
            # one value at the time - and this loop is HOT!
            pte_table_addr = ((pde_value & 0xfffff000) |
                              ((vaddr & 0x3ff000) >> 10))

            data = self.base.read(pte_table_addr, 4 * 0x400)
            pte_table = struct.unpack("<" + "I" * 0x400, data)

            tmp1 = vaddr
            for i, pte_value in enumerate(pte_table):
                vaddr = tmp1 | i << 12
                next_vaddr = tmp1 | ((i + 1) << 12)

                if start > next_vaddr:
                    continue

                if self.pte_entry_present(pte_value):
                    yield (vaddr,
                           self.get_phys_addr(vaddr, pte_value),
                           0x1000)

    def __str__(self):
        return "%s@0x%08X (%s)" % (self.__class__.__name__, self.dtb, self.name)

    def __eq__(self, other):
        return (super(IA32PagedMemory, self).__eq__(other) and
                self.dtb == other.dtb and self.base == other.base)

    def end(self):
        return (2 ** 32) - 1


class IA32PagedMemoryPae(IA32PagedMemory):
    """ Standard x86 32 bit PAE address space.

    Provides an address space for IA32 paged memory, aka the x86
    architecture, with Physical Address Extensions (PAE) enabled. Allows
    callers to map virtual address to offsets in physical memory.

    Comments in this class mostly come from the Intel(R) 64 and IA-32
    Architectures Software Developer's Manual Volume 3A: System Programming
    Guide, Part 1, revision 031, pages 4-15 to 4-23. This book is available
    for free at http://www.intel.com/products/processor/manuals/index.htm.
    Similar information is also available from Advanced Micro Devices (AMD)
    at http://support.amd.com/us/Processor_TechDocs/24593.pdf.
    """
    order = 80

    def pdpte_entry_present(self, entry):
        '''
        Returns whether or not the 'P' (Present) flag is on
        in the given entry
        '''
        return entry & 1

    def pdpte_index(self, vaddr):
        '''
        Compute the Page Directory Pointer Table index using the
        virtual address.

        The index comes from bits 31:30 of the original linear address.
        '''
        return vaddr >> 30

    def get_pdpte(self, vaddr):
        '''
        Return the Page Directory Pointer Table Entry for the given
        virtual address.

        Bits 31:5 come from CR3
        Bits 4:3 come from bits 31:30 of the original linear address
        Bits 2:0 are all 0
        '''
        pdpte_addr = (self.dtb & 0xffffffe0) | ((vaddr & 0xc0000000) >> 27)
        return self.read_long_long_phys(pdpte_addr)

    def get_pde(self, vaddr, pdpte):
        '''
        Return the Page Directory Entry for the given virtual address
        and Page Directory Pointer Table Entry.

        Bits 51:12 are from the PDPTE
        Bits 11:3 are bits 29:21 of the linear address
        Bits 2:0 are 0
        '''
        pde_addr = (pdpte & 0xffffffffff000) | ((vaddr & 0x3fe00000) >> 18)
        return self.read_long_long_phys(pde_addr)

    def get_two_meg_paddr(self, vaddr, pde):
        '''
        Return the offset in a 2MB memory page from the given virtual
        address and Page Directory Entry.

        Bits 51:21 are from the PDE
        Bits 20:0 are from the original linear address
        '''
        return (pde & 0xfffffffe00000) | (vaddr & 0x1fffff)

    def get_pte(self, vaddr, pde):
        '''
        Return the Page Table Entry for the given virtual address
        and Page Directory Entry.

        Bits 51:12 are from the PDE
        Bits 11:3 are bits 20:12 of the original linear address
        Bits 2:0 are 0
        '''
        pte_addr = (pde & 0xffffffffff000) | ((vaddr & 0x1ff000) >> 9)
        return self.read_long_long_phys(pte_addr)

    def get_phys_addr(self, vaddr, pte):
        '''
        Return the offset in a 4KB memory page from the given virtual
        address and Page Table Entry.

        Bits 51:12 are from the PTE
        Bits 11:0 are from the original linear address
        '''
        if not self.pte_entry_present(pte):
            return None

        return (pte & 0xffffffffff000) | (vaddr & 0xfff)

    def vtop(self, vaddr):
        '''
        Translates virtual addresses into physical offsets.
        The function returns either None (no valid mapping)
        or the offset in physical memory where the address maps.
        '''
        try:
            return self._tlb.Get(vaddr)
        except KeyError:
            pdpte = self.get_pdpte(vaddr)
            if not self.pdpte_entry_present(pdpte):
                # Add support for paged out PDPTE
                # Insert buffalo here!
                return None

            pde = self.get_pde(vaddr, pdpte)
            if not self.pde_entry_present(pde):
                # Add support for paged out PDE
                return None

            if self.page_size_flag(pde):
                return self.get_two_meg_paddr(vaddr, pde)

            pte = self.get_pte(vaddr, pde)

            res = self.get_phys_addr(vaddr, pte)

            self._tlb.Put(vaddr, res)
            return res

    def read_long_long_phys(self, addr):
        '''
        Returns an unsigned 64-bit integer from the address addr in
        physical memory. If unable to read from that location, returns None.
        '''
        try:
            return self._cache.Get(addr)
        except KeyError:
            string = self.base.read(addr, 8)
            result = struct.unpack('<Q', string)[0]
            self._cache.Put(addr, result)

            return result

    def get_available_addresses(self, start=0):
        """A generator of address, length tuple for all valid memory regions."""
        # Pages that hold PDEs and PTEs are 0x1000 bytes each.
        # Each PDE and PTE is eight bytes. Thus there are 0x1000 / 8 = 0x200
        # PDEs and PTEs we must test.
        for pdpte in range(0, 4):
            vaddr = pdpte << 30
            next_vaddr = (pdpte + 1) << 30
            if start >= next_vaddr:
                continue

            pdpte_value = self.get_pdpte(vaddr)
            if not self.pdpte_entry_present(pdpte_value):
                continue

            tmp1 = vaddr
            for pde in range(0, 0x200):
                vaddr = tmp1 | (pde << 21)
                next_vaddr = tmp1 | ((pde + 1) << 21)
                if start >= next_vaddr:
                    continue

                pde_value = self.get_pde(vaddr, pdpte_value)
                if not self.pde_entry_present(pde_value):
                    continue

                if self.page_size_flag(pde_value):
                    yield (vaddr,
                           self.get_two_meg_paddr(vaddr, pde_value),
                           0x200000)
                    continue

                # This reads the entire PTE table at once - On
                # windows where IO is extremely expensive, its
                # about 10 times more efficient than reading it
                # one value at the time - and this loop is HOT!
                pte_table_addr = ((pde_value & 0xffffffffff000) |
                                  ((vaddr & 0x1ff000) >> 9))

                data = self.base.read(pte_table_addr, 8 * 0x200)
                pte_table = struct.unpack("<" + "Q" * 0x200, data)

                tmp2 = vaddr
                for i, pte_value in enumerate(pte_table):
                    if self.pte_entry_present(pte_value):
                        vaddr = tmp2 | i << 12
                        next_vaddr = tmp2 | (i + 1) << 12
                        if start >= next_vaddr:
                            continue

                        yield (vaddr,
                               self.get_phys_addr(vaddr, pte_value),
                               0x1000)
