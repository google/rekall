# Rekall Memory Forensics
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Authors:
# Mike Auty
# Michael Cohen
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

""" This is based on Jesse Kornblum's patch to clean up the standard AS's.
"""
import struct

from rekall import config
from rekall.plugins.addrspaces import intel


config.DeclareOption(name="ept", group="Virtualization support",
                     action=config.IntParser,
                     help="The EPT physical address.")


class AMD64PagedMemory(intel.IA32PagedMemoryPae):
    """Standard AMD 64-bit address space.

    Provides an address space for AMD64 paged memory, aka the x86_64
    architecture, which is laid out similarly to Physical Address
    Extensions (PAE). Allows callers to map virtual address to
    offsets in physical memory.

    Create a new AMD64 address space to sit on top of the base address
    space and a Directory Table Base (CR3 value) of 'dtb'.

    Comments in this class mostly come from the Intel(R) 64 and IA-32
    Architectures Software Developer's Manual Volume 3A: System Programming
    Guide, Part 1, revision 031, pages 4-8 to 4-15. This book is available
    for free at http://www.intel.com/products/processor/manuals/index.htm.
    Similar information is also available from Advanced Micro Devices (AMD)
    at http://support.amd.com/us/Processor_TechDocs/24593.pdf.
    """
    order = 60

    _md_arch = "AMD64"


    def pml4e_index(self, vaddr):
        '''
        Returns the Page Map Level 4 Entry Index number from the given
        virtual address. The index number is in bits 47:39.
        '''
        return (vaddr & 0xff8000000000) >> 39

    def get_pml4e(self, vaddr):
        '''
        Return the Page Map Level 4 Entry for the given virtual address.
        If caching

        Bits 51:12 are from CR3
        Bits 11:3 are bits 47:39 of the linear address
        Bits 2:0 are 0.
        '''
        pml4e_addr = (
            self.dtb & 0xffffffffff000) | ((vaddr & 0xff8000000000) >> 36)
        return self._read_long_long_phys(pml4e_addr)

    def get_pdpte(self, vaddr, pml4e):
        '''
        Return the Page Directory Pointer Table Entry for the virtual address.

        Bits 51:12 are from the PML4E
        Bits 11:3 are bits 38:30 of the linear address
        Bits 2:0 are all 0
        '''
        pdpte_addr = (pml4e & 0xffffffffff000) | ((vaddr & 0x7FC0000000) >> 27)
        return self._read_long_long_phys(pdpte_addr)

    def get_one_gig_paddr(self, vaddr, pdpte):
        '''
        Return the offset in a 1GB memory page from the given virtual
        address and Page Directory Pointer Table Entry.

        Bits 51:30 are from the PDE
        Bits 29:0 are from the original linear address
        '''
        return (pdpte & 0xfffffc0000000) | (vaddr & 0x3fffffff)

    def vtop(self, vaddr):
        '''
        Translates virtual addresses into physical offsets.
        The function returns either None (no valid mapping)
        or the offset in physical memory where the address maps.
        '''
        vaddr = long(vaddr)
        pml4e = self.get_pml4e(vaddr)
        if not self.entry_present(pml4e):
            # Add support for paged out PML4E
            return None

        pdpte = self.get_pdpte(vaddr, pml4e)
        if not self.entry_present(pdpte):
            # Add support for paged out PDPTE
            # Insert buffalo here!
            return None

        if self.page_size_flag(pdpte):
            return self.get_one_gig_paddr(vaddr, pdpte)

        pde = self.get_pde(vaddr, pdpte)
        if not self.entry_present(pde):
            # Add support for paged out PDE
            return None

        if self.page_size_flag(pde):
            return self.get_two_meg_paddr(vaddr, pde)

        pte = self.get_pte(vaddr, pde)
        if not self.entry_present(pte):
            # Add support for paged out PTE
            return None

        return self.get_phys_addr(vaddr, pte)

    def get_available_addresses(self):
        '''
        Return a list of lists of available memory pages.
        Each entry in the list is the starting virtual address
        and the size of the memory page.
        '''
        # Pages that hold PDEs and PTEs are 0x1000 bytes each.
        # Each PDE and PTE is eight bytes. Thus there are 0x1000 / 8 = 0x200
        # PDEs and PTEs we must test.
        for pml4e in range(0, 0x200):
            vaddr = pml4e << 39
            pml4e_value = self.get_pml4e(vaddr)
            if not self.entry_present(pml4e_value):
                continue
            for pdpte in range(0, 0x200):
                vaddr = (pml4e << 39) | (pdpte << 30)
                pdpte_value = self.get_pdpte(vaddr, pml4e_value)
                if not self.entry_present(pdpte_value):
                    continue
                if self.page_size_flag(pdpte_value):
                    yield (vaddr,
                           self.get_one_gig_paddr(vaddr, pdpte_value),
                           0x40000000)
                    continue
                tmp2 = vaddr
                for pde in range(0, 0x200):
                    vaddr = tmp2 | (pde << 21)
                    pde_value = self.get_pde(vaddr, pdpte_value)
                    if not self.entry_present(pde_value):
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

                    for i, pte_value in enumerate(pte_table):
                        if self.entry_present(pte_value):
                            out_vaddr = vaddr | i << 12
                            yield (out_vaddr,
                                   self.get_phys_addr(out_vaddr, pte_value),
                                   0x1000)


class VTxPagedMemory(AMD64PagedMemory):
    """Intel VT-x address space.

    Provides an address space that does EPT page translation to provide access
    to the guest physical address space, thus allowing volatility plugins to
    operate on a virtual machine running on a host operating system.

    This is described in the Intel(R) 64 and IA-32 Architectures Software
    Developer's Manual Volume 3C: System Programming Guide, Part 3, pages 28-1
    to 28-12. This book is available for free at
    http://www.intel.com/products/processor/manuals/index.htm.

    This address space depends on the "ept" parameter. You can use the vmscan
    plugin to find valid ept values on a physical memory image.

    Note that support for AMD's AMD-V address space is untested at the moment.
    """

    order = 20
    _md_image = True

    def __init__(self, ept=None, **kwargs):
        # A dummy DTB is passed to the base class so the DTB checks on
        # IA32PagedMemory don't bail out. We require the DTB to never be used
        # for page translation outside of get_pml4e.
        AMD64PagedMemory.__init__(self, dtb=0xFFFFFFFF, **kwargs)

        # Reset the DTB, in case a plugin or AS relies on us providing one.
        self.dtb = None
        self.ept = ept or self.session.GetParameter("ept")
        self.as_assert(self.ept is not None, "No EPT specified")

        # We don't allow overlaying over another VTx AS for now.
        self.as_assert(not isinstance(self.base, VTxPagedMemory),
                       "Attempting to layer over another VT")

    def entry_present(self, entry):
        # A page entry being present depends only on bits 2:0 for EPT
        # translation.
        return entry and (entry & 0x7)

    def get_pml4e(self, vaddr):
        # PML4 for VT-x is in the EPT, not the DTB as AMD64PagedMemory does.
        ept_pml4e_paddr = ((self.ept & 0xffffffffff000) |
                           ((vaddr & 0xff8000000000) >> 36))
        return self._read_long_long_phys(ept_pml4e_paddr)

    def __str__(self):
        return "%s@0x%08X" % (self.__class__.__name__, self.ept)
