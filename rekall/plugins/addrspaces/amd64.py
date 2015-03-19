# Rekall Memory Forensics
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Authors:
# Mike Auty
# Michael Cohen
# Jordi Sanchez
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
# pylint: disable=protected-access

import logging
import struct

from rekall import addrspace
from rekall import config
from rekall import obj
from rekall.plugins.addrspaces import intel
from rekall.plugins.addrspaces import standard


config.DeclareOption("ept", group="Virtualization support",
                     type="ArrayIntParser",
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

    def pml4e_entry_present(self, entry):
        '''
        Returns whether or not the 'P' (Present) flag is on
        in the given entry
        '''
        return entry & 1

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
        return self.read_long_long_phys(pml4e_addr)

    def get_pdpte(self, vaddr, pml4e):
        '''
        Return the Page Directory Pointer Table Entry for the virtual address.

        Bits 51:12 are from the PML4E
        Bits 11:3 are bits 38:30 of the linear address
        Bits 2:0 are all 0
        '''
        pdpte_addr = (pml4e & 0xffffffffff000) | ((vaddr & 0x7FC0000000) >> 27)
        return self.read_long_long_phys(pdpte_addr)

    def get_one_gig_paddr(self, vaddr, pdpte):
        '''
        Return the offset in a 1GB memory page from the given virtual
        address and Page Directory Pointer Table Entry.

        Bits 51:30 are from the PDE
        Bits 29:0 are from the original linear address
        '''
        return (pdpte & 0xfffffc0000000) | (vaddr & 0x3fffffff)

    lock = 0

    def vaddr_access(self, vaddr):
        """Is the access bit set on the page for the vaddr?"""
        vaddr = long(vaddr)
        pml4e = self.get_pml4e(vaddr)
        if not self.pml4e_entry_present(pml4e):
            return None

        pdpte = self.get_pdpte(vaddr, pml4e)
        if not self.pdpte_entry_present(pdpte):
            return None

        if self.page_size_flag(pdpte):
            return (self.page_access_flag(pml4e) and
                    self.page_access_flag(pdpte))

        pde = self.get_pde(vaddr, pdpte)
        if not self.pde_entry_present(pde):
            return None

        if self.page_size_flag(pde):
            return (self.page_access_flag(pde) and
                    self.page_access_flag(pml4e) and
                    self.page_access_flag(pdpte))

        pte = self.get_pte(vaddr, pde)
        if not self.pte_entry_present(pte):
            return None

        return (self.page_access_flag(pte) and
                self.page_access_flag(pde) and
                self.page_access_flag(pml4e) and
                self.page_access_flag(pdpte))

    def vtop(self, vaddr):
        '''
        Translates virtual addresses into physical offsets.
        The function returns either None (no valid mapping)
        or the offset in physical memory where the address maps.
        '''
        vaddr = long(vaddr)
        pml4e = self.get_pml4e(vaddr)
        if not self.pml4e_entry_present(pml4e):
            # Add support for paged out PML4E
            return None

        pdpte = self.get_pdpte(vaddr, pml4e)
        if not self.pdpte_entry_present(pdpte):
            # Add support for paged out PDPTE
            # Insert buffalo here!
            return None

        if self.page_size_flag(pdpte):
            return self.get_one_gig_paddr(vaddr, pdpte)

        pde = self.get_pde(vaddr, pdpte)
        if not self.pde_entry_present(pde):
            # Add support for paged out PDE
            return None

        # Is this a 2 meg page?
        if pde & 1 and self.page_size_flag(pde):
            return self.get_two_meg_paddr(vaddr, pde)

        pte = self.get_pte(vaddr, pde)

        return self.get_phys_addr(vaddr, pte)

    def get_available_addresses(self, start=0):
        """Enumerate all available ranges.

        Yields tuples of (vaddr, physical address, length) for all available
        ranges in the virtual address space.
        """
        # Pages that hold PDEs and PTEs are 0x1000 bytes each.
        # Each PDE and PTE is eight bytes. Thus there are 0x1000 / 8 = 0x200
        # PDEs and PTEs we must test.
        for pml4e in range(0, 0x200):
            vaddr = pml4e << 39

            next_vaddr = (pml4e + 1) << 39
            if start >= next_vaddr:
                continue

            pml4e_value = self.get_pml4e(vaddr)
            if not self.pml4e_entry_present(pml4e_value):
                continue

            tmp1 = vaddr
            for pdpte in range(0, 0x200):
                vaddr = tmp1 | (pdpte << 30)

                next_vaddr = tmp1 | ((pdpte + 1) << 30)
                if start >= next_vaddr:
                    continue

                pdpte_value = self.get_pdpte(vaddr, pml4e_value)
                if not self.pdpte_entry_present(pdpte_value):
                    continue

                if self.page_size_flag(pdpte_value):
                    yield (vaddr,
                           self.get_one_gig_paddr(vaddr, pdpte_value),
                           0x40000000)
                    continue

                for x in self._get_available_PDEs(vaddr, pdpte_value, start):
                    yield x

    def _get_available_PDEs(self, vaddr, pdpte_value, start):
        tmp2 = vaddr
        for pde in range(0, 0x200):
            vaddr = tmp2 | (pde << 21)

            next_vaddr = tmp2 | ((pde + 1) << 21)
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

            for x in self._get_available_PTEs(
                    pte_table, vaddr, start=start):
                yield x

    def _get_available_PTEs(self, pte_table, vaddr, start=0):
        tmp3 = vaddr
        for i, pte_value in enumerate(pte_table):
            if not self.pte_entry_present(pte_value):
                continue

            vaddr = tmp3 | i << 12
            next_vaddr = tmp3 | ((i + 1) << 12)
            if start >= next_vaddr:
                continue

            yield (vaddr,
                   self.get_phys_addr(vaddr, pte_value),
                   0x1000)

    def end(self):
        return (2 ** 64) - 1


class VTxPagedMemory(AMD64PagedMemory):
    """Intel VT-x address space.

    Provides an address space that does EPT page translation to provide access
    to the guest physical address space, thus allowing plugins to operate on a
    virtual machine running on a host operating system.

    This is described in the Intel(R) 64 and IA-32 Architectures Software
    Developer's Manual Volume 3C: System Programming Guide, Part 3, pages 28-1
    to 28-12. This book is available for free at
    http://www.intel.com/products/processor/manuals/index.htm.

    This address space depends on the "ept" parameter. You can use the vmscan
    plugin to find valid ept values on a physical memory image.

    Note that support for AMD's AMD-V address space is untested at the moment.
    """

    # Virtualization is always the last AS since it has to overlay any form of
    # image AS.
    order = standard.FileAddressSpace.order + 10
    __image = True
    _ept = None

    def __init__(self, ept=None, **kwargs):
        # A dummy DTB is passed to the base class so the DTB checks on
        # IA32PagedMemory don't bail out. We require the DTB to never be used
        # for page translation outside of get_pml4e.
        try:
            super(VTxPagedMemory, self).__init__(dtb=0xFFFFFFFF, **kwargs)
        except TypeError:
            raise addrspace.ASAssertionError()

        # Reset the DTB, in case a plugin or AS relies on us providing one.
        self.dtb = None
        ept_list = ept or self.session.GetParameter("ept")
        if not isinstance(ept_list, (list, tuple)):
            ept_list = [ept_list]

        self.as_assert(ept_list, "No EPT specified")

        this_ept = None
        if isinstance(self.base, VTxPagedMemory):
            # Find our EPT, which will be the next one after the base one.
            base_idx = ept_list.index(self.base._ept)
            try:
                this_ept = ept_list[base_idx + 1]
            except IndexError:
                pass
        else:
            this_ept = ept_list[0]

        self.as_assert(this_ept != None, "No more EPTs specified")
        self._ept = this_ept
        self.name = "VTxPagedMemory@%#x" % self._ept

    def pml4e_entry_present(self, entry):
        # A page entry being present depends only on bits 2:0 for EPT
        # translation.
        return entry and (entry & 0x7)

    def pdpte_entry_present(self, entry):
        # A page entry being present depends only on bits 2:0 for EPT
        # translation.
        return entry and (entry & 0x7)

    def pde_entry_present(self, entry):
        # A page entry being present depends only on bits 2:0 for EPT
        # translation.
        return entry and (entry & 0x7)

    def pte_entry_present(self, entry):
        # A page entry being present depends only on bits 2:0 for EPT
        # translation.
        return entry and (entry & 0x7)

    def get_pml4e(self, vaddr):
        # PML4 for VT-x is in the EPT, not the DTB as AMD64PagedMemory does.
        ept_pml4e_paddr = ((self._ept & 0xffffffffff000) |
                           ((vaddr & 0xff8000000000) >> 36))
        return self.read_long_long_phys(ept_pml4e_paddr)

    def __str__(self):
        return "%s@0x%08X" % (self.__class__.__name__, self._ept)


class XenParaVirtAMD64PagedMemory(AMD64PagedMemory):
    """XEN ParaVirtualized guest address space."""

    PAGE_SIZE = 0x1000
    P2M_PER_PAGE = P2M_TOP_PER_PAGE = P2M_MID_PER_PAGE = PAGE_SIZE / 8

    def __init__(self, **kwargs):
        super(XenParaVirtAMD64PagedMemory, self).__init__(**kwargs)
        self.page_offset = self.session.GetParameter("page_offset")
        self.m2p_mapping = {}
        self.rebuilding_map = False
        if self.page_offset:
            self._RebuildM2PMapping()

    def _ReadP2M(self, offset, p2m_size):
        """Helper function to return p2m entries at offset.

        This function is used to speed up reading the p2m tree, because
        traversal via the Array struct is slow.

        Yields tuples of (index, p2m) for each p2m, up to a number of p2m_size.
        """
        for index, mfn in zip(
                xrange(0, p2m_size),
                struct.unpack(
                    "<" + "Q" * p2m_size,
                    self.read(offset, 0x1000))):
            yield (index, mfn)

    def _RebuildM2PMapping(self):
        """Rebuilds the machine to physical mapping.

        A XEN ParaVirtualized kernel (the guest) maintains a special set of
        page tables. Each entry is to machine (host) memory instead of
        physical (guest) memory.

        XEN maintains a mapping of machine to physical and mapping of physical
        to machine mapping in a set of trees. We need to use the former to
        translate the machine addresses in the page tables, but only the later
        tree is available (mapped in memory) on the guest.

        When rekall is run against the memory of a paravirtualized Linux kernel
        we traverse the physical to machine mapping and invert it so we can
        quickly translate from machine (host) addresses to guest physical
        addresses.

        See: http://lxr.free-electrons.com/source/arch/x86/xen/p2m.c?v=3.0 for
        reference.
        """

        logging.debug("Rebuilding the machine to physical mapping...")
        self.rebuilding_map = True
        try:
            p2m_top_location = self.session.profile.get_constant_object(
                "p2m_top", "Pointer", vm=self).deref()

            end_value = self.session.profile.get_constant("__bss_stop", False)
            new_mapping = {}
            for p2m_top in self._ReadP2M(
                    p2m_top_location, self.P2M_TOP_PER_PAGE):
                p2m_top_idx, p2m_top_entry = p2m_top
                self.session.report_progress(
                    "Building m2p map %.02f%%" % (
                        100 * (float(p2m_top_idx) / self.P2M_TOP_PER_PAGE)))

                if p2m_top_entry == end_value:
                    continue

                for p2m_mid in self._ReadP2M(
                        p2m_top_entry, self.P2M_MID_PER_PAGE):
                    p2m_mid_idx, p2m_mid_entry = p2m_mid
                    if p2m_mid_entry == end_value:
                        continue

                    for p2m in self._ReadP2M(p2m_mid_entry, self.P2M_PER_PAGE):
                        p2m_idx, mfn = p2m
                        pfn = (p2m_top_idx * self.P2M_MID_PER_PAGE
                               * self.P2M_PER_PAGE
                               + p2m_mid_idx * self.P2M_PER_PAGE
                               + p2m_idx)

                        new_mapping[mfn] = pfn

            self.m2p_mapping = new_mapping
            self.session.SetCache("mapping", self.m2p_mapping)
        finally:
            self.rebuilding_map = False

    def m2p(self, machine_address):
        """Translates from a machine address to a physical address.

        This translates host physical addresses to guest physical.
        Requires a machine to physical mapping to have been calculated.
        """
        machine_address = obj.Pointer.integer_to_address(machine_address)
        mfn = machine_address / 0x1000
        pfn = self.m2p_mapping.get(mfn)
        if pfn is None:
            return 0
        return (pfn * 0x1000) | (0xFFF & machine_address)

    def get_pml4e(self, vaddr):
        return self.m2p(
            super(XenParaVirtAMD64PagedMemory, self).get_pml4e(vaddr))

    def get_pdpte(self, vaddr, pml4e):
        return self.m2p(
            super(XenParaVirtAMD64PagedMemory, self).get_pdpte(vaddr, pml4e))

    def get_pde(self, vaddr, pml4e):
        return self.m2p(
            super(XenParaVirtAMD64PagedMemory, self).get_pde(vaddr, pml4e))

    def get_pte(self, vaddr, pml4e):
        return self.m2p(
            super(XenParaVirtAMD64PagedMemory, self).get_pte(vaddr, pml4e))

    def vtop(self, vaddr):
        vaddr = obj.Pointer.integer_to_address(vaddr)

        if not self.session.GetParameter("mapping"):
            # Simple shortcut for linux. This is required for the first set
            # of virtual to physical resolutions while we're building the
            # mapping.
            page_offset = obj.Pointer.integer_to_address(
                self.profile.GetPageOffset())
            if vaddr > page_offset:
                return self.profile.phys_addr(vaddr)

            # Try to update the mapping
            if not self.rebuilding_map:
                self._RebuildM2PMapping()

        return super(XenParaVirtAMD64PagedMemory, self).vtop(vaddr)
