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

import struct

from rekall import addrspace
from rekall import config
from rekall import obj
from rekall import utils
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

    def describe_vtop(self, vaddr, collection=None):
        """Describe the resolution process of a Virtual Address.

        See base method for docs.
        """
        if collection is None:
            collection = intel.DescriptorCollection(self.session)

        # Bits 51:12 are from CR3
        # Bits 11:3 are bits 47:39 of the linear address
        pml4e_addr = ((self.get_pml4() & 0xffffffffff000) |
                      ((vaddr & 0xff8000000000) >> 36))
        pml4e_value = self.read_pte(pml4e_addr, collection=collection)

        collection.add(intel.AddressTranslationDescriptor,
                       object_name="pml4e", object_value=pml4e_value,
                       object_address=pml4e_addr)

        if not pml4e_value & self.valid_mask:
            collection.add(intel.InvalidAddress, "Invalid PML4E\n")
            return collection

        # Bits 51:12 are from the PML4E
        # Bits 11:3 are bits 38:30 of the linear address
        pdpte_addr = ((pml4e_value & 0xffffffffff000) |
                      ((vaddr & 0x7FC0000000) >> 27))
        pdpte_value = self.read_pte(pdpte_addr, collection=collection)

        collection.add(intel.AddressTranslationDescriptor,
                       object_name="pdpte", object_value=pdpte_value,
                       object_address=pdpte_addr)

        if not pdpte_value & self.valid_mask:
            collection.add(intel.InvalidAddress, "Invalid PDPTE\n")

        # Large page mapping.
        if pdpte_value & self.page_size_mask:
            # Bits 51:30 are from the PDE
            # Bits 29:0 are from the original linear address
            physical_address = ((pdpte_value & 0xfffffc0000000) |
                                (vaddr & 0x3fffffff))
            collection.add(intel.CommentDescriptor, "One Gig page\n")

            collection.add(intel.PhysicalAddressDescriptor,
                           address=physical_address)

            return collection

        # Bits 51:12 are from the PDPTE
        # Bits 11:3 are bits 29:21 of the linear address
        pde_addr = ((pdpte_value & 0xffffffffff000) |
                    ((vaddr & 0x3fe00000) >> 18))
        self._describe_pde(collection, pde_addr, vaddr)

        return collection

    def get_pml4(self):
        """Returns the PML4, the base of the paging tree."""
        return self.dtb

    def get_mappings(self, start=0, end=2**64):
        """Enumerate all available ranges.

        Yields Run objects for all available ranges in the virtual address
        space.
        """
        # Pages that hold PDEs and PTEs are 0x1000 bytes each.
        # Each PDE and PTE is eight bytes. Thus there are 0x1000 / 8 = 0x200
        # PDEs and PTEs we must test.
        for pml4e_index in range(0, 0x200):
            vaddr = pml4e_index << 39
            if vaddr > end:
                return

            next_vaddr = (pml4e_index + 1) << 39
            if start >= next_vaddr:
                continue

            pml4e_addr = ((self.get_pml4() & 0xffffffffff000) |
                          ((vaddr & 0xff8000000000) >> 36))
            pml4e_value = self.read_pte(pml4e_addr)
            if not pml4e_value & self.valid_mask:
                continue

            tmp1 = vaddr
            for pdpte_index in range(0, 0x200):
                vaddr = tmp1 | (pdpte_index << 30)
                if vaddr > end:
                    return

                next_vaddr = tmp1 | ((pdpte_index + 1) << 30)
                if start >= next_vaddr:
                    continue

                # Bits 51:12 are from the PML4E
                # Bits 11:3 are bits 38:30 of the linear address
                pdpte_addr = ((pml4e_value & 0xffffffffff000) |
                              ((vaddr & 0x7FC0000000) >> 27))
                pdpte_value = self.read_pte(pdpte_addr)
                if not pdpte_value & self.valid_mask:
                    continue

                # 1 gig page.
                if pdpte_value & self.page_size_mask:
                    yield addrspace.Run(
                        start=vaddr,
                        end=vaddr+0x40000000,
                        file_offset=((pdpte_value & 0xfffffc0000000) |
                                     (vaddr & 0x3fffffff)),
                        address_space=self.base)
                    continue

                for x in self._get_available_PDEs(
                        vaddr, pdpte_value, start, end):
                    yield x

    def _get_pte_addr(self, vaddr, pde_value):
        if pde_value & self.valid_mask:
            return (pde_value & 0xffffffffff000) | ((vaddr & 0x1ff000) >> 9)

    def _get_pde_addr(self, pdpte_value, vaddr):
        if pdpte_value & self.valid_mask:
            return ((pdpte_value & 0xffffffffff000) |
                    ((vaddr & 0x3fe00000) >> 18))

    def _get_available_PDEs(self, vaddr, pdpte_value, start, end):
        # This reads the entire PDE table at once - On
        # windows where IO is extremely expensive, its
        # about 10 times more efficient than reading it
        # one value at the time - and this loop is HOT!
        pde_table_addr = self._get_pde_addr(pdpte_value, vaddr)
        if pde_table_addr is None:
            return

        data = self.base.read(pde_table_addr, 8 * 0x200)
        pde_table = struct.unpack("<" + "Q" * 0x200, data)

        tmp2 = vaddr
        for pde_index in range(0, 0x200):
            vaddr = tmp2 | (pde_index << 21)
            if vaddr > end:
                return

            next_vaddr = tmp2 | ((pde_index + 1) << 21)
            if start >= next_vaddr:
                continue

            pde_value = pde_table[pde_index]
            if pde_value & self.valid_mask and pde_value & self.page_size_mask:
                yield addrspace.Run(
                    start=vaddr,
                    end=vaddr + 0x200000,
                    file_offset=(pde_value & 0xfffffffe00000) | (
                        vaddr & 0x1fffff),
                    address_space=self.base)
                continue

            # This reads the entire PTE table at once - On
            # windows where IO is extremely expensive, its
            # about 10 times more efficient than reading it
            # one value at the time - and this loop is HOT!
            pte_table_addr = self._get_pte_addr(vaddr, pde_value)

            # Invalid PTEs.
            if pte_table_addr is None:
                continue

            data = self.base.read(pte_table_addr, 8 * 0x200)
            pte_table = struct.unpack("<" + "Q" * 0x200, data)

            for x in self._get_available_PTEs(
                    pte_table, vaddr, start=start, end=end):
                yield x

    def _get_available_PTEs(self, pte_table, vaddr, start=0, end=2**64):
        tmp3 = vaddr
        for i, pte_value in enumerate(pte_table):
            if not pte_value & self.valid_mask:
                continue

            vaddr = tmp3 | i << 12
            if vaddr > end:
                return

            next_vaddr = tmp3 | ((i + 1) << 12)
            if start >= next_vaddr:
                continue

            yield addrspace.Run(start=vaddr,
                                end=vaddr + 0x1000,
                                file_offset=(
                                    pte_value & 0xffffffffff000) | (
                                        vaddr & 0xfff),
                                address_space=self.base)

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

    # A page entry being present depends only on bits 2:0 for EPT translation.
    valid_mask = 7

    # This is a virtualized address space.
    virtualized = True

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

    @utils.safe_property
    def ept(self):
        return self._ept

    def get_pml4(self):
        # PML4 for VT-x is in the EPT, not the DTB as AMD64PagedMemory does.
        return self._ept

    def __str__(self):
        return "%s@0x%08X" % (self.__class__.__name__, self._ept)


class XenM2PMapper(dict):
    """A maping between machine and physical addresses."""


class XenParaVirtAMD64PagedMemory(AMD64PagedMemory):
    """XEN ParaVirtualized guest address space."""

    PAGE_SIZE = 0x1000
    P2M_PER_PAGE = P2M_TOP_PER_PAGE = P2M_MID_PER_PAGE = PAGE_SIZE / 8

    # From include/xen/interface/features.h
    XENFEAT_writable_page_tables = 0
    XENFEAT_writable_descriptor_tables = 1
    XENFEAT_auto_translated_physmap = 2
    XENFEAT_supervisor_mode_kernel = 3
    XENFEAT_pae_pgdir_above_4gb = 4
    XENFEAT_mmu_pt_update_preserve_ad = 5
    XENFEAT_hvm_callback_vector = 8
    XENFEAT_hvm_safe_pvclock = 9
    XENFEAT_hvm_pirqs = 10
    XENFEAT_dom0 = 11

    def __init__(self, **kwargs):
        super(XenParaVirtAMD64PagedMemory, self).__init__(**kwargs)
        self.page_offset = self.session.GetParameter("page_offset")
        self._xen_features = None
        self.rebuilding_map = False
        if self.page_offset:
            self._RebuildM2PMapping()

    def xen_feature(self, flag):
        """Obtains the state of a XEN feature."""
        if not self._xen_features:
          # We have to instantiate xen_features manually from the physical
          # address space since we are building a virtual one when xen_feature
          # is called.
            xen_features_p = self.session.profile.get_constant("xen_features")
            xen_features_phys = (xen_features_p -
                                 self.session.profile.GetPageOffset())
            self._xen_features = obj.Array(
                vm=self.session.physical_address_space,
                target="unsigned char",
                offset=xen_features_phys,
                session=self.session,
                profile=self.session.profile,
                count=32)

        return self._xen_features[flag]

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

        if self.session.GetParameter("m2p_mapping"):
            return

        if self.rebuilding_map:
            raise RuntimeError("RebuildM2PMapping recursed... aborting.")

        self.rebuilding_map = True

        self.session.logging.debug(
            "Rebuilding the machine to physical mapping...")

        try:
            p2m_top_location = self.session.profile.get_constant_object(
                "p2m_top", "Pointer", vm=self)
            p2m_missing = self.session.profile.get_constant_object(
                "p2m_missing", "Pointer", vm=self)
            p2m_mid_missing = self.session.profile.get_constant_object(
                "p2m_mid_missing", "Pointer", vm=self)
            p2m_identity = self.session.profile.get_constant_object(
                "p2m_identity", "Pointer", vm=self)

            self.session.logging.debug("p2m_top = %#0x", p2m_top_location)
            self.session.logging.debug("p2m_missing = %#0x", p2m_missing)
            self.session.logging.debug("p2m_mid_missing = %#0x",
                                       p2m_mid_missing)
            self.session.logging.debug("p2m_identity = %#0x", p2m_identity)

            # Obtained for debugging purposes as we don't have explicit support
            # for it yet, and it doesn't seem to be common.
            self.session.logging.debug(
                "XENFEAT_auto_translated_physmap = %d",
                self.xen_feature(self.XENFEAT_auto_translated_physmap))

            # A mapping of offset to symbol name
            OFF2SYM = {
                long(p2m_missing): "p2m_missing",
                long(p2m_mid_missing): "p2m_mid_missing",
                ~0: "INVALID_P2M",
                }

            new_mapping = XenM2PMapper()

            # TOP entries
            for p2m_top in self._ReadP2M(
                    p2m_top_location, self.P2M_TOP_PER_PAGE):
                p2m_top_idx, p2m_top_entry = p2m_top
                p2m_top_entry = obj.Pointer.integer_to_address(p2m_top_entry)

                self.session.report_progress(
                    "Building m2p map %.02f%%" % (
                        100 * (float(p2m_top_idx) / self.P2M_TOP_PER_PAGE)))

                self.session.logging.debug(
                    "p2m_top[%d] = %s",
                    p2m_top_idx,
                    OFF2SYM.get(p2m_top_entry, "%#0x" % p2m_top_entry))

                if p2m_top_entry == p2m_mid_missing:
                    continue

                # MID entries
                for p2m_mid in self._ReadP2M(
                        p2m_top_entry, self.P2M_MID_PER_PAGE):

                    p2m_mid_idx, p2m_mid_entry = p2m_mid
                    p2m_mid_entry = obj.Pointer.integer_to_address(
                        p2m_mid_entry)

                    if p2m_mid_entry == p2m_identity:
                        # Logging because we haven't seen IDENTITY mid_entries
                        # before.
                        self.session.logging.debug(
                            "p2m_top[%d][%d] IS IDENTITY",
                            p2m_top_idx, p2m_mid_idx)

                        # XXX: [Experimental] based on the kernel source code.
                        # get_phys_to_machine returns the IDENTITY_FRAME of the
                        # PFN as the MFN when the mid_entry was marked as
                        # being an identity.
                        # http://lxr.free-electrons.com/source/arch/x86/xen/p2m.c?v=3.8#L494
                        #
                        # We fill all the MFNs under this mid_entry as
                        # identities.
                        for idx in xrange(self.P2M_PER_PAGE):
                            pfn = (p2m_top_idx * self.P2M_MID_PER_PAGE
                                   * self.P2M_PER_PAGE
                                   + p2m_mid_idx * self.P2M_PER_PAGE
                                   + idx)
                            mfn = self.IDENTITY_FRAME(pfn)
                            new_mapping[mfn] = pfn
                        continue

                    # Uninitialized p2m_mid_entries can be skipped entirely.
                    if p2m_mid_entry == p2m_missing:
                        continue

                    self.session.logging.debug(
                        "p2m_top[%d][%d] = %s",
                        p2m_top_idx,
                        p2m_mid_idx,
                        OFF2SYM.get(p2m_mid_entry, "%#0x" % p2m_mid_entry))

                    for p2m in self._ReadP2M(p2m_mid_entry, self.P2M_PER_PAGE):
                        p2m_idx, mfn = p2m
                        pfn = (p2m_top_idx * self.P2M_MID_PER_PAGE
                               * self.P2M_PER_PAGE
                               + p2m_mid_idx * self.P2M_PER_PAGE
                               + p2m_idx)

                        if p2m_mid_entry == p2m_identity:
                            self.session.logging.debug(
                                "p2m_top[%d][%d][%d] is IDENTITY",
                                p2m_top_idx,
                                p2m_mid_idx,
                                p2m_idx)

                        # For debugging purposes. Not found commonly as far as
                        # we've seen.
                        if mfn == ~0:
                            self.session.logging.debug(
                                "p2m_top[%d][%d][%d] is INVALID")
                            continue

                        new_mapping[mfn] = pfn
            self.session.logging.debug("Caching m2p_mapping (%d entries)...",
                                       len(new_mapping))
            self.session.SetCache("m2p_mapping", new_mapping)
        finally:
            self.rebuilding_map = False

    def IDENTITY_FRAME(self, pfn):
        """Returns the identity frame of pfn.

        From
        http://lxr.free-electrons.com/source/arch/x86/include/asm/xen/page.h?v=3.8#L36
        """

        BITS_PER_LONG = 64
        IDENTITY_BIT = 1 << (BITS_PER_LONG - 2)
        return pfn | IDENTITY_BIT

    def m2p(self, machine_address):
        """Translates from a machine address to a physical address.

        This translates host physical addresses to guest physical.
        Requires a machine to physical mapping to have been calculated.
        """
        m2p_mapping = self.session.GetParameter("m2p_mapping", cached=True)
        if not m2p_mapping:
            self._RebuildM2PMapping()
        machine_address = obj.Pointer.integer_to_address(machine_address)
        mfn = machine_address / 0x1000
        pfn = m2p_mapping.get(mfn)
        if pfn is None:
            return obj.NoneObject("No PFN mapping found for MFN %d" % mfn)
        return (pfn * 0x1000) | (0xFFF & machine_address)

    def read_pte(self, vaddr, collection=None):
        mfn = super(XenParaVirtAMD64PagedMemory, self).read_pte(vaddr)
        pfn = self.m2p(mfn)
        if collection != None:
            collection.add(
                intel.CommentDescriptor,
                ("\n(XEN resolves MFN 0x%x to PFN 0x%x)\n"
                 % (mfn, pfn)))

        return pfn

    def vtop(self, vaddr):
        vaddr = obj.Pointer.integer_to_address(vaddr)

        if not self.session.GetParameter("m2p_mapping"):
            # Simple shortcut for linux. This is required for the first set
            # of virtual to physical resolutions while we're building the
            # mapping.
            page_offset = obj.Pointer.integer_to_address(
                self.profile.GetPageOffset())

            if vaddr > page_offset:
                result = self.profile.phys_addr(vaddr)
                if result > self.base.end():
                    # Force a rebuild if the phys_addr is outside the base
                    # image.
                    self._RebuildM2PMapping()
                    return super(XenParaVirtAMD64PagedMemory,
                                 self).vtop(vaddr)
                return result

            # Try to update the mapping
            if not self.rebuilding_map:
                self._RebuildM2PMapping()

        return super(XenParaVirtAMD64PagedMemory, self).vtop(vaddr)

    def _get_available_PDEs(self, vaddr, pdpte_value, start, end):
        # This reads the entire PDE table at once - On
        # windows where IO is extremely expensive, its
        # about 10 times more efficient than reading it
        # one value at the time - and this loop is HOT!
        pde_table_addr = self._get_pde_addr(pdpte_value, vaddr)
        if pde_table_addr is None:
            return

        data = self.base.read(pde_table_addr, 8 * 0x200)
        pde_table = struct.unpack("<" + "Q" * 0x200, data)

        tmp2 = vaddr
        for pde_index in range(0, 0x200):
            vaddr = tmp2 | (pde_index << 21)
            if vaddr > end:
                return

            next_vaddr = tmp2 | ((pde_index + 1) << 21)
            if start >= next_vaddr:
                continue

            pde_value = self.m2p(pde_table[pde_index])
            if pde_value & self.valid_mask and pde_value & self.page_size_mask:
                yield addrspace.Run(
                    start=vaddr,
                    end=vaddr + 0x200000,
                    file_offset=(pde_value & 0xfffffffe00000) | (
                        vaddr & 0x1fffff),
                    address_space=self.base)
                continue

            # This reads the entire PTE table at once - On
            # windows where IO is extremely expensive, its
            # about 10 times more efficient than reading it
            # one value at the time - and this loop is HOT!
            pte_table_addr = self._get_pte_addr(vaddr, pde_value)

            # Invalid PTEs.
            if pte_table_addr is None:
                continue

            data = self.base.read(pte_table_addr, 8 * 0x200)
            pte_table = struct.unpack("<" + "Q" * 0x200, data)

            for x in self._get_available_PTEs(
                    pte_table, vaddr, start=start, end=end):
                yield x

    def _get_available_PTEs(self, pte_table, vaddr, start=0, end=2**64):
        """Returns PFNs for each PTE entry."""
        tmp3 = vaddr
        for i, pte_value in enumerate(pte_table):
            # Each of the PTE values has to be translated back to a PFN, since
            # they are MFNs.
            pte_value = self.m2p(pte_value)

            # When no translation was found, we skip the PTE, since we don't
            # know where it's pointing to.
            if pte_value == None:
                continue

            if not pte_value & self.valid_mask:
                continue

            vaddr = tmp3 | i << 12
            if vaddr > end:
                return

            next_vaddr = tmp3 | ((i + 1) << 12)
            if start >= next_vaddr:
                continue

            yield addrspace.Run(start=vaddr,
                                end=vaddr + 0x1000,
                                file_offset=(
                                    pte_value & 0xffffffffff000) | (
                                        vaddr & 0xfff),
                                address_space=self.base)
