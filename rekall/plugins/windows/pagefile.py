# Rekall Memory Forensics
# Copyright 2014 Google Inc. All Rights Reserved.
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
""" This file adds pagefile support.

Although much of the address translation machinery occurs in hardware, when a
page fault occurs the operating system's pager is called. The pager is
responsible for faulting in invalid pages, and hence we need operating system
specific support.

Rekall's base paging address spaces emulate the hardware's MMU page translation,
but when the page is invalid Rekall emulates the operating system's page fault
handling code. The correct (OS depended) address space is selected in
rekall.plugins.core.FindDTB.GetAddressSpaceImplementation() based on the profile
metadata.
"""

__author__ = "Michael Cohen <scudette@google.com>"
import struct

from rekall.plugins.addrspaces import amd64
from rekall.plugins.addrspaces import intel
from rekall.plugins.windows import common

# pylint: disable=protected-access


class WindowsPagedMemoryMixin(object):
    """A mixin to implement windows specific paged memory address spaces.

    This mixin allows us to share code between 32 and 64 bit implementations.
    """

    def __init__(self, **kwargs):
        super(WindowsPagedMemoryMixin, self).__init__(**kwargs)

        # This is the offset at which the pagefile is mapped into the physical
        # address space.
        self.pagefile_mapping = getattr(self.base, "pagefile_offset", None)
        self.prototype_pte_mask = 1 << 10
        self.proto_transition_pte_mask = 1 << 10 | 1 << 11
        self.proto_transition_valid_pte_mask = 1 << 10 | 1 << 11 | 1
        self.transition_valid_mask = 1 << 11 | 1

        # Only transition bit on and proto bit off.
        self.transition_pte_value = 1 << 11 # (p=0, t=1)
        self.subsection_pte_value = 1 << 10 # (v=0, p=1, t=0)
        self._resolve_vads = True
        self.vads = None

    def entry_present(self, entry):
        # Treat Transition PTEs as valid.
        return entry & self.transition_valid_mask

    def _ConsultVad(self, virtual_address, pte):
        vad_hit = self.session.address_resolver.FindProcessVad(
            virtual_address, cache_only=not self._resolve_vads)
        if vad_hit:
            pte = pte.u.Proto
            pte.vad_hit = vad_hit
            desc = "Vad"
        else:
            # This should not happen
            desc = "Unknown"

        return desc, pte

    def DeterminePTEType(self, pte, virtual_address):
        """Determine which type of pte this is."""
        if pte.u.Hard.Valid:
            pte = pte.u.Hard
            desc = "Valid"

        elif not pte.u.Trans.Prototype and pte.u.Trans.Transition:
            pte = pte.u.Trans
            desc = "Transition"

        elif (pte.u.Proto.Prototype and
              pte.u.Proto.ProtoAddress == 0xffffffff0000):
            return self._ConsultVad(virtual_address, pte)

        # Regular prototype PTE.
        elif pte.u.Proto.Prototype:
            pte = pte.u.Proto
            desc = "Prototype"

        elif pte.u.Soft.PageFileHigh == 0:
            return self._ConsultVad(virtual_address, pte)

        # Regular _MMPTE_SOFTWARE entry - look in pagefile.
        else:
            pte = pte.u.Soft
            desc = "Pagefile"

        return desc, pte

    def ResolveProtoPTE(self, pte, virtual_address):
        """Second level resolution of prototype PTEs.

        This function resolves a prototype PTE. Some states must be interpreted
        differently than the first level PTE.
        """
        # If the prototype is Valid or in Transition, just resolve it with the
        # hardware layer.
        if pte.u.Hard.Valid or (
                not pte.u.Trans.Prototype and pte.u.Trans.Transition):
            return super(WindowsPagedMemoryMixin, self).get_phys_addr(
                virtual_address, pte.u.Long | 1)

        # If the target of the Prototype looks like a Prototype PTE, then it is
        # a Subsection PTE. However, We cant do anything about it because we
        # don't have the filesystem. Therefore we return an invalid page.
        if pte.u.Proto.Prototype:
            return None

        # Prototype PTE is a Demand Zero page
        if pte.u.Soft.PageFileHigh == 0:
            return None

        # Regular _MMPTE_SOFTWARE entry - return physical offset into pagefile.
        if self.pagefile_mapping is not None:
            return (pte.u.Soft.PageFileHigh * 0x1000 + self.pagefile_mapping +
                    (virtual_address & 0xFFF))

    def get_available_addresses(self, start=0):
        self.vads = list(self.session.address_resolver.GetVADs())
        for ranges in super(
                WindowsPagedMemoryMixin, self).get_available_addresses(
                    start=start):
            yield ranges

    def _get_available_PDEs(self, vaddr, pdpte_value, start):
        tmp2 = vaddr
        for pde in range(0, 0x200):
            vaddr = tmp2 | (pde << 21)

            next_vaddr = tmp2 | ((pde + 1) << 21)
            if start >= next_vaddr:
                continue

            pde_value = self.get_pde(vaddr, pdpte_value)
            if not self.entry_present(pde_value):
                # An invalid PDE means we read the vad, i.e. it is the same as
                # an array of zero PTEs.
                for x in self._get_available_PTEs(
                        [0] * 0x200, vaddr, start=start):
                    yield x

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
        """Scan the PTE table and yield address ranges which are valid."""
        tmp = vaddr
        for i, pte_value in enumerate(pte_table):
            vaddr = tmp | i << 12
            next_vaddr = tmp | ((i+1) << 12)
            if start >= next_vaddr:
                continue

            # Remove all the vads that end below this address. This optimization
            # allows us to skip DemandZero pages which occur outsize the VAD
            # ranges.
            while self.vads and self.vads[0][1] < vaddr:
                self.vads.pop(0)

            # PTE of 0 means we consult the VADs.
            if pte_value == 0:
                if not self.vads:
                    continue

                # Address is below the next available vad's start. We are not
                # inside a vad range and a 0 PTE is unmapped.
                if vaddr < self.vads[0][0]:
                    continue

            phys_addr = self.get_phys_addr(vaddr, pte_value)

            # Only yield valid physical addresses. This will skip DemandZero
            # pages and File mappings into the filesystem.
            if phys_addr != None:
                yield (vaddr, phys_addr, 0x1000)

    def get_phys_addr(self, virtual_address, pte_value):
        """First level resolution of PTEs.

        pte_value must be the actual PTE from hardware page tables (Not software
        PTEs which are prototype PTEs).
        """
        # If the pte is in the Transition state (i.e. Prototype=0,
        # Transition=1), make it valid.
        if (pte_value & self.proto_transition_pte_mask ==
                self.transition_pte_value):
            pte_value |= 1

        # PTE is valid or in transition, let the hardware layer handle it.
        if pte_value & 1:
            return super(WindowsPagedMemoryMixin, self).get_phys_addr(
                virtual_address, pte_value)

        try:
            # Prevent recursively calling ourselves. We might resolve Prototype
            # PTEs which end up calling plugins (like the VAD plugin) which
            # might recursively translate another Vad Prototype address. This
            # safety below ensures we cant get into infinite recursion by
            # failing more complex PTE resolution on recursive calls.
            self._resolve_vads = False

            # Switch to using symbols. Its a little bit slower but more accurate
            # and readable.
            pte = self.session.profile._MMPTE()
            pte.u.Long = pte_value

            desc, pte = self.DeterminePTEType(pte, virtual_address)
            if desc == "Prototype":
                return self.ResolveProtoPTE(pte.Proto, virtual_address)

            # This is a prototype into a vad region.
            elif desc == "Vad":
                start, _, _, mmvad = pte.vad_hit

                # If the MMVAD has PTEs resolve those..
                if "FirstPrototypePte" in mmvad.members:
                    pte = mmvad.FirstPrototypePte[
                        (virtual_address - start) >> 12]

                    return self.ResolveProtoPTE(pte, virtual_address)

            elif desc == "Pagefile" and self.pagefile_mapping:
                return (pte.PageFileHigh * 0x1000 + self.pagefile_mapping +
                        (virtual_address & 0xFFF))

        finally:
            self._resolve_vads = True


class WindowsIA32PagedMemoryPae(WindowsPagedMemoryMixin,
                                intel.IA32PagedMemoryPae):
    """A Windows specific IA32PagedMemoryPae."""

    def vtop(self, vaddr):
        '''Translates virtual addresses into physical offsets.

        The function should return either None (no valid mapping) or the offset
        in physical memory where the address maps.
        '''
        vaddr = int(vaddr)
        try:
            return self._tlb.Get(vaddr)
        except KeyError:
            pdpte = self.get_pdpte(vaddr)
            if not self.entry_present(pdpte):
                return None

            pde = self.get_pde(vaddr, pdpte)
            if not self.entry_present(pde):
                # If PDE is not valid the page table does not exist
                # yet. According to
                # http://i-web.i.u-tokyo.ac.jp/edu/training/ss/lecture/new-documents/Lectures/14-AdvVirtualMemory/AdvVirtualMemory.pdf
                # slide 11 this is the same as PTE of zero - i.e. consult the
                # VAD.
                if not self._resolve_vads:
                    return None

                return self.get_phys_addr(vaddr, 0)

            if self.page_size_flag(pde):
                return self.get_two_meg_paddr(vaddr, pde)

            pte = self.get_pte(vaddr, pde)

            res = self.get_phys_addr(vaddr, pte)

            self._tlb.Put(vaddr, res)
            return res


class WindowsAMD64PagedMemory(WindowsPagedMemoryMixin, amd64.AMD64PagedMemory):
    """A windows specific AMD64PagedMemory.

    Implements support for reading the pagefile if the base address space
    contains a pagefile.
    """

    def vtop(self, vaddr):
        '''Translates virtual addresses into physical offsets.

        The function returns either None (no valid mapping) or the offset in
        physical memory where the address maps.
        '''
        try:
            return self._tlb.Get(vaddr)
        except KeyError:
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
                # If PDE is not valid the page table does not exist
                # yet. According to
                # http://i-web.i.u-tokyo.ac.jp/edu/training/ss/lecture/new-documents/Lectures/14-AdvVirtualMemory/AdvVirtualMemory.pdf
                # slide 11 this is the same PTE of zero.
                if not self._resolve_vads:
                    return None

                return self.get_phys_addr(vaddr, 0)

            # Is this a 2 meg page?
            if self.page_size_flag(pde):
                return self.get_two_meg_paddr(vaddr, pde)

            pte = self.get_pte(vaddr, pde)
            res = self.get_phys_addr(vaddr, pte)

            self._tlb.Put(vaddr, res)
            return res


class Pagefiles(common.WindowsCommandPlugin):
    """Report all the active pagefiles."""

    name = "pagefiles"

    def render(self, renderer):
        pagingfiles = self.profile.get_constant_object(
            'MmPagingFile',
            target='Array', target_args=dict(
                target='Pointer',
                count=16,
                target_args=dict(
                    target='_MMPAGING_FILE'
                    )
                )
            )

        renderer.table_header([
            ('_MMPAGING_FILE', '', '[addrpad]'),
            ('Number', 'number', '>3'),
            ('Size (b)', 'size', '>10'),
            ('Filename', 'filename', '20'),
            ])

        for pf in pagingfiles:
            if pf:
                renderer.table_row(
                    pf, pf.PageFileNumber, pf.Size * 0x1000, pf.PageFileName)
