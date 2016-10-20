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
"""This file adds pagefile support.

Although much of the address translation machinery occurs in hardware, when a
page fault occurs the operating system's pager is called. The pager is
responsible for faulting in invalid pages, and hence we need operating system
specific support.

Rekall's base paging address spaces emulate the hardware's MMU page translation,
but when the page is invalid Rekall emulates the operating system's page fault
handling code. The correct (OS dependent) address space is selected in
rekall.plugins.core.FindDTB.GetAddressSpaceImplementation() based on the profile
metadata.

This file implements the algorithms described in the paper:

Forensic Analysis of Windows User space Applications through Heap allocations.
Michael Cohen, 3rd IEEE International Workshop on Security and Forensics in
Communication Systems 2015 [1]

http://www.rekall-forensic.com/docs/References/Papers/p1138-cohen.pdf
"""

__author__ = "Michael Cohen <scudette@google.com>"
import struct

from rekall import addrspace
from rekall import obj
from rekall import utils
from rekall.plugins.addrspaces import amd64
from rekall.plugins.addrspaces import intel
from rekall.plugins.windows import address_resolver
from rekall.plugins.windows import common

# pylint: disable=protected-access


def Reentrant(func):
    def Wrapper(self, *args, **kwargs):
        lock = "_lock" + func.__name__
        if not getattr(self, lock, False):
            try:
                setattr(self, lock, True)
                return func(self, *args, **kwargs)
            except RuntimeError:
                pass
            finally:
                setattr(self, lock, False)

    return Wrapper


# Windows has some special steps in its address translation. We define some
# windows specific descriptors here.
class WindowsPTEDescriptor(intel.AddressTranslationDescriptor):
    """Print the PTE in exploded view."""

    default_pte_type = None
    object_name = "pte"

    def __init__(self, pte_type=None, pte_value=None, pte_addr=None,
                 object_name=None, session=None):
        """Define a windows PTE object.

        Valid PTE types are all the members inside the _MMPTE
        union. e.g. "Hard", "Transition", "Soft", etc).
        """
        super(WindowsPTEDescriptor, self).__init__(
            object_name=self.object_name, object_value=pte_value,
            object_address=pte_addr, session=session)
        self.pte_type = pte_type or self.default_pte_type
        if object_name is not None:
            self.object_name = object_name

    def render(self, renderer):
        super(WindowsPTEDescriptor, self).render(renderer)

        pte = self.session.profile._MMPTE()
        pte.u.Long = int(self.object_value)
        if self.pte_type:
            specific_pte = pte.u.m(self.pte_type)

            self.session.plugins.dt(
                specific_pte, offset=self.object_address).render(renderer)


class WindowsPDEDescriptor(WindowsPTEDescriptor):
    object_name = "pde"


class WindowsProtoTypePTEDescriptor(WindowsPTEDescriptor):
    default_pte_type = "Proto"


class WindowsSoftwarePTEDescriptor(WindowsPTEDescriptor):
    default_pte_type = "Soft"



class DemandZeroDescriptor(intel.AddressTranslationDescriptor):
    """Describe a Demand Zero page."""

    def render(self, renderer):
        renderer.format("Demand Zero")



class WindowsValidPTEDescriptor(WindowsPTEDescriptor):
    """A descriptor for Valid or in Transition PTEs."""

    def __init__(self, **kwargs):
        super(WindowsValidPTEDescriptor, self).__init__(**kwargs)
        if self.object_value & 1:
            self.pte_type = "Hard"
        else:
            self.pte_type = "Trans"


class WindowsPagefileDescriptor(intel.AddressTranslationDescriptor):
    """A descriptor to mark the final physical address resolution."""

    def __init__(self, address=0, pagefile_number=0, protection=0,
                 session=None):
        super(WindowsPagefileDescriptor, self).__init__(session=session)
        self.address = address
        self.pagefile_number = pagefile_number
        self.protection = protection

    def render(self, renderer):
        renderer.format("Pagefile ({0}) @ {1:addr}\n",
                        self.pagefile_number, self.address)


class WindowsFileMappingDescriptor(intel.AddressTranslationDescriptor):
    """Describe a file mapping."""

    def __init__(self, pte_address=None, page_offset=0,
                 original_pte=None, **kwargs):
        super(WindowsFileMappingDescriptor, self).__init__(
            object_address=pte_address, **kwargs)
        self.pte_address = pte_address
        self.page_offset = page_offset
        self.original_pte = original_pte

    def get_subsection(self):
        """Find the right subsection object for this pte."""
        # Try to find the subsection by looking it up from the list of known
        # subsections.
        subsection_lookup = self.session.GetParameter(
            "prototype_pte_array_subsection_lookup")

        start, _, subsection_offset = subsection_lookup.get_containing_range(
            self.pte_address)

        if start:
            return self.session.profile._SUBSECTION(subsection_offset)

        if self.original_pte is not None:
            return self.original_pte.u.Subsect.Subsection

    def filename_and_offset(self, subsection=None):
        """Return the filename of the file mapped (if it is a file mapping)."""
        if subsection is None:
            subsection = self.get_subsection()

        if subsection:
            # File mapping.
            ca = subsection.ControlArea

            # First PTE in subsection.
            start = subsection.SubsectionBase.v()

            if ca.u.Flags.File:
                size_of_pte = self.session.profile.get_obj_size("_MMPTE")
                mapped_offset_in_file = 0x1000 * (
                    self.pte_address - start) / size_of_pte + (
                        subsection.StartingSector * 512)

                return (ca.FilePointer.file_name_with_drive(),
                        mapped_offset_in_file + self.page_offset)

        return None, None

    def get_owners(self, subsection=None):
        """Returns a list of _EPROCESS, virtual offsets for owners."""
        result = []
        if subsection is None:
            subsection = self.get_subsection()

        if subsection:
            for details in self.session.GetParameter("subsections").get(
                    subsection.obj_offset, []):
                task = self.session.profile._EPROCESS(details["task"])
                vad = self.session.profile.Object(offset=details["vad"],
                                                  type_name=details["type"])

                # Find the virtual address.
                size_of_pte = self.session.profile.get_obj_size("_MMPTE")
                relative_offset = (
                    self.pte_address - vad.FirstPrototypePte.v()) / size_of_pte

                virtual_address = (
                    relative_offset * 0x1000 + vad.Start + self.page_offset)

                result.append((task, virtual_address))

        return result

    def render(self, renderer):
        subsection = self.get_subsection()
        filename, offset = self.filename_and_offset(subsection)
        if filename:
            renderer.format("File Mapping ({0} @ {1:#x} \n", filename, offset)

        # Private mapping.
        else:
            renderer.format(
                "Private Mapping by {0}\n",
                subsection.ControlArea.Segment.u1.CreatingProcess.deref())

        for task, virtual_address in self.get_owners(subsection=subsection):
            renderer.format(
                "Mapped in {0} @ {1:#x}\n", task, virtual_address)


class WindowsSubsectionPTEDescriptor(WindowsPTEDescriptor):
    """A descriptor for a subsection PTE."""

    def metadata(self):
        pte = self.session.profile._MMPTE(self.object_address)
        subsection = pte.u.Subsect.Subsection

        # Calculate the file offset. The SubsectionBase is an array pointer
        # to the linear arrays of section PTEs (one per file sector).
        file_offset = (
            (pte - subsection.SubsectionBase) * 0x1000 / pte.obj_size +
            subsection.StartingSector * 512)

        return dict(
            type="File Mapping",
            filename=subsection.ControlArea.FilePointer.file_name_with_drive(),
            offset=file_offset)

    def render(self, renderer):
        pte = self.session.profile._MMPTE()
        pte.u.Long = int(self.object_value)
        specific_pte = pte.u.Subsect

        self.session.plugins.dt(
            specific_pte, offset=self.object_address).render(renderer)

        metadata = self.metadata()
        renderer.format("Subsection PTE to file {0} @ {1:addr}\n",
                        metadata["filename"], metadata["offset"])


class VadPteDescriptor(WindowsPTEDescriptor):
    """A descriptor which applies specifically for Prototype PTEs from the VAD.

    Windows uses placeholder values in the PTE to trigger a further resolution
    of the PTE from the VAD. For example a PTE of 0xffffffff00000420 would
    signal to consult the VAD for the real status of this PTE.
    """

    def __init__(self, virtual_address=None, **kwargs):
        """Define a windows PTE object.

        Valid PTE types are all the members inside the _MMPTE
        union. e.g. "Hard", "Transition", "Soft", etc).
        """
        super(VadPteDescriptor, self).__init__(pte_type="Soft", **kwargs)
        self.virtual_address = virtual_address

    def render(self, renderer):
        renderer.format("Prototype PTE is found in VAD\n")
        task = self.session.GetParameter("process_context")

        # Show the VAD region for the virtual address.
        vad_plugin = self.session.plugins.vad(
            eprocess=task, offset=self.virtual_address)
        vad_plugin.render(renderer)

        resolver = self.session.address_resolver
        module = resolver.GetContainingModule(self.virtual_address)
        if isinstance(module, address_resolver.VadModule):
            mmvad = module.vad

            # The MMVAD does not have any prototypes.
            if mmvad.m("FirstPrototypePte").deref() == None:
                renderer.format("Demand Zero page\n")

            else:
                renderer.format("\n_MMVAD.FirstPrototypePte: {0:#x}\n",
                                mmvad.FirstPrototypePte)
                pte = mmvad.FirstPrototypePte[
                    (self.virtual_address - module.start) >> 12]

                renderer.format(
                    "Prototype PTE is at virtual address {0:#x} "
                    "(Physical Address {1:#x})\n", pte,
                    pte.obj_vm.vtop(pte.obj_offset))
        else:
            renderer.format("Demand Zero page\n")


class WindowsDTBDescriptor(intel.AddressTranslationDescriptor):
    """A descriptor for DTB values.

    On windows the DTB holds a reference to the _EPROCESS that owns it. This
    descriptor prints this information too.
    """
    object_name = "DTB"

    def __init__(self, dtb, **kwargs):
        super(WindowsDTBDescriptor, self).__init__(object_value=dtb, **kwargs)
        self.dtb = dtb

    def owner(self):
        pfn_database = self.session.profile.get_constant_object("MmPfnDatabase")
        pfn_obj = pfn_database[self.dtb >> 12]
        return pfn_obj.u1.Flink.cast("Pointer", target="_EPROCESS").deref()

    def render(self, renderer):
        renderer.format("DTB {0:#x} ", self.dtb)
        owning_process = self.owner()

        if owning_process != None:
            renderer.format("Owning process: {0}", owning_process)

        renderer.format("\n")


class WindowsPagedMemoryMixin(object):

    """A mixin to implement windows specific paged memory address spaces.

    This mixin allows us to share code between 32 and 64 bit implementations.
    """

    def __init__(self, **kwargs):
        super(WindowsPagedMemoryMixin, self).__init__(**kwargs)

        # This is the offset at which the pagefile is mapped into the physical
        # address space.
        self._resolve_vads = True
        self._vad = None

        # We cache these bitfields in order to speed up mask calculations. We
        # derive them initially from the profile so we do not need to hardcode
        # any bit positions.
        pte = self.session.profile._MMPTE()
        self.prototype_mask = pte.u.Proto.Prototype.mask
        self.transition_mask = pte.u.Trans.Transition.mask
        self.valid_mask = pte.u.Hard.Valid.mask
        self.proto_protoaddress_mask = pte.u.Proto.ProtoAddress.mask
        self.proto_protoaddress_start = pte.u.Proto.ProtoAddress.start_bit
        self.soft_pagefilehigh_mask = pte.u.Soft.PageFileHigh.mask

        # Combined masks for faster checking.
        self.proto_transition_mask = self.prototype_mask | self.transition_mask
        self.proto_transition_valid_mask = (self.proto_transition_mask |
                                            self.valid_mask)
        self.transition_valid_mask = self.transition_mask | self.valid_mask
        self.task = None

        self.base_as_can_map_files = self.base.metadata("can_map_files")

        # A Guard flag for protecting against re-entrancy when resolving the
        # pagefiles.
        self._resolving_pagefiles = False

    @utils.safe_property
    def vad(self):
        """Returns a cached RangedCollection() of vad ranges."""

        # If this dtb is the same as the kernel dtb - there are no vads.
        if self.dtb == self.session.GetParameter("dtb"):
            return

        # If it is already cached, just return that.
        if self._vad is not None:
            return self._vad

        # We can not run plugins in recursive context.
        if not self._resolve_vads:
            return obj.NoneObject("vads not available right now")

        try:
            # Prevent recursively calling ourselves. We might resolve Prototype
            # PTEs which end up calling plugins (like the VAD plugin) which
            # might recursively translate another Vad Prototype address. This
            # safety below ensures we cant get into infinite recursion by
            # failing more complex PTE resolution on recursive calls.
            self._resolve_vads = False

            # Try to map the dtb to a task struct so we can look up the vads.
            if self.task == None:
                # Find the _EPROCESS for this dtb - we need to consult the VAD
                # for some of the address transition.
                self.task = self.session.GetParameter("dtb2task").get(self.dtb)

            self._vad = utils.RangedCollection()
            task = self.session.profile._EPROCESS(self.task)
            for vad in task.RealVadRoot.traverse():
                self._vad.insert(vad.Start, vad.End, vad)

            return self._vad
        finally:
            self._resolve_vads = True

    def _get_available_PTEs(self, pte_table, vaddr, start=0, end=2**64):
        """Scan the PTE table and yield address ranges which are valid."""
        tmp = vaddr
        for i in xrange(0, len(pte_table)):
            pfn = i << 12
            pte_value = pte_table[i]

            vaddr = tmp | pfn
            if vaddr > end:
                return

            next_vaddr = tmp | ((i + 1) << 12)
            if start >= next_vaddr:
                continue

            # A PTE value of 0 means to consult the vad, but the vad shows no
            # mapping at this virtual address, so we can just skip this PTE in
            # the iteration.
            if self.vad:
                start, _, _ = self.vad.get_containing_range(vaddr)
                if pte_value == 0 and start is None:
                    continue

            elif pte_value == 0:
                continue

            phys_addr = self._get_phys_addr_from_pte(vaddr, pte_value)

            # Only yield valid physical addresses. This will skip DemandZero
            # pages and File mappings into the filesystem.
            if phys_addr is not None:
                yield addrspace.Run(start=vaddr,
                                    end=vaddr + 0x1000,
                                    file_offset=phys_addr,
                                    address_space=self.base)

    def _get_phys_addr_from_pte(self, vaddr, pte_value):
        """Gets the final physical address from the PTE value."""
        collection = intel.PhysicalAddressDescriptorCollector(self.session)
        self.describe_pte(collection, None, pte_value, vaddr)
        return collection.physical_address

    def _describe_pde(self, collection, pde_addr, vaddr):
        """Describe processing of the PDE.

        The PDE is sometimes not present in main memory, we then implement most
        of the algorithm described in Figure 2 of the paper (except for the
        prototype state since the PDE can not use a prototype).
        """
        pde_value = self.read_pte(pde_addr)

        # PDE is valid or in transition:
        if pde_value & self.transition_valid_mask:
            collection.add(WindowsPDEDescriptor, pte_value=pde_value,
                           pte_addr=pde_addr)

            # PDE refers to a valid large page.
            if pde_value & self.valid_mask and  pde_value & self.page_size_mask:
                physical_address = ((pde_value & 0xfffffffe00000) |
                                    (vaddr & 0x1fffff))
                collection.add(intel.CommentDescriptor, "Large page mapped\n")

                collection.add(
                    intel.PhysicalAddressDescriptor, address=physical_address)

            # PDE is mapped in - just read the PTE.
            else:
                pte_addr = ((pde_value & 0xffffffffff000) |
                            ((vaddr & 0x1ff000) >> 9))
                pte_value = self.read_pte(pte_addr)
                self.describe_pte(collection, pte_addr, pte_value, vaddr)

        # PDE is paged out into a valid pagefile address.
        elif pde_value & self.soft_pagefilehigh_mask:
            collection.add(WindowsPDEDescriptor, pte_value=pde_value,
                           pte_addr=pde_addr, pte_type="Soft")

            pde = self.session.profile._MMPTE()
            pde.u.Long = pde_value

            # This is the address in the pagefile where the PDE resides.
            soft_pte = pde.u.Soft
            pagefile_address = (soft_pte.PageFileHigh * 0x1000 +
                                ((vaddr & 0x1ff000) >> 9))

            protection = soft_pte.Protection.v()
            if protection == 0:
                collection.add(intel.InvalidAddress, "Invalid Soft PTE")
            else:
                collection.add(WindowsPagefileDescriptor,
                               address=pagefile_address,
                               protection=protection,
                               pagefile_number=pde.u.Soft.PageFileLow.v())

                # Try to make the pagefile into the base address space.
                pte_addr = self._get_pagefile_mapped_address(
                    soft_pte.PageFileLow.v(), pagefile_address)

                if pte_addr is not None:
                    pte_value = self.read_pte(pte_addr)
                    self.describe_pte(collection, pte_addr, pte_value, vaddr)

        else:
            collection.add(DemandZeroDescriptor)

    @Reentrant
    def _get_subsection_mapped_address(self, subsection_pte_address):
        """Map the subsection into the physical address space.

        Returns:
          The offset in the physical AS where this subsection PTE is mapped to.
        """
        if self.base_as_can_map_files:
            pte = self.session.profile._MMPTE(subsection_pte_address)
            subsection = pte.u.Subsect.Subsection
            subsection_base = subsection.SubsectionBase.v()

            filename = subsection.ControlArea.FilePointer.file_name_with_drive()
            if filename:
                # The offset within the file starts at the beginning sector of
                # the section object, plus one page for each PTE. A section
                # object has an array of PTEs - the first one is 0 pages from
                # the start of the section, and each other PTE is another page
                # into the file. So we calculate the total number of pages from
                # the array index of the subsection_pte_address that we were
                # given.
                file_offset = (
                    (subsection_pte_address -
                     subsection_base) * 0x1000 / pte.obj_size +
                    subsection.StartingSector * 512)

                return self.base.get_mapped_offset(filename, file_offset)

    def _get_pagefile_mapped_address(self, pagefile_number, pagefile_offset):
        """Map the required pagefile into the physical AS.

        Returns:
          the mapped address of the required offset in the physical AS.
        """
        if self.base_as_can_map_files:
            # If we are in the process of resolving the pagefiles, break
            # re-entrancy.
            if (self._resolving_pagefiles and
                    not self.session.HasParameter("pagefiles")):
                return

            # If we have the pagefile we can just read it now.
            try:
                self._resolving_pagefiles = True
                pagefile_name, _ = self.session.GetParameter("pagefiles")[
                    pagefile_number]
            except (KeyError, ValueError):
                return

            except RuntimeError:
                # Sometimes we cant recover the name of the pagefile because it
                # is paged. We just take a guess here.
                pagefile_name = ur"c:\pagefile.sys"

            finally:
                self._resolving_pagefiles = False

            # Try to make the pagefile into the base address space.
            return self.base.get_mapped_offset(pagefile_name, pagefile_offset)

    def _describe_vad_pte(self, collection, pte_addr, pte_value, vaddr):
        if self.vad:
            collection.add(intel.CommentDescriptor, "Consulting Vad: ")
            start, _, mmvad = self.vad.get_containing_range(vaddr)
            if start is not None:
                # If the MMVAD has PTEs resolve those..
                if "FirstPrototypePte" in mmvad.members:
                    pte = mmvad.FirstPrototypePte[(vaddr - start) >> 12]
                    collection.add(VadPteDescriptor,
                                   pte_value=pte_value, pte_addr=pte_addr,
                                   virtual_address=vaddr)

                    self.describe_proto_pte(
                        collection, pte.obj_offset, pte.u.Long.v(), vaddr)

                    return

                else:
                    collection.add(intel.CommentDescriptor,
                                   "Vad type {0}\n", mmvad.Tag)

        # Virtual address does not exist in any VAD region.
        collection.add(DemandZeroDescriptor)

    def ResolveProtoPTE(self, pte_value, vaddr):
        collection = intel.PhysicalAddressDescriptorCollector(self.session)
        self.describe_proto_pte(collection, 0, pte_value, vaddr)

        return collection.physical_address

    def describe_proto_pte(self, collection, pte_addr, pte_value, vaddr):
        """Describe the analysis of the prototype PTE.

        This essentially explains how we utilize the flow chart presented in [1]
        Figure 3.

        NOTE: pte_addr is given here in the kernel's Virtual Address Space since
        prototype PTEs are always allocated from pool.
        """
        if pte_value & self.transition_valid_mask:
            physical_address = (pte_value & 0xffffffffff000) | (vaddr & 0xfff)
            collection.add(WindowsValidPTEDescriptor,
                           pte_value=pte_value, pte_addr=self.vtop(pte_addr))

            collection.add(intel.PhysicalAddressDescriptor,
                           address=physical_address)

        # File mapping subsection PTE.
        elif pte_value & self.prototype_mask:
            collection.add(WindowsSubsectionPTEDescriptor,
                           pte_value=pte_value, pte_addr=pte_addr)

            # Try to map the file into the physical address space.
            file_mapping = self._get_subsection_mapped_address(pte_addr)
            if file_mapping is not None:
                # Add offset within the page.
                file_mapping += vaddr & 0xFFF
                collection.add(intel.PhysicalAddressDescriptor,
                               address=file_mapping)

        # PTE is paged out into a valid pagefile address.
        elif pte_value & self.soft_pagefilehigh_mask:
            pte = self.session.profile._MMPTE()
            pte.u.Long = pte_value

            # This is the address in the pagefle where the PTE resides.
            soft_pte = pte.u.Soft
            pagefile_address = soft_pte.PageFileHigh * 0x1000 + (vaddr & 0xFFF)
            protection = soft_pte.Protection.v()

            if protection == 0:
                collection.add(intel.InvalidAddress, "Invalid Soft PTE")
                return

            collection.add(WindowsPTEDescriptor,
                           pte_type="Soft", pte_value=pte_value,
                           pte_addr=pte_addr)

            collection.add(WindowsPagefileDescriptor,
                           address=pagefile_address,
                           protection=protection,
                           pagefile_number=pte.u.Soft.PageFileLow.v())

            # If we have the pagefile we can just read it now.
            physical_address = self._get_pagefile_mapped_address(
                soft_pte.PageFileLow.v(), pagefile_address)

            if physical_address is not None:
                collection.add(
                    intel.PhysicalAddressDescriptor, address=physical_address)

        else:
            collection.add(DemandZeroDescriptor)

    def describe_pte(self, collection, pte_addr, pte_value, vaddr):
        """Describe the initial analysis of the PTE.

        This essentially explains how we utilize the flow chart presented in [1]
        Figure 2.
        """
        if pte_value & self.transition_valid_mask:
            physical_address = (pte_value & 0xffffffffff000) | (vaddr & 0xfff)
            collection.add(WindowsValidPTEDescriptor,
                           pte_value=pte_value, pte_addr=pte_addr)

            collection.add(intel.PhysicalAddressDescriptor,
                           address=physical_address)

        # PTE Type is not known - we need to look it up in the vad. This case is
        # triggered when the PTE ProtoAddress field is 0xffffffff - it means to
        # consult the vad. An example PTE value is 0xffffffff00000420.
        elif pte_value & self.prototype_mask:
            if ((self.proto_protoaddress_mask & pte_value) >>
                    self.proto_protoaddress_start in (0xffffffff0000,
                                                      0xffffffff)):

                collection.add(WindowsSoftwarePTEDescriptor,
                               pte_value=pte_value, pte_addr=pte_addr)

                self._describe_vad_pte(collection, pte_addr, pte_value, vaddr)

            else:
                collection.add(WindowsProtoTypePTEDescriptor,
                               pte_value=pte_value, pte_addr=pte_addr)

                # This PTE points at the prototype PTE in
                # pte.ProtoAddress. NOTE: The prototype PTE address is specified
                # in the kernel's address space since it is allocated from pool.
                pte_addr = pte_value >> self.proto_protoaddress_start
                pte_value = struct.unpack("<Q", self.read(pte_addr, 8))[0]

                self.describe_proto_pte(collection, pte_addr, pte_value, vaddr)

        # Case 2 of consult VAD: pte.u.Soft.PageFileHigh == 0.
        elif pte_value & self.soft_pagefilehigh_mask == 0:
            collection.add(WindowsSoftwarePTEDescriptor,
                           pte_value=pte_value, pte_addr=pte_addr)

            self._describe_vad_pte(collection, pte_addr, pte_value, vaddr)

        # PTE is demand zero.
        elif (pte_value >> 12) == 0:
            collection.add(DemandZeroDescriptor)

        # PTE is paged out into a valid pagefile address.
        elif pte_value & self.soft_pagefilehigh_mask:
            pte = self.session.profile._MMPTE()
            pte.u.Long = pte_value

            # This is the address in the pagefle where the PTE resides.
            soft_pte = pte.u.Soft
            pagefile_address = soft_pte.PageFileHigh * 0x1000 + (vaddr & 0xFFF)
            protection = soft_pte.Protection.v()
            if protection == 0:
                collection.add(intel.InvalidAddress, "Invalid Soft PTE")
                return

            collection.add(WindowsPTEDescriptor,
                           pte_type="Soft", pte_value=pte_value,
                           pte_addr=pte_addr)

            collection.add(WindowsPagefileDescriptor,
                           address=pagefile_address,
                           protection=soft_pte.Protection,
                           pagefile_number=pte.u.Soft.PageFileLow.v())

            physical_address = self._get_pagefile_mapped_address(
                soft_pte.PageFileLow.v(), pagefile_address)

            # If we have the pagefile we can just read it now.
            if physical_address is not None:
                collection.add(
                    intel.PhysicalAddressDescriptor, address=physical_address)

        else:
            # Fallback
            collection.add(intel.AddressTranslationDescriptor,
                           object_name="pte", object_value=pte_value,
                           object_address=pte_addr)

            collection.add(intel.CommentDescriptor, "Error! Unknown PTE\n")

    def _get_pte_addr(self, vaddr, pde_value):
        if pde_value & self.transition_valid_mask:
            return (pde_value & 0xffffffffff000) | ((vaddr & 0x1ff000) >> 9)

        if pde_value & self.soft_pagefilehigh_mask:
            pde = self.session.profile._MMPTE()
            pde.u.Long = pde_value
            soft_pte = pde.u.Soft

            # This is the address in the pagefle where the PDE resides.
            pagefile_address = (soft_pte.PageFileHigh * 0x1000 +
                                ((vaddr & 0x1ff000) >> 9))

            physical_address = self._get_pagefile_mapped_address(
                soft_pte.PageFileLow.v(), pagefile_address)

            return physical_address


class WindowsIA32PagedMemoryPae(WindowsPagedMemoryMixin,
                                intel.IA32PagedMemoryPae):
    """A Windows specific IA32PagedMemoryPae."""

    __pae = True


class WindowsAMD64PagedMemory(WindowsPagedMemoryMixin,
                              amd64.AMD64PagedMemory):
    """A windows specific AMD64PagedMemory.

    Implements support for reading the pagefile if the base address space
    contains a pagefile.
    """


class Pagefiles(common.WindowsCommandPlugin):
    """Report all the active pagefiles."""

    name = "pagefiles"

    table_header = [
        dict(name='_MMPAGING_FILE', style="address"),
        dict(name='number', align="r", width=3),
        dict(name='size', align="r", width=10),
        dict(name='filename', width=20),
    ]

    def collect(self):
        for pf_num, (pf_name, pf) in self.session.GetParameter(
                "pagefiles").items():
            pf = self.profile._MMPAGING_FILE(pf)
            yield (pf, pf_num, pf.Size * 0x1000, pf_name)


class PagefileHook(common.AbstractWindowsParameterHook):
    """Map pagefile number to the filename."""

    name = "pagefiles"

    def calculate(self):
        result = {}
        pagingfiles = self.session.profile.get_constant_object(
            'MmPagingFile',
            target='Array', target_args=dict(
                target='Pointer',
                count=16,
                target_args=dict(
                    target='_MMPAGING_FILE'
                    )
                )
            )

        # In windows 10, the pagefiles are stored in an AVL Tree.
        if pagingfiles == None:
            mistate = self.session.address_resolver.get_constant_object(
                "nt!MiState", "_MI_SYSTEM_INFORMATION")

            root = mistate.PagingIo.PageFileHead.Root
            pagingfiles = root.traverse_as_type(
                "_MMPAGING_FILE", "FileObjectNode")

        for pf in pagingfiles:
            if pf:
                result[pf.PageFileNumber.v()] = (
                    pf.File.file_name_with_drive(), pf.v())

        return result
