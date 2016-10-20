# Rekall Memory Forensics
#
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Authors:
# Michael Cohen <scudette@gmail.com>
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

# References:
# http://www.codemachine.com/article_kernelstruct.html#MMPFN
# http://www.reactos.org/wiki/Techwiki:Memory_management_in_the_Windows_XP_kernel#MmPfnDatabase

# pylint: disable=protected-access
import re
import StringIO

from rekall import kb
from rekall import testlib
from rekall import plugin
from rekall import utils
from rekall.ui import text
from rekall.plugins import core
from rekall.plugins.addrspaces import intel
from rekall.plugins.windows import common
from rekall.plugins.windows import pagefile


class VtoP(core.VtoPMixin, common.WinProcessFilter):
    """Prints information about the virtual to physical translation."""


class PFNInfo(common.WindowsCommandPlugin):
    """Prints information about an address from the PFN database."""

    __name = "pfn"

    # Size of page.
    PAGE_SIZE = 0x1000
    PAGE_BITS = 12

    __args = [
        dict(name="pfn", type="IntParser", positional=True, required=True,
             help="The PFN to examine.")
    ]

    table_header = [
        dict(name="fact", width=25),
        dict(name="Address", style="address"),
        dict(name="Value"),
    ]


    def collect(self):
        pfn_obj = self.profile.get_constant_object("MmPfnDatabase")[
            self.plugin_args.pfn]

        yield "PFN", self.plugin_args.pfn
        yield "PFN Record VA", pfn_obj.obj_offset

        yield "Type", None, pfn_obj.Type

        # In these states the other fields are meaningless.
        if pfn_obj.Type in ("Zeroed", "Freed", "Bad"):
            yield "Flink", pfn_obj.u1.Flink
            yield "Blink", pfn_obj.u2.Blink

            return

        # The flags we are going to print.
        flags = ["Modified",
                 "ParityError",
                 "ReadInProgress",
                 "WriteInProgress"]

        long_flags_string = " ".join(
            [v for v in flags if pfn_obj.u3.e1.m(v) == 0])

        yield "Flags", None, long_flags_string

        containing_page = int(pfn_obj.u4.PteFrame)
        pte_physical_address = ((containing_page << self.PAGE_BITS) |
                                (int(pfn_obj.PteAddress) & 0xFFF))

        yield "Reference", None, pfn_obj.u3.e2.ReferenceCount
        yield "ShareCount", None, pfn_obj.u2.ShareCount
        yield "Color", None, pfn_obj.multi_m("u3.e1.PageColor", "u4.PageColor")

        yield "Controlling PTE (VA)", pfn_obj.PteAddress
        yield "Controlling PTE (PA)", pte_physical_address
        yield ("Controlling PTE Type", None,
               "Prototype" if pfn_obj.IsPrototype else "Hardware")

        # PFN is actually a DTB.
        if containing_page == self.plugin_args.pfn:
            owning_process = pfn_obj.u1.Flink.cast(
                "Pointer", target="_EPROCESS")

            yield "Owning process", owning_process

        # Now describe the PTE and Prototype PTE pointed to by this PFN entry.
        collection = intel.DescriptorCollection(self.session)
        self.session.kernel_address_space.describe_pte(
            collection, pfn_obj.PteAddress,
            pfn_obj.PteAddress.Long, 0)

        yield "Controlling PTE", None, collection

        if pfn_obj.OriginalPte:
            collection = intel.DescriptorCollection(self.session)
            self.session.kernel_address_space.describe_proto_pte(
                collection, pfn_obj.OriginalPte.v(),
                pfn_obj.OriginalPte.Long, 0)

            yield "Original PTE", None, collection


class PtoV(common.WinProcessFilter):
    """Converts a physical address to a virtual address."""

    __name = "ptov"

    PAGE_SIZE = 0x1000
    PAGE_BITS = 12

    __args = [
        dict(name="physical_address", type="IntParser", positional=True,
             help="The Virtual Address to examine.")
    ]

    def __init__(self, *args, **kwargs):
        super(PtoV, self).__init__(*args, **kwargs)

        if self.profile.metadata("arch") == "I386":
            if self.profile.metadata("pae"):
                self.table_names = ["Phys", "PTE", "PDE", "DTB"]
                self.bit_divisions = [12, 9, 9, 2]

            else:
                self.table_names = ["Phys", "PTE", "PDE", "DTB"]
                self.bit_divisions = [12, 10, 10]

        elif self.profile.metadata("arch") == "AMD64":
            self.table_names = ["Phys", "PTE", "PDE", "PDPTE", "PML4E", "DTB"]
            self.bit_divisions = [12, 9, 9, 9, 9, 4]

        else:
            raise plugin.PluginError("Memory model not supported.")

    def ptov(self, collection, physical_address):
        pfn_obj = self.profile.get_constant_object("MmPfnDatabase")[
            physical_address >> self.PAGE_BITS]

        # The PFN points at a prototype PTE.
        if pfn_obj.IsPrototype:
            collection.add(pagefile.WindowsFileMappingDescriptor,
                           pte_address=pfn_obj.PteAddress.v(),
                           page_offset=physical_address & 0xFFF,
                           original_pte=pfn_obj.OriginalPte)

        else:
            # PTE is a system PTE, we can directly resolve the virtual address.
            self._ptov_x64_hardware_PTE(collection, physical_address)

    def _ptov_x64_hardware_PTE(self, collection, physical_address):
        """An implementation of ptov for x64."""
        pfn_database = self.session.profile.get_constant_object("MmPfnDatabase")

        # A list of PTEs and their physical addresses.
        physical_addresses = dict(Phys=physical_address)

        # The physical and virtual address of the pte that controls the named
        # member.
        phys_addresses_of_pte = {}
        ptes = {}
        p_addr = physical_address
        pfns = {}

        # Starting with the physical address climb the PFN database in reverse
        # to reach the DTB. At each page table entry we store the its physical
        # offset. Then below we traverse the page tables in the forward order
        # and add the bits into the virtual address.
        for i, name in enumerate(self.table_names):
            pfn = p_addr >> self.PAGE_BITS
            pfns[name] = pfn_obj = pfn_database[pfn]

            # The PTE which controls this pfn.
            pte = pfn_obj.PteAddress

            # PTE is not valid - this may be a large page. We dont currently
            # know how to handle large pages.
            #if not pte.u.Hard.Valid:
            #    return

            if i > 0:
                physical_addresses[name] = ptes[
                    self.table_names[i-1]].obj_offset

            # The physical address of the PTE.
            p_addr = ((pfn_obj.u4.PteFrame << self.PAGE_BITS) |
                      (pte.v() & 0xFFF))

            phys_addresses_of_pte[name] = p_addr

            # Hold on to the PTE in the physical AS. This is important as it
            # ensures we can always access the correct PTE no matter the process
            # context.
            ptes[name] = self.session.profile._MMPTE(
                p_addr, vm=self.session.physical_address_space)

            self.session.logging.getChild("PageTranslation").debug(
                "%s %#x is controlled by pte %#x (PFN %#x)",
                name, physical_addresses[name], ptes[name], pfns[name])

        # The DTB must be page aligned.
        dtb = p_addr & ~0xFFF

        # Now we construct the virtual address by locating the offset in each
        # page table where the PTE is and deducing the bits covered within that
        # range.
        virtual_address = 0
        start_of_page_table = dtb
        size_of_pte = self.session.profile._MMPTE().obj_size

        for name, bit_division in reversed(zip(
                self.table_names, self.bit_divisions)):
            pte = ptes[name]
            virtual_address += (
                ptes[name].obj_offset - start_of_page_table) / size_of_pte

            virtual_address <<= bit_division

            # The physical address where the page table begins. The next
            # iteration will find the offset of the next higher up page table
            # level in this table.
            start_of_page_table = pte.u.Hard.PageFrameNumber << self.PAGE_BITS

            if name == "Phys":
                collection.add(intel.PhysicalAddressDescriptor,
                               address=physical_address)

            elif name == "DTB":
                # The DTB must be page aligned.
                collection.add(pagefile.WindowsDTBDescriptor,
                               dtb=physical_addresses["DTB"] & ~0xFFF)

            else:
                collection.add(pagefile.WindowsPTEDescriptor,
                               object_name=name, pte_value=pte.Long,
                               pte_addr=pte.obj_offset, session=self.session)

        virtual_address = self.session.profile.integer_to_address(
            virtual_address)
        virtual_address += physical_address & 0xFFF

        collection.add(intel.VirtualAddressDescriptor, dtb=dtb,
                       address=virtual_address)

    def render(self, renderer):
        if self.plugin_args.physical_address is None:
            return

        descriptors = intel.DescriptorCollection(self.session)
        self.ptov(descriptors, self.plugin_args.physical_address)

        for descriptor in descriptors:
            descriptor.render(renderer)


class WinRammap(common.WindowsCommandPlugin):
    """Scan all physical memory and report page owners."""

    name = "rammap"

    __args = [
        dict(name="start", type="IntParser", default=0, positional=True,
             help="Physical memory address to start displaying."),
        dict(name="end", type="IntParser",
             help="Physical memory address to end displaying."),
    ]

    table_header = [
        dict(name="phys_offset", max_depth=1,
             type="TreeNode", child=dict(style="address", align="l"),
             width=16),
        dict(name="List", width=10),
        dict(name="Use", width=15),
        dict(name="Pr", width=2),
        dict(name="Process", type="_EPROCESS"),
        dict(name="VA", style="address"),
        dict(name="Offset", style="address"),
        dict(name="Filename"),
    ]

    def __init__(self, *args, **kwargs):
        super(WinRammap, self).__init__(*args, **kwargs)
        self.plugin_args.start &= ~0xFFF
        self.ptov_plugin = self.session.plugins.ptov()
        self.pfn_database = self.session.profile.get_constant_object(
            "MmPfnDatabase")
        self.pools = self.session.plugins.pools()

    def describe_phys_addr(self, phys_off):
        pfn_obj = self.pfn_database[phys_off >> 12]

        collection = intel.DescriptorCollection(self.session)
        self.ptov_plugin.ptov(collection, phys_off)
        result = dict(phys_offset=phys_off,
                      List=pfn_obj.Type,
                      Pr=pfn_obj.Priority)

       # Go through different kinds of use and display them in the table.
        descriptor = collection["VirtualAddressDescriptor"]
        if descriptor:
            dtb_descriptor = collection["WindowsDTBDescriptor"]
            # Address is in kernel space.
            if descriptor.address > self.session.GetParameter(
                    "highest_usermode_address"):
                _, _, pool = self.pools.is_address_in_pool(descriptor.address)
                if pool:
                    yield dict(Use=pool.PoolType,
                               VA=descriptor.address, **result)
                else:
                    yield dict(Use="Kernel",
                               VA=descriptor.address, **result)
            else:
                yield dict(Use="Private",
                           Process=dtb_descriptor.owner(),
                           VA=descriptor.address, **result)

            return

        descriptor = collection["WindowsFileMappingDescriptor"]
        if descriptor:
            subsection = descriptor.get_subsection()
            filename, file_offset = descriptor.filename_and_offset(
                subsection=subsection)

            # First show the owner that mapped the file.
            virtual_address = None

            depth = 0
            # A real mapped file.
            for process, virtual_address in descriptor.get_owners(
                    subsection=subsection):

                yield dict(Use="Mapped File",
                           Filename=filename,
                           Offset=file_offset,
                           depth=depth,
                           Process=process,
                           VA=virtual_address, **result)

                if self.plugin_args.verbosity <= 1:
                    return

                # If the user wants more, also show the other processes which
                # map this file.
                depth = 1

            # We could not find a process owner so we just omit it.
            if depth == 0:
                yield dict(Use="Mapped File",
                           Filename=filename,
                           Offset=file_offset,
                           **result)
                return

        if pfn_obj.u3.e2.ReferenceCount == 0:
            result["Use"] = "Unused"
            yield result
            return

        yield result

    def collect(self):
        phys_off = self.plugin_args.start

        end = self.plugin_args.end
        if end is None or end < phys_off:
            end = phys_off + 10 * 0x1000

        for phys_off in utils.xrange(self.plugin_args.start, end, 0x1000):
            for result in self.describe_phys_addr(phys_off):
                yield result

        # Re-run from here next invocation.
        self.plugin_args.start = phys_off

    def summary(self):
        """Return a multistring summary of the result."""
        # We just use the WideTextRenderer to render the records.
        fd = StringIO.StringIO()
        with text.WideTextRenderer(session=self.session, fd=fd) as renderer:
            self.render(renderer)

        return filter(None,
                      re.split(r"(^|\n)\*+\n", fd.getvalue(), re.S | re.M))


class TestWinRammap(testlib.SimpleTestCase):
    PARAMETERS = dict(
        commandline="rammap %(start)s",
        start=0x4d7000,
    )


class DTBScan(common.WinProcessFilter):
    """Scans the physical memory for DTB values.

    This plugin can compare the DTBs found against the list of known processes
    to find hidden processes.
    """

    __name = "dtbscan"

    __args = [
        dict(name="limit", type="IntParser", default=2**64,
             help="Stop scanning after this many mb.")
    ]

    table_header = [
        dict(name="DTB", style="address"),
        dict(name="VA", style="address"),
        dict(name="Owner", type="_EPROCESS"),
        dict(name="Known", type="Bool"),
    ]

    def collect(self):
        ptov = self.session.plugins.ptov(session=self.session)
        pslist = self.session.plugins.pslist(session=self.session)
        pfn_database = self.session.profile.get_constant_object("MmPfnDatabase")

        # Known tasks:
        known_tasks = set()
        for task in pslist.list_eprocess():
            known_tasks.add(task.obj_offset)

        seen_dtbs = set()

        # Now scan all the physical address space for DTBs.
        for run in self.physical_address_space.get_mappings():
            for page in range(run.start, run.end, 0x1000):
                self.session.report_progress("Scanning 0x%08X (%smb)" % (
                    page, page/1024/1024))

                # Quit early if requested to.
                if page > self.plugin_args.limit:
                    return

                collection = intel.DescriptorCollection(self.session)
                ptov.ptov(collection, page)
                dtb_descriptor = collection["WindowsDTBDescriptor"]

                if dtb_descriptor:
                    dtb = dtb_descriptor.dtb
                    if dtb not in seen_dtbs:
                        seen_dtbs.add(dtb)

                        pfn_obj = pfn_database[dtb >> 12]

                        # Report the VA of the DTB (Since DTBs contains
                        # themselves this will equal to the VA of the DTB.
                        va = pfn_obj.PteAddress.v()
                        task = dtb_descriptor.owner()

                        yield (dtb, va, task,
                               task.obj_offset in known_tasks)


class TestDTBScan(testlib.SimpleTestCase):
    PARAMETERS = dict(
        commandline="dtbscan --limit 10mb",
        )


class WinSubsectionProducer(kb.ParameterHook):
    """Produce all the subsection objects we know about.

    Returns a dict keyed with subsection offsets with values being a details
    dict. The details include the vad and the _EPROCESS address for this
    process.
    """
    name = "subsections"

    def calculate(self):
        result = {}
        for task in self.session.plugins.pslist().filter_processes():
            self.session.report_progress("Inspecting VAD for %s", task.name)
            for vad in task.RealVadRoot.traverse():
                subsection_list = vad.multi_m(
                    "Subsection", "ControlArea.FirstSubsection")
                for subsection in subsection_list.walk_list(
                        "NextSubsection", include_current=True):
                    record = result.setdefault(subsection.obj_offset, [])
                    record.append(dict(task=task.obj_offset,
                                       vad=vad.obj_offset,
                                       type=vad.obj_type))
        return result


class WinPrototypePTEArray(kb.ParameterHook):
    """A ranged collection for Prototype PTE arrays."""

    name = "prototype_pte_array_subsection_lookup"

    def calculate(self):
        result = utils.RangedCollection()
        for subsection_offset in self.session.GetParameter("subsections"):
            subsection = self.session.profile._SUBSECTION(subsection_offset)
            start = subsection.SubsectionBase.v()

            # Pte Arrays are always allocated from kernel pools.
            if start < self.session.GetParameter("highest_usermode_address"):
                continue

            end = start + (subsection.PtesInSubsection *
                           subsection.SubsectionBase[0].obj_size)
            result.insert(start, end, subsection_offset)

        return result
