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

from rekall import testlib
from rekall import obj
from rekall import plugin
from rekall.plugins import core
from rekall.plugins.windows import common
from rekall.plugins.overlays import basic

class ValueEnumeration(basic.Enumeration):
    """An enumeration which receives its value from a callable."""

    def __init__(self, value=None, parent=None, **kwargs):
        super(ValueEnumeration, self).__init__(parent=parent, **kwargs)
        if callable(value):
            value = value(parent)

        self.value = value

    def v(self, vm=None):
        return self.value


class PFNModification(obj.ProfileModification):
    """Installs types specific to the PFN database."""

    @classmethod
    def modify(cls, profile):
        # Some shortcuts to the most important information.
        profile.add_overlay({
            '_MMPTE': [None, {
                'Valid': lambda x: x.u.Hard.Valid,
                'PFN': lambda x: x.u.Hard.PageFrameNumber,
                }],
            '_MMPFN': [None, {
                "Type": [0, ["ValueEnumeration", dict(
                    value=lambda x: x.u3.e1.PageLocation,
                    choices={
                        0: 'ZeroedPageList',
                        1: 'FreePageList',
                        2: 'StandbyPageList',
                        3: 'ModifiedPageList',
                        4: 'ModifiedNoWritePageList',
                        5: 'BadPageList',
                        6: 'ActiveAndValid',
                        7: 'TransitionPage'
                        }
                    )]],
                }],
            '_KDDEBUGGER_DATA64': [None, {
                # This is the pointer to the PFN database.
                'MmPfnDatabase': [None, ['Pointer', dict(
                    target="Pointer",
                    target_args=dict(
                        target="Array",
                        target_args=dict(target="_MMPFN"),
                        ))]],
                }],
            })
        profile.add_classes({
            "ValueEnumeration": ValueEnumeration,
            })


class VtoP(core.VtoPMixin, common.WinProcessFilter):
    """Prints information about the virtual to physical translation."""


class PFNInfo(common.WindowsCommandPlugin):
    """Prints information about an address from the PFN database."""

    __name = "pfn"

    # Size of page.
    PAGE_SIZE = 0x1000
    PAGE_BITS = 12

    @classmethod
    def args(cls, parser):
        super(PFNInfo, cls).args(parser)
        parser.add_argument("pfn", type="IntParser",
                            help="The PFN to examine.")

    def __init__(self, pfn=None, physical_address=None, **kwargs):
        """Prints information about the physical PFN entry.

        Args:
          pfn: A page file number to display.
          physical_address: The physical address to print information about.
        """
        super(PFNInfo, self).__init__(**kwargs)

        self.profile = PFNModification(self.profile)

        # A reference to the pfn database.
        self.pfn_database = self.profile.get_constant_object(
            "MmPfnDatabase",
            target="Pointer",
            target_args=dict(
                target="Array",
                target_args=dict(
                    target="_MMPFN",
                    )
                )
            )

        self.pfn = pfn
        self.physical_address = physical_address

    def pfn_record(self, pfn=None, physical_address=None):
        """Returns the pfn record for a pfn or a virtual address."""
        if physical_address is not None:
            pfn = int(physical_address) / self.PAGE_SIZE

        if pfn is None:
            raise RuntimeError("PFN not provided.")

        # Return the pfn record.
        return self.pfn_database.deref()[pfn]

    def render(self, renderer):
        pfn = self.pfn
        if pfn is None:
            raise plugin.PluginError("PFN not provided.")

        if self.physical_address is not None:
            pfn = int(self.physical_address) / self.PAGE_SIZE

        pfn_obj = self.pfn_record(pfn)

        renderer.format("    PFN {0:style=address} at "
                        "kernel address {1:addrpad}\n",
                        pfn, pfn_obj.obj_offset)

        # The flags we are going to print.
        flags = {"M": "Modified",
                 "P": "ParityError",
                 "R": "ReadInProgress",
                 "W": "WriteInProgress"}

        short_flags_string = "".join(
            [k for k, v in flags.items() if pfn_obj.u3.e1.m(v) == 0])

        long_flags_string = " ".join(
            [v for k, v in flags.items() if pfn_obj.u3.e1.m(v) == 0])

        containing_page = int(pfn_obj.u4.PteFrame)
        pte_physical_address = ((containing_page << self.PAGE_BITS) |
                                (int(pfn_obj.PteAddress) & 0xFFF))

        renderer.format("""    flink  {0:addr}  blink / share count {1:addr}
    pteaddress (VAS) {2:addrpad}  (Phys AS) {3:addr}
    reference count {4:addr}   color {5}
    containing page        {6:addr}  {7}     {8}
    {9}
    """, pfn_obj.u1.Flink, pfn_obj.u2.Blink,
                        pfn_obj.PteAddress,
                        pte_physical_address,
                        pfn_obj.u3.e2.ReferenceCount,
                        pfn_obj.u3.e1.m("PageColor") or
                        pfn_obj.u4.m("PageColor"),
                        containing_page,
                        pfn_obj.Type,
                        short_flags_string,
                        long_flags_string)


class PtoV(common.WinProcessFilter):
    """Converts a physical address to a virtual address."""

    __name = "ptov"

    PAGE_SIZE = 0x1000
    PAGE_BITS = 12

    @classmethod
    def args(cls, parser):
        super(PtoV, cls).args(parser)
        parser.add_argument("physical_address", type="IntParser",
                            help="The Virtual Address to examine.")

    def __init__(self, physical_address=None, **kwargs):
        """Converts a physical address to a virtual address."""
        super(PtoV, self).__init__(**kwargs)

        # Get a handle to the pfninfo plugin
        self.pfn_plugin = self.session.plugins.pfn(session=self.session)
        self.physical_address = physical_address

    def _ptov_x86(self, physical_address):
        """An implementation of ptov for x86."""
        result = physical_address & 0xFFF

        # Get the pte for this physical_address using the pfn database.
        pfn_obj = self.pfn_plugin.pfn_record(physical_address >> self.PAGE_BITS)

        if pfn_obj.Type != "ActiveAndValid":
            return obj.NoneObject("PTE invalid."), []

        containing_page = int(pfn_obj.u4.PteFrame)
        pte_address = ((containing_page << self.PAGE_BITS) |
                       (int(pfn_obj.PteAddress) & 0xFFF))

        result |= (pte_address << 10) & 0x3FF000

        # Get the PDE now:
        pfn_obj = self.pfn_plugin.pfn_record(containing_page)

        if pfn_obj.Type != "ActiveAndValid":
            return obj.NoneObject("PDE invalid (Is this a large page?)."), []

        containing_page = int(pfn_obj.u4.PteFrame)
        pde_address = ((containing_page << self.PAGE_BITS) |
                       (int(pfn_obj.PteAddress) & 0xFFF))

        result |= (pde_address << 20) & 0xffc00000

        # Now get the DTB.
        pfn_obj = self.pfn_plugin.pfn_record(containing_page)

        containing_page = int(pfn_obj.u4.PteFrame)
        dtb_address = containing_page << self.PAGE_BITS

        return result, (("DTB", dtb_address),
                        ("PDE", pde_address),
                        ("PTE", pte_address))

    def _ptov_x86_pae(self, physical_address):
        """An implementation of ptov for x86 pae."""
        result = physical_address & 0xFFF
        # Get the pte for this physical_address using the pfn database.
        pfn_obj = self.pfn_plugin.pfn_record(physical_address >> self.PAGE_BITS)

        if pfn_obj.Type != "ActiveAndValid":
            return obj.NoneObject("PTE invalid."), []

        containing_page = int(pfn_obj.u4.PteFrame)
        pte_address = ((containing_page << self.PAGE_BITS) |
                       (int(pfn_obj.PteAddress) & 0xFFF))

        result |= (pte_address << 9) & 0x1FF000

        # Get the PDE now:
        pfn_obj = self.pfn_plugin.pfn_record(containing_page)

        if pfn_obj.Type != "ActiveAndValid":
            return obj.NoneObject("PDE invalid (Is this a large page?)."), []

        containing_page = int(pfn_obj.u4.PteFrame)
        pde_address = ((containing_page << self.PAGE_BITS) |
                       (int(pfn_obj.PteAddress) & 0xFFF))

        result |= (pde_address << 18) & 0x3fe00000

        # Get the PDPTE now:
        pfn_obj = self.pfn_plugin.pfn_record(containing_page)

        if pfn_obj.Type != "ActiveAndValid":
            return obj.NoneObject(
                "PDPTE invalid (Is this a one gig page?)."), []

        containing_page = int(pfn_obj.u4.PteFrame)
        pdpte_address = ((containing_page << self.PAGE_BITS) |
                         (int(pfn_obj.PteAddress) & 0xFFF))

        result |= (pdpte_address << 27) & 0x7FC0000000

        # Now get the DTB.
        pfn_obj = self.pfn_plugin.pfn_record(containing_page)

        containing_page = int(pfn_obj.u4.PteFrame)
        dtb_address = containing_page << self.PAGE_BITS

        return result, (("DTB", dtb_address),
                        ("PDPTE", pdpte_address),
                        ("PDE", pde_address),
                        ("PTE", pte_address))

    def _ptov_x64(self, physical_address):
        """An implementation of ptov for x64."""
        result = physical_address & 0xFFF

        # Get the pte for this physical_address using the pfn database.
        pfn_obj = self.pfn_plugin.pfn_record(physical_address >> self.PAGE_BITS)

        if pfn_obj.Type != "ActiveAndValid":
            return obj.NoneObject("PTE invalid."), []

        containing_page = int(pfn_obj.u4.PteFrame)
        pte_address = ((containing_page << self.PAGE_BITS) |
                       (int(pfn_obj.PteAddress) & 0xFFF))

        result |= (pte_address << 9) & 0x1FF000

        # Get the PDE now:
        pfn_obj = self.pfn_plugin.pfn_record(containing_page)

        if pfn_obj.Type != "ActiveAndValid":
            return obj.NoneObject("PDE invalid (Is this a large page?)."), []

        containing_page = int(pfn_obj.u4.PteFrame)
        pde_address = ((containing_page << self.PAGE_BITS) |
                       (int(pfn_obj.PteAddress) & 0xFFF))

        result |= (pde_address << 18) & 0x3fe00000

        # Get the PDPTE now:
        pfn_obj = self.pfn_plugin.pfn_record(containing_page)

        if pfn_obj.Type != "ActiveAndValid":
            return obj.NoneObject(
                "PDPTE invalid (Is this a one gig page?)."), []

        containing_page = int(pfn_obj.u4.PteFrame)
        pdpte_address = ((containing_page << self.PAGE_BITS) |
                         (int(pfn_obj.PteAddress) & 0xFFF))

        result |= (pdpte_address << 27) & 0x7FC0000000

        # Get the PML4E now:
        pfn_obj = self.pfn_plugin.pfn_record(containing_page)

        if pfn_obj.Type != "ActiveAndValid":
            return obj.NoneObject("PML4E invalid."), []

        containing_page = int(pfn_obj.u4.PteFrame)
        pml4e_address = ((containing_page << self.PAGE_BITS) |
                         (int(pfn_obj.PteAddress) & 0xFFF))

        result |= (pml4e_address << 36) & 0xff8000000000

        # Now get the DTB.
        pfn_obj = self.pfn_plugin.pfn_record(containing_page)

        containing_page = int(pfn_obj.u4.PteFrame)
        dtb_address = containing_page << self.PAGE_BITS

        return result, (("DTB", dtb_address),
                        ("PML4E", pml4e_address),
                        ("PDPTE", pdpte_address),
                        ("PDE", pde_address),
                        ("PTE", pte_address))

    def ptov(self, physical_address):
        """Convert the physical address to a virtual address.

        Returns:
          a tuple (_EPROCESS of owning process, virtual address in process AS).
        """
        if self.profile.metadata("arch") == "I386":
            if self.profile.metadata("pae"):
                return self._ptov_x86_pae(physical_address)
            else:
                return self._ptov_x86(physical_address)
        elif self.profile.metadata("arch") == "AMD64":
            return self._ptov_x64(physical_address)

        return obj.NoneObject("Memory model not supported."), []

    def render(self, renderer):
        if self.physical_address is None:
            return

        result, structures = self.ptov(self.physical_address)
        if result:
            renderer.format("Physical Address {0:#x} => "
                            "Virtual Address {1:#x}\n",
                            self.physical_address, result)

            for type, phys_addr in structures:
                renderer.format("{0} @ {1:#x}\n", type, phys_addr)
        else:
            renderer.format("Error converting Physical Address {0:#x}: "
                            "{1}\n", self.physical_address, result)


class DTBScan2(common.WindowsCommandPlugin):
    """A Fast scanner for hidden DTBs.

    This scanner uses the fact that the virtual address of the DTB is always the
    same. We walk over all the physical pages, assume each page is a DTB and try
    to resolve the constant to a physical address.

    This plugin was written based on ideas and discussion with thomasdullien.
    """

    name = "dtbscan2"

    def TestVAddr(self, test_as, vaddr, symbol_checks):
        for vaddr, paddr in symbol_checks:
            if test_as.vtop(vaddr) != paddr:
                return False
        return True

    def render(self, renderer):
        dtb_map = {}
        pslist_plugin = self.session.plugins.pslist()
        for task in pslist_plugin.filter_processes():
            dtb = task.Pcb.DirectoryTableBase.v()
            dtb_map[dtb] = task

        symbols = ["nt", "nt!MmGetPhysicalMemoryRanges"]
        if self.session.profile.metadata("arch") == "AMD64":
            dtb_step = 0x1000
            # Add _KUSER_SHARED_DATA
            symbols.append(0xFFFFF78000000000)
        else:
            dtb_step = 0x20
            symbols.append(0xFFDF0000)

        symbol_checks = []
        for symbol in symbols:
            vaddr = self.session.address_resolver.get_address_by_name(symbol)
            paddr = self.session.kernel_address_space.vtop(vaddr)
            symbol_checks.append((vaddr, paddr))

        renderer.table_header([("DTB", "dtb", "[addrpad]"),
                               dict(name="Process", type="_EPROCESS"),
                              ])

        descriptor = self.profile.get_constant_object(
            "MmPhysicalMemoryBlock",
            target="Pointer",
            target_args=dict(
                target="_PHYSICAL_MEMORY_DESCRIPTOR",
                ))

        for memory_range in descriptor.Run:
            start = memory_range.BasePage * 0x1000
            length = memory_range.PageCount * 0x1000

            for page in range(start, start+length, dtb_step):
                self.session.report_progress("Checking %#x", page)
                test_as = self.session.kernel_address_space.__class__(
                    dtb=page, base=self.physical_address_space)

                if self.TestVAddr(test_as, vaddr, symbol_checks):
                    renderer.table_row(
                        page,
                        dtb_map.get(page, obj.NoneObject("Unknown"))
                    )


class DTBScan(common.WinProcessFilter):
    """Scans the physical memory for DTB values.

    This plugin can compare the DTBs found against the list of known processes
    to find hidden processes.
    """

    __name = "dtbscan"

    @classmethod
    def args(cls, parser):
        super(DTBScan, cls).args(parser)
        parser.add_argument("--limit", type="IntParser", default=0,
                            help="Stop scanning after this many mb.")

    def __init__(self, limit=None, **kwargs):
        super(DTBScan, self).__init__(**kwargs)
        self.limit = limit

    def render(self, renderer):
        ptov = self.session.plugins.ptov(session=self.session)
        pslist = self.session.plugins.pslist(session=self.session)
        pfn_plugin = self.session.plugins.pfn(session=self.session)

        # Known tasks:
        known_tasks = set()
        for task in pslist.list_eprocess():
            known_tasks.add(task.obj_offset)

        renderer.table_header([("DTB", "dtb", "[addrpad]"),
                               ("VAddr", "vaddr", "[addrpad]"),
                               dict(type="_EPROCESS"),
                               ("Known", "known", "")])

        seen_dtbs = set()

        # Now scan all the physical address space for DTBs.
        for run in self.physical_address_space.get_mappings():
            for page in range(run.start, run.end, 0x1000):
                self.session.report_progress("Scanning 0x%08X (%smb)" % (
                    page, page/1024/1024))

                # Quit early if requested to.
                if self.limit and page > self.limit:
                    return

                virtual_address, results = ptov.ptov(page)
                if virtual_address:
                    dtb = results[0][1]
                    if dtb not in seen_dtbs:
                        seen_dtbs.add(dtb)

                        # The _EPROCESS address is stored as the
                        # KernelStackOwner for the pfn of this dtb.
                        task = pfn_plugin.pfn_record(
                            dtb >> 12).u1.Flink.cast(
                                "Pointer", target="_EPROCESS").deref()

                        va, _ = ptov.ptov(dtb)
                        renderer.table_row(dtb, va, task,
                                           task.obj_offset in known_tasks)

class TestDTBScan(testlib.SimpleTestCase):
    PARAMETERS = dict(
        commandline="dtbscan --limit 10mb",
        )
