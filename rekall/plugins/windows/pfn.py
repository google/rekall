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

from rekall import config
from rekall import testlib
from rekall import obj
from rekall import plugin
from rekall.plugins.windows import common
from rekall.plugins.overlays import basic

class ValueEnumeration(basic.Enumeration):
    """An enumeration which receives its value from a callable."""

    def __init__(self, choices=None, value=None, parent=None, **kwargs):
        super(ValueEnumeration, self).__init__(parent=parent, **kwargs)
        self.choices = choices
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


class VtoP(plugin.KernelASMixin, plugin.ProfileCommand):
    """Prints information about the virtual to physical translation."""

    __name = "vtop"

    PAGE_SIZE = 0x1000

    @classmethod
    def args(cls, parser):
        super(VtoP, cls).args(parser)
        parser.add_argument("virtual_address", action=config.IntParser,
                            help="Specify to see all the fops, even if they "
                            "are known.")

    def __init__(self, virtual_address=None, address_space=None, **kwargs):
        """Prints information about the virtual to physical translation.

        This is similar to windbg's !vtop extension.

        Args:
          virtual_address: The virtual address to describe.
          address_space: The address space to use (default the
            kernel_address_space).
        """
        super(VtoP, self).__init__(**kwargs)
        self.address_space = address_space or self.kernel_address_space
        self.address = virtual_address

    def _vtop_32bit(self, vaddr, address_space):
        """An implementation specific to the 32 bit intel address space."""
        pde_addr = ((address_space.dtb & 0xfffff000) |
                    ((vaddr & 0xffc00000) >> 20))

        pde_value = address_space.read_long_phys(pde_addr)
        yield "pde", pde_value, pde_addr

        if not address_space.entry_present(pde_value):
            yield "Invalid PDE", None, None
            return

        if address_space.page_size_flag(pde_value):
            yield "Large page mapped", address_space.get_four_meg_paddr(
                vaddr, pde_value), None
            return

        pte_addr = (pde_value & 0xfffff000) | ((vaddr & 0x3ff000) >> 10)
        pte_value = address_space.read_long_phys(pte_addr)
        yield "pte", pte_value, pte_addr

        if not address_space.entry_present(pde_value):
            yield "Invalid PTE", None, None
            return

        yield ("PTE mapped",
               address_space.get_phys_addr(vaddr, pte_value),
               pte_addr)

    def _vtop_32bit_pae(self, vaddr, address_space):
        """An implementation specific to the 32 bit PAE intel AS."""
        pdpte_addr = ((address_space.dtb & 0xfffffff0) |
                      ((vaddr & 0x7FC0000000) >> 27))

        pdpte_value = address_space._read_long_long_phys(pdpte_addr)
        yield "pdpte", pdpte_value, pdpte_addr

        if not address_space.entry_present(pdpte_value):
            yield "Invalid PDPTE", None, None
            return

        pde_addr = (pdpte_value & 0xfffff000) | ((vaddr & 0x3fe00000) >> 18)
        pde_value = address_space.read_long_phys(pde_addr)
        yield "pde", pde_value, pde_addr

        if not address_space.entry_present(pde_value):
            yield "Invalid PDE", None, None
            return

        if address_space.page_size_flag(pde_value):
            yield "Large page mapped", address_space.get_four_meg_paddr(
                vaddr, pde_value), None
            return

        pte_addr = (pde_value & 0xfffff000) | ((vaddr & 0x1ff000) >> 9)
        pte_value = address_space.read_long_phys(pte_addr)
        yield "pte", pte_value, pte_addr

        if not address_space.entry_present(pde_value):
            yield "Invalid PTE", None, None
            return

        yield ("PTE mapped",
               address_space.get_phys_addr(vaddr, pte_value),
               pte_addr)

    def _vtop_64bit(self, vaddr, address_space):
        """An implementation specific to the 64 bit intel address space."""
        pml4e_addr = ((address_space.dtb & 0xffffffffff000) |
                      ((vaddr & 0xff8000000000) >> 36))

        pml4e_value = address_space._read_long_long_phys(pml4e_addr)
        yield "pml4e", pml4e_value, pml4e_addr

        if not address_space.entry_present(pml4e_value):
            yield "Invalid PDE", None, None
            return

        pdpte_addr = ((pml4e_value & 0xffffffffff000) |
                      ((vaddr & 0x7FC0000000) >> 27))

        pdpte_value = address_space._read_long_long_phys(pdpte_addr)
        yield "pdpte", pdpte_value, pdpte_addr

        if address_space.page_size_flag(pdpte_value):
            yield "One Gig page", address_space.get_one_gig_paddr(
                vaddr, pdpte_value), None
            return

        pde_addr = ((pdpte_value & 0xffffffffff000) |
                    ((vaddr & 0x3fe00000) >> 18))
        pde_value = address_space.read_long_phys(pde_addr)
        yield "pde", pde_value, pde_addr

        if not address_space.entry_present(pde_value):
            yield "Invalid PDE", None, None
            return

        if address_space.page_size_flag(pde_value):
            yield "Large page mapped", address_space.get_four_meg_paddr(
                vaddr, pde_value), None
            return

        pte_addr = (pde_value & 0xffffffffff000) | ((vaddr & 0x1ff000) >> 9)
        pte_value = address_space.read_long_phys(pte_addr)
        yield "pte", pte_value, pte_addr

        if not address_space.entry_present(pte_value):
            yield "Invalid PTE", None, None
            return

        yield ("PTE mapped",
               address_space.get_phys_addr(vaddr, pte_value),
               pte_addr)

    def vtop(self, virtual_address, address_space=None):
        """Translate the virtual_address using the address_space."""
        if address_space is None:
            address_space = self.kernel_address_space

        if address_space.metadata("arch") == "AMD64":
            function = self._vtop_64bit
        else:
            if address_space.metadata("pae"):
                function = self._vtop_32bit_pae
            else:
                function = self._vtop_32bit

        return function(virtual_address, address_space)

    def render(self, renderer):
        if self.address is None:
            return

        renderer.format("Virtual {0:#08x} Page Directory 0x{1:08x}\n",
                        self.address, self.address_space.dtb)

        for name, value, address in self.vtop(self.address, self.address_space):
            if address:
                renderer.format("{0}@ {2:#08x} = {1:#08x}\n",
                                name, value, address)
            elif value:
                renderer.format("{0} {1:#08x}\n", name, value)
            else:
                renderer.format("{0}\n", name)

        physical_address = self.address_space.vtop(self.address)
        if physical_address is None:
            renderer.format("Physical Address Invalid\n")
        else:
            renderer.format("Physical Address {0:#08x}\n", physical_address)


class PFNInfo(common.WindowsCommandPlugin):
    """Prints information about an address from the PFN database."""

    __name = "pfn"

    # Size of page.
    PAGE_SIZE = 0x1000
    PAGE_BITS = 12

    def __init__(self, pfn=None, physical_address=None, **kwargs):
        """Prints information about the physical PFN entry.

        Args:
          pfn: A page file number to display.
          physical_address: The physical address to print information about.
        """
        super(PFNInfo, self).__init__(**kwargs)

        self.profile = PFNModification(self.profile)

        # We prefer our own private version of the kdbg.
        self.kdbg = self.profile.Object("_KDDEBUGGER_DATA64", offset=self.kdbg,
                                        vm=self.kernel_address_space)

        # A reference to the pfn database.
        self.pfn_database = self.kdbg.MmPfnDatabase.dereference().dereference()
        self.pfn = pfn
        self.physical_address = physical_address

    def pfn_record(self, pfn=None, physical_address=None):
        """Returns the pfn record for a pfn or a virtual address."""
        if physical_address is not None:
            pfn = int(physical_address) / self.PAGE_SIZE

        if pfn is None:
            raise RuntimeError("PFN not provided.")

        # Return the pfn record.
        return self.pfn_database[pfn]

    def render(self, renderer):
        pfn = self.pfn
        if self.physical_address is not None:
            pfn = int(self.physical_address) / self.PAGE_SIZE

        pfn_obj = self.pfn_record(pfn)

        renderer.format("""    PFN 0x{0:08X} at kernel address 0x{1:016X}
""", pfn, pfn_obj.obj_offset)

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

        renderer.format("""    flink       {0:08X}  blink / share count {1:016X}
    pteaddress (VAS) 0x{2:016X}  (Phys AS) 0x{3:016X}
    reference count {4:04X}   color {5}
    containing page        0x{6:08X}  {7}     {8}
    {9}
    """, pfn_obj.u1.Flink, pfn_obj.u2.Blink,
                        pfn_obj.PteAddress,
                        pte_physical_address,
                        pfn_obj.u3.e2.ReferenceCount,
                        pfn_obj.u3.e1.m("PageColor") or pfn_obj.u4.PageColor,
                        containing_page,
                        pfn_obj.Type,
                        short_flags_string,
                        long_flags_string)


class PTE(common.WindowsCommandPlugin):
    """Prints information about a PTE."""

    __name = "pte"


    def __init__(self, virtual_address=None, pte_address=None, **kwargs):
        """Prints information about a PTE.

        Similar to windbg's !pte extension.

        Args:
          virtual_address: The virtual address to describe.
          pte_address: An address of a PTE record.
        """
        super(PTE, self).__init__(**kwargs)
        self.vtop = VtoP(session=self.session)
        self.pte_address = pte_address
        self.virtual_address = virtual_address


    def render(self, renderer):
        if self.virtual_address is not None:
            for name, _, _ in self.vtop.vtop(
                self.virtual_address, self.kernel_address_space):
                if name == "pte":
                    break


class PtoV(common.WinProcessFilter):
    """Converts a physical address to a virtual address."""

    __name = "ptov"

    PAGE_SIZE = 0x1000
    PAGE_BITS = 12

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
        if self.kernel_address_space.metadata("arch") == "I386":
            if self.kernel_address_space.metadata("pae"):
                return self._ptov_x86_pae(physical_address)
            else:
                return self._ptov_x86(physical_address)
        elif self.kernel_address_space.metadata("arch") == "AMD64":
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
                            "{1!r}\n", self.physical_address, result)


class DTBScan(common.WinProcessFilter):
    """Scans the physical memory for DTB values.

    This plugin can compare the DTBs found against the list of known processes
    to find hidden processes.
    """

    __name = "dtbscan"

    @classmethod
    def args(cls, parser):
        super(DTBScan, cls).args(parser)
        parser.add_argument("--limit", action=config.IntParser, default=0,
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
                               ("_EPROCESS", "task", "[addrpad]"),
                               ("Image Name", "filename", "<20"),
                               ("Known", "known", "")])

        seen_dtbs = set()

        # Now scan all the physical address space for DTBs.
        for _ in self.physical_address_space.get_available_addresses():
            start, phys_start, length = _
            for page in range(start, start + length, 0x1000):
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

                        if not task:
                            task = obj.NoneObject("Invalid")
                            filename = "Process not Found!"
                        else:
                            filename = task.ImageFileName

                        va, _ = ptov.ptov(dtb)
                        renderer.table_row(dtb, va, task, filename,
                                           task.obj_offset in known_tasks)

class TestDTBScan(testlib.SimpleTestCase):
    PARAMETERS = dict(
        commandline="dtbscan --limit 10mb",
        )
