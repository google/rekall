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


class VtoP(common.WinProcessFilter):
    """Prints information about the virtual to physical translation."""

    __name = "vtop"

    PAGE_SIZE = 0x1000

    @classmethod
    def args(cls, parser):
        super(VtoP, cls).args(parser)
        parser.add_argument("virtual_address", type="SymbolAddress",
                            required=True,
                            help="The Virtual Address to examine.")

    def __init__(self, virtual_address=(), **kwargs):
        """Prints information about the virtual to physical translation.

        This is similar to windbg's !vtop extension.

        Args:
          virtual_address: The virtual address to describe.
          address_space: The address space to use (default the
            kernel_address_space).
        """
        super(VtoP, self).__init__(**kwargs)
        if not isinstance(virtual_address, (tuple, list)):
            virtual_address = [virtual_address]

        self.addresses = [self.session.address_resolver.get_address_by_name(x)
                          for x in virtual_address]

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

        phys_addr = address_space.get_phys_addr(vaddr, pte_value)
        if phys_addr is None:
            yield "Invalid PTE", None, None
            return

        yield ("PTE mapped", phys_addr, pte_addr)

    def _vtop_32bit_pae(self, vaddr, address_space):
        """An implementation specific to the 32 bit PAE intel AS."""
        transition_valid_mask = 1 << 11 | 1

        pdpte_addr = ((address_space.dtb & 0xfffffff0) |
                      ((vaddr & 0x7FC0000000) >> 27))

        pdpte_value = address_space.read_long_long_phys(pdpte_addr)
        yield "pdpte", pdpte_value, pdpte_addr

        if not pdpte_value & transition_valid_mask:
            yield "Invalid PDPTE", None, None
            return

        pde_addr = (pdpte_value & 0xfffff000) | ((vaddr & 0x3fe00000) >> 18)
        pde_value = address_space.read_long_long_phys(pde_addr)
        yield "pde", pde_value, pde_addr

        if not address_space.entry_present(pde_value):
            yield "Invalid PDE", None, None
            return

        if address_space.page_size_flag(pde_value):
            yield "Large page mapped", address_space.get_four_meg_paddr(
                vaddr, pde_value), None
            return

        pte_addr = (pde_value & 0xfffff000) | ((vaddr & 0x1ff000) >> 9)
        pte_value = address_space.read_long_long_phys(pte_addr)

        yield "pte", pte_value, pte_addr

    def _vtop_64bit(self, vaddr, address_space):
        """An implementation specific to the 64 bit intel address space."""
        transition_valid_mask = 1 << 11 | 1

        pml4e_addr = ((address_space.dtb & 0xffffffffff000) |
                      ((vaddr & 0xff8000000000) >> 36))

        pml4e_value = address_space.read_long_long_phys(pml4e_addr)
        yield "pml4e", pml4e_value, pml4e_addr

        if not pml4e_value & transition_valid_mask:
            yield "Invalid PDE", None, None
            return

        pdpte_addr = ((pml4e_value & 0xffffffffff000) |
                      ((vaddr & 0x7FC0000000) >> 27))

        pdpte_value = address_space.read_long_long_phys(pdpte_addr)
        yield "pdpte", pdpte_value, pdpte_addr

        if not pdpte_value & transition_valid_mask:
            yield "Invalid PDPTE", None, None

        if address_space.page_size_flag(pdpte_value):
            yield "One Gig page", address_space.get_one_gig_paddr(
                vaddr, pdpte_value), None
            return

        pde_addr = ((pdpte_value & 0xffffffffff000) |
                    ((vaddr & 0x3fe00000) >> 18))
        pde_value = address_space.read_long_long_phys(pde_addr)
        yield "pde", pde_value, pde_addr

        if not pde_value & transition_valid_mask:
            yield "Invalid PDE", None, None
            pte_value = 0

        elif address_space.page_size_flag(pde_value):
            yield "Large page mapped", address_space.get_four_meg_paddr(
                vaddr, pde_value), None
            return

        else:
            pte_addr = (pde_value & 0xffffffffff000) | ((vaddr & 0x1ff000) >> 9)
            pte_value = address_space.read_long_long_phys(pte_addr)
            yield "pte", pte_value, pte_addr

    def vtop(self, virtual_address, address_space=None):
        """Translate the virtual_address using the address_space."""
        if self.profile.metadata("arch") == "AMD64":
            function = self._vtop_64bit
        else:
            if self.profile.metadata("pae"):
                function = self._vtop_32bit_pae
            else:
                function = self._vtop_32bit

        return function(virtual_address, address_space)

    def render_pte(self, address, value, renderer, vaddr):
        """Analyze the PTE in detail.

        This follows the algorithm in WindowsAMD64PagedMemory.get_phys_addr().
        """
        pte_plugin = self.session.plugins.pte(address, "P", vaddr)

        pte_plugin.render(renderer)

        pte = self.profile._MMPTE()
        pte.u.Long = value

        phys_addr = self.address_space.ResolveProtoPTE(pte, vaddr)
        if phys_addr:
            renderer.format("PTE mapped at {0:addrpad}\n", phys_addr)
        else:
            renderer.format("Invalid PTE\n")

    def render(self, renderer):
        if self.filtering_requested:
            with self.session.plugins.cc() as cc:
                for task in self.filter_processes():
                    cc.SwitchProcessContext(task)

                    for vaddr in self.addresses:
                        self.render_address(renderer, vaddr)

        else:
            # Use current process context.
            for vaddr in self.addresses:
                self.render_address(renderer, vaddr)

    def render_address(self, renderer, vaddr):
        renderer.section(name="{0:#08x}".format(vaddr))
        self.address_space = self.session.GetParameter("default_address_space")

        renderer.format("Virtual {0:addrpad} Page Directory {1:addr}\n",
                        vaddr, self.address_space.dtb)

        for name, value, address in self.vtop(vaddr, self.address_space):
            if address:
                # Properly format physical addresses.
                renderer.format(
                    "{0}@ {1} = {2:addr}\n",
                    name,
                    self.physical_address_space.describe(address),
                    value or 0)
            elif value:
                renderer.format("{0} {1}\n",
                                name,
                                self.physical_address_space.describe(value))
            else:
                renderer.format("{0}\n", name)

            if name == "pde" and not value & 1:
                self.render_pte(0, value, renderer, vaddr)
                break

            if name == "pte":
                self.render_pte(address, value, renderer, vaddr)
                break

        # The below re-does all the analysis using the address space. It should
        # agree!
        physical_address = self.address_space.vtop(vaddr)
        if physical_address is None:
            renderer.format("Physical Address Invalid\n")
        else:
            renderer.format(
                "Physical Address {0}\n",
                self.physical_address_space.describe(physical_address))


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


class PTE(common.WindowsCommandPlugin):
    """Prints information about a PTE.

    This plugin essentially explains the algorithm implemented in
    WindowsAMD64PagedMemory.get_phys_addr().
    """
    __name = "pte"

    @classmethod
    def args(cls, parser):
        super(PTE, cls).args(parser)
        parser.add_argument("pte_address", type="IntParser",
                            help="The address of the PTE.")

        parser.add_argument("--address_space", default="P",
                            help="The address space to use.")

        parser.add_argument("--virtual_address", type="IntParser",
                            help="The virtual address that this pte is for.")

    def __init__(self, pte_address=None, address_space="P",
                 virtual_address=None, **kwargs):
        """Prints information about a PTE.

        Similar to windbg's !pte extension.
        """
        super(PTE, self).__init__(**kwargs)
        load_as = self.session.plugins.load_as(session=self.session)
        self.address_space = load_as.ResolveAddressSpace(address_space)
        self.pte_address = pte_address
        self.virtual_address = virtual_address
        self.default_address_space = self.session.GetParameter(
            "default_address_space")

    def _ResolveProtoPTE(self, pte, virtual_address):
        # Page is pointing to a subsection.
        if not pte.u.Hard.Valid and pte.u.Proto.Prototype:
            subsection = pte.u.Subsect.Subsection

            # Calculate the file offset.
            file_offset = ((pte - subsection.SubsectionBase) * 0x1000 +
                           subsection.StartingSector * 512)

            return dict(
                type="File Mapping",
                filename=subsection.ControlArea.FilePointer.FileName.v(),
                offset=file_offset)

        # When a prototype PTE has (v=0, p=0, t=0) and PageFileHigh=0 it is
        # definitely demand page.
        soft = pte.u.Soft
        if not (soft.Valid or soft.Prototype or soft.Transition or
                soft.PageFileHigh):
            return dict(type="Demand Zero")

        return self.ResolvePTE(pte, virtual_address)

    def ResolvePTE(self, pte, virtual_address):
        """Resolves the virtual_address using the PTE.

        Given a PTE and a virtual address, returns information about where to
        find the data in the page.

        This is basically the same algorithm as the render() method except we
        don't render anything.
        """
        desc, pte = self.default_address_space.DeterminePTEType(
            pte, virtual_address)

        if desc == "Prototype":
            result = self._ResolveProtoPTE(pte.Proto, virtual_address)
            result["ProtoType"] = True
            return result

        # This is a prototype into a vad region.
        elif desc == "Vad":
            resolver = self.session.address_resolver
            start, _, _, mmvad = resolver.FindProcessVad(virtual_address)

            # The MMVAD does not have any prototypes.
            if mmvad.m("FirstPrototypePte") == None:
                return dict(type="Demand Zero")

            else:
                pte = mmvad.FirstPrototypePte[(virtual_address - start) >> 12]
                return self._ResolveProtoPTE(pte.reference(), virtual_address)

        elif desc == "Pagefile":
            return dict(
                type="Pagefile",
                number=pte.PageFileLow,
                offset=pte.PageFileHigh * 0x1000)

        elif desc == "Valid":
            return dict(
                type="Valid",
                offset=pte.PageFrameNumber * 0x1000 | (virtual_address & 0xFFF))

        elif desc == "Transition":
            return dict(
                type="Transition",
                offset=pte.PageFrameNumber * 0x1000 | (virtual_address & 0xFFF))

        return dict(type="Unknown")

    def RenderPrototypePTE(self, pte, renderer):
        """Analyze the prototype PTE's target."""
        # Resolve this Prototype PTE recursively.
        pte_plugin = self.session.plugins.pte(pte, address_space=pte.obj_vm)

        # If the prototype is Valid or in Transition, just show it with the
        # plugin..
        if pte.u.Hard.Valid or (
                not pte.u.Trans.Prototype and pte.u.Trans.Transition):
            pte_plugin.render(renderer)

        # Page is pointing to a subsection.
        elif pte.u.Proto.Prototype:
            renderer.format(
                "Prototype PTE backed by file.\n{0:style=full}\n",
                pte.u.Subsect)

            subsection = pte.u.Subsect.Subsection

            renderer.format(
                "Filename: {0}\n",
                subsection.ControlArea.FilePointer.FileName)

            # Calculate the file offset.
            file_offset = ((pte.reference() - subsection.SubsectionBase) *
                           0x1000 + subsection.StartingSector * 512)

            renderer.format("File Offset: {0} ({0:style=address})\n",
                            file_offset)

        # Prototype PTE is a Demand Zero page
        elif pte.u.Soft.PageFileHigh == 0:
            renderer.format("Demand Zero\n{0}\n", pte.u.Soft)

        else:
            pte_plugin.render(renderer)

    def render(self, renderer):
        pte = self.profile._MMPTE(self.pte_address, vm=self.address_space)
        desc, pte = self.default_address_space.DeterminePTEType(
            pte, self.virtual_address)

        renderer.format(
            "\nPTE Contains {1:#x}\nPTE Type: {2}\n{0:style=full}\n",
            pte, pte.cast("_MMPTE").u.Long, desc)

        if desc == "Prototype":
            self.RenderPrototypePTE(pte.Proto.deref(), renderer)

        # This is a prototype into a vad region.
        elif desc == "Vad":
            renderer.format("Prototype PTE is found in VAD\n")
            if not self.virtual_address:
                renderer.format(
                    "Specify virtual_address to further resolve PTE.\n")

            task = self.session.GetParameter("process_context")
            vad_plugin = self.session.plugins.vad(
                eprocess=task, offset=self.virtual_address)
            vad_plugin.render(renderer)

            resolver = self.session.address_resolver
            hit = resolver.FindProcessVad(self.virtual_address)
            if hit:
                start, _, _, mmvad = hit
                # The MMVAD does not have any prototypes.
                if mmvad.m("FirstPrototypePte") == None:
                    renderer.format("Demand Zero page\n")

                else:
                    renderer.format("\n_MMVAD.FirstPrototypePte: {0:#x}\n",
                                    mmvad.FirstPrototypePte)
                    pte = mmvad.FirstPrototypePte[
                        (self.virtual_address - start) >> 12]

                    renderer.format("PTE is at {0:#x}\n", pte)
                    self.RenderPrototypePTE(pte, renderer)
            else:
                renderer.format("Demand Zero page\n")


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
        for _ in self.physical_address_space.get_available_addresses():
            start, _, length = _
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

                        va, _ = ptov.ptov(dtb)
                        renderer.table_row(dtb, va, task,
                                           task.obj_offset in known_tasks)

class TestDTBScan(testlib.SimpleTestCase):
    PARAMETERS = dict(
        commandline="dtbscan --limit 10mb",
        )
