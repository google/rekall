# Volatility
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
import logging

from volatility import scan
from volatility import plugin
from volatility.plugins.windows import common



class KDBGScanner(scan.DiscontigScanner):
    """Scans for _KDDEBUGGER_DATA64 structures.

    Note that this does not rely on signatures, as validity of hits is
    calculated through list reflection.
    """
    checks = [ ("MultiStringFinderCheck", dict(needles=["KDBG"])) ]

    def scan(self, offset = 0, maxlen = None):
        # How far into the struct the OwnerTag is.
        owner_tag_offset = self.profile.get_obj_offset("_DBGKD_DEBUG_DATA_HEADER64",
                                                       "OwnerTag")

        # Depending on the memory model this behaves slightly differently.
        memory_model = self.profile.metadata("memory_model", "32bit")

        # This basical iterates over all hits on the string "KDBG".
        for offset in super(KDBGScanner, self).scan(offset, maxlen):
            # For each hit we overlay a _DBGKD_DEBUG_DATA_HEADER64 on it and
            # reflect through the "List" member.
            result = self.profile.Object("_KDDEBUGGER_DATA64",
                                         offset=offset - owner_tag_offset,
                                         vm=self.address_space)

            # We verify this hit by reflecting through its header list.
            list_entry = result.Header.List

            # On 32 bit systems the Header.List member seems to actually be a
            # LIST_ENTRY32 instead of a LIST_ENTRY64, but it is still padded to
            # take the same space:
            if memory_model == "32bit":
                list_entry = list_entry.cast("LIST_ENTRY32")

            if list_entry.reflect():
                yield result

            elif list_entry.Flink == list_entry.Blink and not list_entry.Flink.dereference():
                logging.debug("KDBG list_head is not mapped, assuming its valid.")
                yield result


class KDBGScan(plugin.KernelASMixin, common.AbstractWindowsCommandPlugin):
    """A scanner for the kdbg structures."""

    __name = "kdbgscan"

    def __init__(self, **kwargs):
        """Scan for possible _KDDEBUGGER_DATA64 structures.

        The scanner is detailed here:
        http://moyix.blogspot.com/2008/04/finding-kernel-global-variables-in.html

        The relevant structures are detailed here:
        http://doxygen.reactos.org/d3/ddf/include_2psdk_2wdbgexts_8h_source.html

        We can see that _KDDEBUGGER_DATA64.Header is:

        typedef struct _DBGKD_DEBUG_DATA_HEADER64 {
            LIST_ENTRY64    List;
            ULONG           OwnerTag;
            ULONG           Size;
        }

        We essentially search for an owner tag of "KDBG", then overlay the
        _KDDEBUGGER_DATA64 struct on it. We test for validity by reflecting
        through the Header.List member.
        """
        super(KDBGScan, self).__init__(**kwargs)

    def hits(self):
        scanner = scan.BaseScanner.classes['KDBGScanner'](
            session=self.session, profile=self.profile,
            address_space=self.kernel_address_space)

        # Yield actual objects here
        for kdbg in scanner.scan():
            yield kdbg

    def render(self, renderer=None):
        """Renders the KPCR values as text"""

        for kdbg in self.hits():
            renderer.section()
            renderer.format("Instantiating KDBG using: {0} {1} ({2}.{3}.{4} {5})\n",
                            kdbg.obj_vm.name, kdbg.obj_profile.__class__.__name__,
                            kdbg.obj_profile.metadata('major', "Unknown"),
                            kdbg.obj_profile.metadata('minor', "Unknown"),
                            kdbg.obj_profile.metadata('build', "Unknown"),
                            kdbg.obj_profile.metadata('memory_model', "Unknown"),
                            )

            renderer.format("{0:<30}: {1:#x}\n", "Offset (V)", kdbg.obj_offset)
            renderer.format("{0:<30}: {1:#x}\n", "Offset (P)", kdbg.obj_vm.vtop(
                    kdbg.obj_offset))

            # These fields can be gathered without dereferencing
            # any pointers, thus they're available always
            renderer.format("{0:<30}: {1}\n", "KDBG owner tag check", kdbg.is_valid())

            verinfo = kdbg.dbgkd_version64()
            if verinfo:
                renderer.format("{0:<30}: {1:#x} (Major: {2}, Minor: {3})\n",
                                "Version64", verinfo.obj_offset, verinfo.MajorVersion,
                                verinfo.MinorVersion)

            renderer.format("{0:<30}: {1}\n", "Service Pack (CmNtCSDVersion)",
                            kdbg.ServicePack)

            renderer.format("{0:<30}: {1}\n", "Build string (NtBuildLab)",
                            kdbg.NtBuildLab.dereference())

            # Count the total number of tasks from PsActiveProcessHead.
            try:
                pslist = self.session.plugins.pslist(session=self.session,
                                                     kdbg=kdbg)
                num_tasks = len(list(pslist.list_eprocess_from_kdbg(kdbg)))
            except AttributeError:
                num_tasks = 0

            try:
                modules = self.session.plugins.modules(session=self.session,
                                                       kdbg=kdbg)
                num_modules = len(list(modules.lsmod()))
            except AttributeError:
                num_modules = 0

            renderer.format("{0:<30}: {1:#x} ({2} processes)\n",
                            "PsActiveProcessHead", kdbg.PsActiveProcessHead, num_tasks)

            renderer.format("{0:<30}: {1:#x} ({2} modules)\n",
                            "PsLoadedModuleList", kdbg.PsLoadedModuleList, num_modules)

            renderer.format("{0:<30}: {1:#x} (Matches MZ: {2})\n",
                            "KernelBase", kdbg.KernBase,
                            kdbg.obj_vm.read(kdbg.KernBase, 2) == "MZ")

            dos_header = self.profile.Object("_IMAGE_DOS_HEADER",
                                             offset = kdbg.KernBase,
                                             vm = kdbg.obj_vm)
            nt_header = dos_header.NTHeader
            if nt_header:
                renderer.format("{0:<30}: {1}\n", "Major (OptionalHeader)",
                                nt_header.OptionalHeader.MajorOperatingSystemVersion)
                renderer.format("{0:<30}: {1}\n", "Minor (OptionalHeader)",
                                nt_header.OptionalHeader.MinorOperatingSystemVersion)

            # The CPU block.
            for kpcr in kdbg.kpcrs():
                renderer.format("{0:<30}: {1:#x} (CPU {2})\n",
                                "KPCR", kpcr.obj_offset, kpcr.ProcessorBlock.Number)
