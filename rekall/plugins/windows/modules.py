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

import bisect
import re

from rekall import obj
from rekall import plugin
from rekall import scan
from rekall.plugins.windows import common


class Modules(common.WindowsCommandPlugin):
    """Print list of loaded modules."""

    __name = "modules"

    # A local cache for find_modules. Key is module base and value is the
    # _LDR_DATA_TABLE_ENTRY for the module.
    mod_lookup = None
    modlist = None

    @classmethod
    def args(cls, parser):
        """Declare the command line args we need."""
        super(Modules, cls).args(parser)
        parser.add_argument("--name_regex",
                            help="Filter module names by this regex.")

    def __init__(self, name_regex=None, **kwargs):
        """List kernel modules by walking the PsLoadedModuleList."""
        super(Modules, self).__init__(**kwargs)
        self.name_regex = re.compile(name_regex or ".", re.I)

    def lsmod(self):
        """ A Generator for modules (uses _KPCR symbols) """
        if not self.mod_lookup:
            self._make_cache()

        for module in self.mod_lookup.values():
            # Skip modules which do not match.
            if not self.name_regex.search(str(module.FullDllName)):
                continue

            yield module

    def addresses(self):
        """Returns a list of module addresses."""
        if not self.mod_lookup:
            self._make_cache()

        return sorted(self.mod_lookup.keys())

    def _make_cache(self):
        self.mod_lookup = {}

        ## Try to iterate over the process list in PsActiveProcessHead
        ## (its really a pointer to a _LIST_ENTRY)
        PsLoadedModuleList = self.kdbg.PsLoadedModuleList.cast(
            "Pointer", target="_LIST_ENTRY", vm=self.kernel_address_space)

        for l in PsLoadedModuleList.list_of_type("_LDR_DATA_TABLE_ENTRY",
                                                 "InLoadOrderLinks"):
            self.mod_lookup[l.DllBase.v()] = l

        self.modlist = sorted(self.mod_lookup.keys())

    def find_module(self, addr):
        """Uses binary search to find what module a given address resides in.

        This is much faster than a series of linear checks if you have
        to do it many times. Note that modlist and mod_addrs must be sorted
        in order of the module base address."""
        if self.mod_lookup is None:
            self._make_cache()

        addr = int(addr)
        pos = bisect.bisect_right(self.modlist, addr) - 1
        if pos == -1:
            return obj.NoneObject("Unknown")
        mod = self.mod_lookup[self.modlist[pos]]

        if (addr >= mod.DllBase.v() and
            addr < mod.DllBase.v() + mod.SizeOfImage.v()):
            return mod

        return obj.NoneObject("Unknown")

    def render(self, renderer):
        renderer.table_header([("Offset (V)", "offset_v", "[addrpad]"),
                               ("Name", "file_name", "20"),
                               ('Base', "module_base", "[addrpad]"),
                               ('Size', "module_size", "[addr]"),
                               ('File', "path", "")
                               ])

        for module in self.lsmod():
            renderer.table_row(module.obj_offset,
                               module.BaseDllName,
                               module.DllBase,
                               module.SizeOfImage,
                               module.FullDllName)


class RSDSScanner(scan.BaseScanner):
    """Scan for RSDS objects."""

    checks = [
        ("StringCheck", dict(needle="RSDS"))
        ]


class ModVersions(Modules):
    """Try to determine the versions for all kernel drivers."""

    __name = "version_modules"

    def ScanVersions(self):
        pe_profile = self.session.LoadProfile("pe")
        scanner = RSDSScanner(address_space=self.kernel_address_space,
                              session=self.session)

        for module in self.lsmod():
            for hit in scanner.scan(offset=int(module.DllBase),
                                    maxlen=int(module.SizeOfImage)):

                rsds = pe_profile.CV_RSDS_HEADER(offset=hit,
                                                 vm=self.kernel_address_space)
                guid = "%s%x" % (rsds.GUID.AsString, rsds.Age)
                yield module, rsds, guid

    def render(self, renderer):
        renderer.table_header(
            [("Offset (V)", "offset_v", "[addrpad]"),
             ("Name", "file_name", "20"),
             ('GUID/Version', "guid", "32"),
             ("PDB", "pdb", "30")])

        for module, rsds, guid in self.ScanVersions():
            renderer.table_row(
                rsds,
                module.BaseDllName,
                guid,
                rsds.Filename)


class VersionScan(plugin.PhysicalASMixin, plugin.Command):
    """Scan the physical address space for RSDS versions."""

    __name = "version_scan"

    @classmethod
    def args(cls, parser):
        """Declare the command line args we need."""
        super(VersionScan, cls).args(parser)
        parser.add_argument("--name_regex",
                            help="Filter module names by this regex.")

    def __init__(self, name_regex=None, **kwargs):
        """List kernel modules by walking the PsLoadedModuleList."""
        super(VersionScan, self).__init__(**kwargs)
        self.name_regex = re.compile(name_regex or ".", re.I)

    def ScanVersions(self):
        """Scans the physical AS for RSDS structures."""
        guids = set()
        pe_profile = self.session.LoadProfile("pe")
        scanner = RSDSScanner(address_space=self.physical_address_space)

        for hit in scanner.scan():
            rsds = pe_profile.CV_RSDS_HEADER(
                offset=hit, vm=self.physical_address_space)

            # The filename must end with pdb for valid pdb.
            if not unicode(rsds.Filename).endswith("pdb"):
                continue

            guid = rsds.GUID_AGE
            if guid not in guids:
                guids.add(guid)

                if self.name_regex.search(unicode(rsds.Filename)):
                    yield rsds, guid

    def render(self, renderer):
        renderer.table_header(
            [("Offset (P)", "offset_p", "[addrpad]"),
             ('GUID/Version', "guid", "32"),
             ("PDB", "pdb", "30")])

        for rsds, guid in self.ScanVersions():
            renderer.table_row(rsds, guid, rsds.Filename)
