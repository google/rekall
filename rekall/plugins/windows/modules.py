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
    """Print list of loaded kernel modules."""

    __name = "modules"

    # A local cache for find_modules. Key is module base and value is the
    # _LDR_DATA_TABLE_ENTRY for the module.
    mod_lookup = None

    @classmethod
    def args(cls, parser):
        """Declare the command line args we need."""
        super(Modules, cls).args(parser)
        parser.add_argument("--name_regex",
                            help="Filter module names by this regex.")

        parser.add_argument("-a", "--address_space", default=None,
                            help="The address space to use.")

    def __init__(self, name_regex=None, address_space=None, **kwargs):
        """List kernel modules by walking the PsLoadedModuleList."""
        super(Modules, self).__init__(**kwargs)
        self.name_regex = re.compile(name_regex or ".", re.I)

        # Resolve the correct address space. This allows the address space to be
        # specified from the command line (e.g.
        load_as = self.session.plugins.load_as(session=self.session)
        self.address_space = load_as.ResolveAddressSpace(address_space)
        self.modlist = []

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
        for l in self.session.GetParameter("PsLoadedModuleList").list_of_type(
                "_LDR_DATA_TABLE_ENTRY", "InLoadOrderLinks"):
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
             ('GUID/Version', "guid", "33"),
             ("PDB", "pdb", "")])

        for module, rsds, guid in self.ScanVersions():
            renderer.table_row(
                rsds,
                module.BaseDllName,
                guid,
                rsds.Filename)


class VersionScan(plugin.PhysicalASMixin, plugin.Command):
    """Scan the physical address space for RSDS versions."""

    __name = "version_scan"

    PHYSICAL_AS_REQUIRED = False

    @classmethod
    def args(cls, parser):
        """Declare the command line args we need."""
        super(VersionScan, cls).args(parser)
        parser.add_argument("--name_regex",
                            help="Filter module names by this regex.")

        parser.add_argument("scan_filename", required=False,
                            help="Optional file to scan. If not specified "
                            "we scan the physical address space.")

    def __init__(self, name_regex=None, scan_filename=None, **kwargs):
        """List kernel modules by walking the PsLoadedModuleList."""
        super(VersionScan, self).__init__(**kwargs)
        self.name_regex = re.compile(name_regex or ".", re.I)
        if scan_filename is not None:
            load_as = self.session.plugins.load_as()
            self.physical_address_space = load_as.GuessAddressSpace(
                filename=scan_filename)

    def ScanVersions(self):
        """Scans the physical AS for RSDS structures."""
        guids = set()
        pe_profile = self.session.LoadProfile("pe")
        scanner = RSDSScanner(address_space=self.physical_address_space,
                              session=self.session, profile=pe_profile)

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
             ('GUID/Version', "guid", "33"),
             ("PDB", "pdb", "30")])

        for rsds, guid in self.ScanVersions():
            renderer.table_row(rsds, guid, rsds.Filename)


class UnloadedModules(common.WindowsCommandPlugin):
    """Print a list of recently unloaded modules.

    Ref:
    http://volatility-labs.blogspot.de/2013/05/movp-ii-22-unloaded-windows-kernel_22.html
    """

    name = "unloaded_modules"

    def render(self, renderer):
        unloaded_table = self.profile.get_constant_object(
            "MmUnloadedDrivers",
            target="Pointer",
            target_args=dict(
                target="Array",
                target_args=dict(
                    target="_UNLOADED_DRIVER",
                    count=self.profile.get_constant_object(
                        "MmLastUnloadedDriver", "unsigned int").v(),
                    )
                )
            )

        renderer.table_header([("Name", "name", "20"),
                               ("Start", "start", "[addrpad]"),
                               ("End", "end", "[addrpad]"),
                               ("Time", "time", "")])

        for driver in unloaded_table:
            renderer.table_row(driver.Name,
                               driver.StartAddress.v(),
                               driver.EndAddress.v(),
                               driver.CurrentTime)
