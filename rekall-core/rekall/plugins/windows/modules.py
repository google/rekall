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

import re

from rekall import plugin
from rekall import scan
from rekall import utils
from rekall.plugins.windows import common


class Modules(common.WindowsCommandPlugin):
    """Print list of loaded kernel modules."""

    __name = "modules"

    __args = [
        dict(name="name_regex", type="RegEx",
             help="Filter module names by this regex.")
    ]

    table_header = [
        dict(name="_LDR_DATA_TABLE_ENTRY", cname="offset_v", style="address"),
        dict(name="Name", cname="file_name", width=20),
        dict(name='Base', cname="module_base", style="address"),
        dict(name='Size', cname="module_size", style="address"),
        dict(name='File', cname="path")
    ]

    def lsmod(self):
        """ A Generator for modules (uses _KPCR symbols) """
        for module in self.session.GetParameter(
                "PsLoadedModuleList").list_of_type(
                    "_LDR_DATA_TABLE_ENTRY", "InLoadOrderLinks"):

            # Skip modules which do not match.
            if (self.plugin_args.name_regex and
                    not self.plugin_args.name_regex.search(
                        utils.SmartUnicode(module.FullDllName))):
                continue

            yield module

    def addresses(self):
        """Returns a list of module addresses."""
        return sorted(self.mod_lookup.keys())

    def collect(self):
        object_tree_plugin = self.session.plugins.object_tree()

        for module in self.lsmod():
            yield (module,
                   module.BaseDllName,
                   module.DllBase,
                   module.SizeOfImage,
                   object_tree_plugin.FileNameWithDrive(module.FullDllName.v()))


class RSDSScanner(scan.BaseScanner):
    """Scan for RSDS objects."""

    checks = [
        ("StringCheck", dict(needle="RSDS"))
        ]


class ModVersions(Modules):
    """Try to determine the versions for all kernel drivers."""

    __name = "version_modules"

    table_header = [
        dict(name="Offset (V)", cname="offset_v", style="address"),
        dict(name="Name", cname="file_name", width=20),
        dict(name='GUID/Version', cname="guid", width=33),
        dict(name="PDB", cname="pdb")
    ]

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

    def collect(self):
        for module, rsds, guid in self.ScanVersions():
            yield (rsds,
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

    table_header = [
        dict(name="Name", cname="name", width=20),
        dict(name="Start", cname="start", style="address"),
        dict(name="End", cname="end", style="address"),
        dict(name="Time", cname="time")
    ]

    def collect(self):
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

        # In Windows 10 this has moved to the MiState.
        if unloaded_table == None:
            mistate = self.profile.get_constant_object(
                "MiState", target="_MI_SYSTEM_INFORMATION")

            unloaded_table = mistate.multi_m(
                "UnloadedDrivers",
                "Vs.UnloadedDrivers"
            ).dereference_as(
                "Array",
                target_args=dict(
                    target="_UNLOADED_DRIVERS",
                    count=mistate.LastUnloadedDriver)
            )

        for driver in unloaded_table:
            yield (driver.Name,
                   driver.StartAddress.v(),
                   driver.EndAddress.v(),
                   driver.CurrentTime)
