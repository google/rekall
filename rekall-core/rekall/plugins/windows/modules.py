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
        dict(name="_LDR_DATA_TABLE_ENTRY", style="address"),
        dict(name="name", width=20),
        dict(name="base", style="address"),
        dict(name="size", style="address"),
        dict(name="path")
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
            yield dict(_LDR_DATA_TABLE_ENTRY=module,
                       name=module.BaseDllName,
                       base=module.DllBase,
                       size=module.SizeOfImage,
                       path=object_tree_plugin.FileNameWithDrive(
                           module.FullDllName.v()))


class RSDSScanner(scan.BaseScanner):
    """Scan for RSDS objects."""

    checks = [
        ("StringCheck", dict(needle="RSDS"))
        ]


class ModVersions(Modules):
    """Try to determine the versions for all kernel drivers."""

    __name = "version_modules"

    table_header = [
        dict(name="offset_v", style="address"),
        dict(name="name", width=20),
        dict(name="guid", width=33),
        dict(name="pdb")
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
            yield dict(offset_v=rsds,
                       name=module.BaseDllName,
                       guid=guid,
                       pdb=rsds.Filename)


class VersionScan(plugin.PhysicalASMixin, plugin.TypedProfileCommand,
                  plugin.Command):
    """Scan the physical address space for RSDS versions."""

    __name = "version_scan"

    PHYSICAL_AS_REQUIRED = False

    __args = [
        dict(name="name_regex", type="RegEx", default=".",
             help="Filter module names by this regex."),

        dict(name="scan_filename", required=False, positional=True,
             help="Optional file to scan. If not specified "
             "we scan the physical address space.")
    ]

    table_header = [
        dict(name="offset", style="address"),
        dict(name="guid", width=33),
        dict(name="pdb", width=30)
    ]

    def __init__(self, *args, **kwargs):
        """List kernel modules by walking the PsLoadedModuleList."""
        super(VersionScan, self).__init__(*args, **kwargs)
        if self.plugin_args.scan_filename is not None:
            load_as = self.session.plugins.load_as()
            self.physical_address_space = load_as.GuessAddressSpace(
                filename=self.plugin_args.scan_filename)

    def ScanVersions(self):
        """Scans the physical AS for RSDS structures."""
        guids = set()
        pe_profile = self.session.LoadProfile("pe")
        scanner = RSDSScanner(address_space=self.physical_address_space,
                              session=self.session, profile=pe_profile)

        for hit in scanner.scan(0, self.physical_address_space.end()):
            rsds = pe_profile.CV_RSDS_HEADER(
                offset=hit, vm=self.physical_address_space)

            # The filename must end with pdb for valid pdb.
            if not unicode(rsds.Filename).endswith("pdb"):
                continue

            guid = rsds.GUID_AGE
            if guid not in guids:
                guids.add(guid)

                if self.plugin_args.name_regex.search(unicode(rsds.Filename)):
                    yield rsds, guid

    def collect(self):
        for rsds, guid in self.ScanVersions():
            yield dict(offset=rsds, guid=guid, pdb=rsds.Filename)


class UnloadedModules(common.WindowsCommandPlugin):
    """Print a list of recently unloaded modules.

    Ref:
    http://volatility-labs.blogspot.de/2013/05/movp-ii-22-unloaded-windows-kernel_22.html
    """

    name = "unloaded_modules"

    table_header = [
        dict(name="name", width=20),
        dict(name="start", style="address"),
        dict(name="end", style="address"),
        dict(name="time")
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
