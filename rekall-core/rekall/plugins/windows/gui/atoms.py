# Rekall Memory Forensics
# Copyright (C) 2007,2008 Volatile Systems
# Copyright (C) 2010,2011,2012 Michael Hale Ligh <michael.ligh@mnin.org>
# Copyright 2013 Google Inc. All Rights Reserved.
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
# pylint: disable=protected-access

from rekall import obj

from rekall.plugins.windows import common
from rekall.plugins.windows.gui import win32k_core


class PoolScanAtom(common.PoolScanner):
    """Pool scanner for atom tables"""

    def __init__(self, **kwargs):
        super(PoolScanAtom, self).__init__(**kwargs)

        self.checks = [
            ('PoolTagCheck', dict(tag=self.profile.get_constant(
                "PoolTag_Atom"))),

            ('CheckPoolSize', dict(
                min_size=self.profile.get_obj_size("_RTL_ATOM_TABLE"))),

            ('CheckPoolType', dict(paged=True, non_paged=True, free=True)),
            ]


class AtomScan(win32k_core.Win32kPluginMixin, common.PoolScannerPlugin):
    """Pool scanner for _RTL_ATOM_TABLE"""

    __name = "atomscan"

    __args = [
        dict(name="sort_by", choices=["atom", "refcount", "offset"],
             default="offset", help="Sort by [offset | atom | refcount]")
    ]

    table_header = [
        dict(name="offset_p", style="address"),
        dict(name="offset_v", style="address"),
        dict(name="atom", style="address"),
        dict(name="refs", width=6),
        dict(name="pinned", width=6),
        dict(name="name"),
    ]

    scanner_defaults = dict(
        scan_physical=True
    )

    def collect(self):
        for run in self.generate_memory_ranges():
            scanner = PoolScanAtom(
                profile=self.win32k_profile, session=self.session,
                address_space=run.address_space)

            for pool_header in scanner.scan(run.start, run.length):
                # Note: all OS after XP, there are an extra 8 bytes (for 32-bit)
                # or 16 bytes (for 64-bit) between the _POOL_HEADER and
                # _RTL_ATOM_TABLE.  This is variable length structure, so we
                # can't use the bottom-up approach as we do with other object
                # scanners - because the size of an _RTL_ATOM_TABLE differs
                # depending on the number of hash buckets.

                version = self.profile.metadata('version')
                fixup = 0

                if self.profile.metadata('arch') == 'I386':
                    if version > 5.1:
                        fixup = 8
                else:
                    if version > 5.1:
                        fixup = 16

                atom_table = self.win32k_profile._RTL_ATOM_TABLE(
                    offset=pool_header.obj_end + fixup,
                    vm=pool_header.obj_vm)

                # There's no way to tell which session or window station
                # owns an atom table by *just* looking at the atom table,
                # so we have to instantiate it from the default kernel AS.
                if not atom_table.is_valid():
                    continue

                # This defeats the purpose of having a generator, but
                # its required if we want to be able to sort. We also
                # filter string atoms here.
                atoms = []
                for atom in atom_table.atoms(vm=self.kernel_address_space):
                    if atom.is_string_atom():
                        atoms.append(atom)

                if self.plugin_args.sort_by == "atom":
                    attr = "Atom"
                elif self.plugin_args.sort_by == "refcount":
                    attr = "ReferenceCount"
                else:
                    attr = "obj_offset"

                for atom in sorted(atoms, key=lambda x: getattr(x, attr)):
                    yield dict(offset_p=atom_table.obj_offset,
                               offset_v=atom.obj_offset,
                               atom=atom.Atom,
                               refs=atom.ReferenceCount,
                               pinned=atom.Pinned,
                               name=atom.Name)


class Atoms(win32k_core.Win32kPluginMixin,
            common.WindowsCommandPlugin):
    """Print session and window station atom tables.

    From:
    http://msdn.microsoft.com/en-us/library/windows/desktop/ms649053.aspx

    An atom table is a system-defined table that stores strings and
    corresponding identifiers. An application places a string in an atom table
    and receives a 16-bit integer, called an atom, that can be used to access
    the string. A string that has been placed in an atom table is called an atom
    name.

    The global atom table is available to all applications. When an application
    places a string in the global atom table, the system generates an atom that
    is unique throughout the system. Any application that has the atom can
    obtain the string it identifies by querying the global atom table.

    (The global atom tables are only global within each session).
    """

    __name = "atoms"


    table_header = [
        dict(name="offset_p", style="address"),
        dict(name="session", width=10),
        dict(name="windows_station", width=18),
        dict(name="atom", style="address"),
        dict(name="ref_count", width=10),
        dict(name="hindex", width=10),
        dict(name="pinned", width=10),
        dict(name="name"),
    ]

    def station_atoms(self, station):
        """Generate all the atoms in the windows station atom table."""
        table = station.pGlobalAtomTable

        # In Windows 8 this pointer is not valid or points to something else
        # since there are no more global atom tables. Ref:
        # http://mista.nu/research/smashing_the_atom.pdf
        if table.Signature != 0x6D6F7441:
            return

        for atom in sorted(table.atoms(), key=lambda x: x.Atom):
            ## Filter string atoms
            if not atom.is_string_atom():
                continue

            yield table, atom

    def session_atoms(self, session):
        """Generate all (Session) Global User Atoms."""
        # Now find all the atoms in the User handle table.
        table = self.win32k_profile.get_constant_object(
            "UserAtomTableHandle",
            target="Pointer",
            target_args=dict(
                target="_RTL_ATOM_TABLE",
                ),
            vm=session.obj_vm,
            )

        for atom in sorted(table.atoms(), key=lambda x: x.Atom):
            ## Filter string atoms
            if not atom.is_string_atom():
                continue

            yield table, atom

    def find_atoms(self):
        windows_stations = self.session.plugins.windows_stations()
        # List the atom tables that belong to each window station.
        for station in windows_stations.stations():
            for table, atom in self.station_atoms(station):
                yield table, atom, station, station.dwSessionId

        # List the global user atom tables.
        for session in self.session.plugins.sessions().session_spaces():
            for table, atom in self.session_atoms(session):
                yield table, atom, obj.NoneObject(), session.SessionId

    def collect(self):
        for table, atom, window_station, session_id in self.find_atoms():
            yield dict(offset_p=table,
                       session=session_id,
                       windows_station=window_station.Name,
                       atom=atom.Atom,
                       ref_count=atom.ReferenceCount,
                       hindex=atom.HandleIndex,
                       pinned=atom.Pinned,
                       name=atom.Name)
