# Rekall Memory Forensics
# Copyright (C) 2012 Michael Cohen <scudette@users.sourceforge.net>
# Copyright (c) 2008 Volatile Systems
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
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

import copy

from rekall.plugins.overlays import basic
from rekall.plugins.overlays.windows import common
from rekall.plugins.overlays.windows import xp
from rekall.plugins.overlays.windows import vista
from rekall.plugins.overlays.windows import win7
from rekall.plugins.overlays.windows import win8
from rekall.plugins.overlays.windows import crash_vtypes
from rekall.plugins.overlays.windows import kdbg_vtypes

# Reference:
# http://computer.forensikblog.de/en/2006/03/dmp-file-structure.html

crash_overlays = {
    "_DMP_HEADER": [None, {
            'Signature': [None, ['String', dict(length=4)]],
            'ValidDump': [None, ['String', dict(length=4)]],
            'SystemTime': [None, ['WinFileTime']],
            'DumpType': [None, ['Enumeration', {
                        'choices': {
                            1: "Full Dump",
                            2: "Kernel Dump",
                            },
                        'target': 'unsigned int'}]],
            }],
    '_PHYSICAL_MEMORY_DESCRIPTOR' : [None, {
            'Run' : [None, ['Array', dict(
                        count=lambda x: x.NumberOfRuns,
                        target='_PHYSICAL_MEMORY_RUN')]],
            }],
    }

crash_overlays['_DMP_HEADER64'] = copy.deepcopy(crash_overlays['_DMP_HEADER'])


class CrashDump32Profile(basic.Profile32Bits, basic.BasicClasses):
    """A profile for crash dumps."""
    def __init__(self, **kwargs):
        super(CrashDump32Profile, self).__init__(**kwargs)
        self.add_overlay(crash_vtypes.crash_vtypes)
        self.add_overlay(crash_overlays)


class CrashDump64Profile(basic.ProfileLLP64, basic.BasicClasses):
    """A profile for crash dumps."""
    def __init__(self, **kwargs):
        super(CrashDump64Profile, self).__init__(**kwargs)
        self.add_overlay(crash_vtypes.crash_vtypes)
        self.add_overlay(crash_vtypes.crash_64_vtypes)
        self.add_overlay(crash_overlays)


def InstallKDDebuggerProfile(profile):
    """Define the kernel debugger structures.

    The kernel debugger strucutures do not vary with windows operating system
    version very much. This is probably done to make it easier for Windbg to
    support all the different windows versions.
    """
    profile.add_types(kdbg_vtypes.kdbg_vtypes)
    profile.add_overlay(kdbg_vtypes.kdbg_overlay)
    profile.add_classes({
            "_KDDEBUGGER_DATA64": kdbg_vtypes._KDDEBUGGER_DATA64
            })


class Ntoskrnl(basic.BasicClasses):
    """A profile for Windows."""

    METADATA = dict(os="windows")

    @classmethod
    def Initialize(cls, profile):
        super(Ntoskrnl, cls).Initialize(profile)

        # Architecture not known - guess.
        if profile.metadata("arch") is None:
            if profile.get_obj_size("_LIST_ENTRY") == 16:
                profile.set_metadata("arch", "AMD64")
            else:
                profile.set_metadata("arch", "I386")

        # Select basic compiler model type.
        if profile.metadata("arch") == "AMD64":
            basic.ProfileLLP64.Initialize(profile)

        elif profile.metadata("arch") == "I386":
            basic.Profile32Bits.Initialize(profile)

            # Detect if this is a PAE system. PAE systems have 64 bit PTEs:
            if profile.get_obj_size("_MMPTE") == 8:
                profile.set_metadata("pae", True)

        # Install the base windows support.
        common.InitializeWindowsProfile(profile)

        InstallKDDebuggerProfile(profile)

        # Version specific support.
        try:
            version = ".".join(profile.metadatas("major", "minor"))
        except TypeError:
            # We have no idea what version it is, this can happen if we were
            # just given a GUID and a pdb file without a kernel executable.
            version = "6.1"

        if version in ("6.2", "6.3"):
            win8.InitializeWindows8Profile(profile)

        elif version == "6.1":
            win7.InitializeWindows7Profile(profile)

        elif version == "6.0":
            vista.InitializeVistaProfile(profile)

        elif version in ("5.2", "5.1"):
            xp.InitializeXPProfile(profile)

