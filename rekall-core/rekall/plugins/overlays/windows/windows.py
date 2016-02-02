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

from rekall import obj

from rekall.plugins.overlays.windows import common
from rekall.plugins.overlays.windows import heap
from rekall.plugins.overlays.windows import pe_vtypes
from rekall.plugins.overlays.windows import tokens

from rekall.plugins.overlays.windows import xp
from rekall.plugins.overlays.windows import vista
from rekall.plugins.overlays.windows import win7
from rekall.plugins.overlays.windows import win8
from rekall.plugins.overlays.windows import win10
from rekall.plugins.overlays.windows import crashdump
from rekall.plugins.overlays.windows import undocumented



class Ntoskrnl(pe_vtypes.BasicPEProfile):
    """A profile for Windows."""

    @classmethod
    def GuessVersion(cls, profile):
        """Guess the windows version of a profile."""
        # If the version is provided, then just use it.
        try:
            major, minor = profile.metadatas("major", "minor")
            version = major + minor / 10.0
            profile.set_metadata("version", version)

            return version
        except TypeError:
            pass

        # Rekall is moving away from having features keyed by version, rather we
        # use the profile to dictate the algorithms to use. In future we will
        # remove all requirement to know the windows version, but for now we
        # just guess the version based on structures which are known to exist in
        # the profile.
        version = 5.2

        # Windows XP did not use a BalancedRoot for VADs.
        if profile.get_obj_offset("_MM_AVL_TABLE", "BalancedRoot") == None:
            version = 5.1

        # Windows 7 introduces TypeIndex into the object header.
        if profile.get_obj_offset("_OBJECT_HEADER", "TypeIndex") != None:
            # Windows 10 introduces a cookie for object types.
            if profile.get_constant("ObHeaderCookie"):
                version = 10.0

            elif profile._EPROCESS().m(
                    "VadRoot.BalancedRoot").obj_type == "_MMADDRESS_NODE":
                version = 6.1

            elif profile._EPROCESS().m("VadRoot").obj_type == "_MM_AVL_TABLE":
                # Windows 8 uses _MM_AVL_NODE as the VAD traversor struct.
                version = 6.2

            elif profile._EPROCESS().m("VadRoot").obj_type == "_RTL_AVL_TREE":
                # Windows 8.1 and on uses _RTL_AVL_TREE
                version = 6.3

            else:
                raise RuntimeError("Unknown windows version")

        profile.set_metadata("version", version)
        major, minor = divmod(version, 1)
        profile.set_metadata("minor", int(minor * 10))
        profile.set_metadata("major", major)

        return version

    @classmethod
    def Initialize(cls, profile):
        super(Ntoskrnl, cls).Initialize(profile)

        profile.add_enums(**undocumented.ENUMS)
        if profile.metadata("arch") == "AMD64":
            profile.add_overlay(undocumented.AMD64)

        elif profile.metadata("arch") == "I386":
            profile.add_overlay(undocumented.I386)

            # Detect if this is a PAE system. PAE systems have 64 bit PTEs:
            if profile.get_obj_size("_MMPTE") == 8:
                profile.set_metadata("pae", True)

        # Install the base windows support.
        common.InitializeWindowsProfile(profile)
        crashdump.InstallKDDebuggerProfile(profile)
        tokens.InitializeTokenProfiles(profile)
        heap.InitializeHeapProfile(profile)

        # Get the windows version of this profile.
        version = cls.GuessVersion(profile)
        if 10 <= version:
            win10.InitializeWindows10Profile(profile)

        elif 6.2 <= version < 10:
            win8.InitializeWindows8Profile(profile)

        elif version == 6.1:
            win7.InitializeWindows7Profile(profile)

        elif version == 6.0:
            vista.InitializeVistaProfile(profile)

        elif 5.1 <= version <= 5.2:
            xp.InitializeXPProfile(profile)

    def GetImageBase(self):
        if not self.image_base:
            self.image_base = obj.Pointer.integer_to_address(
                self.session.GetParameter("kernel_base"))

        return self.image_base


class Ntkrnlmp(Ntoskrnl):
    """Alias for the windows kernel class."""


class Ntkrnlpa(Ntoskrnl):
    """Alias for the windows kernel class."""


class Ntkrpamp(Ntoskrnl):
    """Alias for the windows kernel class."""


class Nt(Ntoskrnl):
    """Alias for the windows kernel class."""
