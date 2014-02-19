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
import re

from rekall.plugins.overlays import basic
from rekall.plugins.overlays.windows import common
from rekall.plugins.overlays.windows import xp
from rekall.plugins.overlays.windows import vista
from rekall.plugins.overlays.windows import win7
from rekall.plugins.overlays.windows import win8
from rekall.plugins.overlays.windows import crash_vtypes
from rekall.plugins.overlays.windows import kdbg_vtypes
from rekall.plugins.overlays.windows import undocumented

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


class RelativeOffsetMixin(object):
    """A mixin which shifts all constant addresses by a constant."""

    # This should be adjusted to the correct image base.
    def GetImageBase(self):
        return 0

    def get_constant(self, name, is_address=False):
        """Gets the constant from the profile.

        The windows profile specify addresses relative to the kernel image base.
        """
        base_constant = super(RelativeOffsetMixin, self).get_constant(name)
        if is_address and isinstance(base_constant, (int, long)):
            return base_constant + self.GetImageBase()

        return base_constant

    def get_nearest_constant_by_address(self, address):
        if address < self.GetImageBase():
            return 0, ""

        try:
            offset, name = super(
                RelativeOffsetMixin, self).get_nearest_constant_by_address(
                address - self.GetImageBase())

            return offset + self.GetImageBase(), name
        except ValueError:
            return self.GetImageBase(), "image_base"


class BasicPEProfile(RelativeOffsetMixin, basic.BasicClasses):
    """A basic profile for a pe image.

    This profile deals with Microsoft Oddities like name mangling, and
    correcting global offsets to the base image address.
    """

    image_base = 0

    METADATA = dict(os="windows")

    def GetImageBase(self):
        return self.image_base

    def GuessArchitecture(self):
      """Guesses the architecture of this profile."""

    STRING_MANGLE_MAP = {
        "^0": ",",
        "^2": r"\\",
        "^4": ".",
        "^3": ":",
        "^5": "_",  # Really space.
        "^6": ".",  # Really \n.
        r"\$AA": "",
        r"\$AN": "", # Really \r.
        r"\$CF": "%",
        r"\$EA": "@",
        r"\$CD": "#",
        r"\$CG": "&",
        r"\$HO": "~",
        r"\$CI": "(",
        r"\$CJ": ")",
        r"\$DM1": "</",
        r"\$DMO": ">",
        r"\$DN": "=",
        r"\$CK": "*",
        r"\$CB": "!",

        }

    def _UnpackMangledString(self, string):
        string = string.split("@")[3]

        result = []
        for cap in string.split("?"):
            for k, v in self.STRING_MANGLE_MAP.items():
                cap = re.sub(k, v, cap)

            result.append(cap)

        return "str:" + "".join(result).strip()

    SIMPLE_X86_CALL = re.compile(r"[_@]([A-Za-z0-9_]+)@\d+")
    def DemangleName(self, mangled_name):
      """Returns the de-mangled name.

      At this stage we don't really do proper demangling since we usually dont
      care about the prototype, nor c++ exports. In the future we should though.
      """
      m = self.SIMPLE_X86_CALL.match(mangled_name)
      if m:
          # If we see x86 name mangling (_cdecl, __stdcall) this is definitely a
          # 32 bit pdb since those do not exist on AMD64. Sometimes we dont know
          # the architecture of the pdb file for example if we do not have the
          # original binary, but on the GUID as extracted by version_scan.
          self._metadata.setdefault("arch", "I386")

          return m.group(1)

      if mangled_name.startswith("??_C@"):
          return self._UnpackMangledString(mangled_name)

      return mangled_name

    def add_constants(self, **kwargs):
        """Add the demangled constants.

        This allows us to handle 32 bit vs 64 bit constant names easily since
        the mangling rules are different.
        """
        result = {}
        for k, v in kwargs.iteritems():
            result[self.DemangleName(k)] = v

        super(BasicPEProfile, self).add_constants(**result)

    @classmethod
    def Initialize(cls, profile):
        super(BasicPEProfile, cls).Initialize(profile)

        # Version specific support.
        try:
            version = ".".join(profile.metadatas("major", "minor"))
        except TypeError:
            # We have no idea what version it is, this can happen if we were
            # just given a GUID and a pdb file without a kernel executable.
            version = "6.1"

        profile.set_metadata("version", version)

        # Add the basic compiler model for windows.
        if profile.metadata("arch") == "AMD64":
            basic.ProfileLLP64.Initialize(profile)

        elif profile.metadata("arch") == "I386":
            basic.Profile32Bits.Initialize(profile)

            # Detect if this is a PAE system. PAE systems have 64 bit PTEs:
            if profile.get_obj_size("_MMPTE") == 8:
                profile.set_metadata("pae", True)


class Ntoskrnl(BasicPEProfile):
    """A profile for Windows."""

    @classmethod
    def Initialize(cls, profile):
        super(Ntoskrnl, cls).Initialize(profile)

        # Add undocumented types.
        if profile.metadata("arch") == "AMD64":
            profile.add_types(undocumented.AMD64)

        elif profile.metadata("arch") == "I386":
            profile.add_types(undocumented.I386)

        # Install the base windows support.
        common.InitializeWindowsProfile(profile)

        InstallKDDebuggerProfile(profile)

        version = profile.metadata("version")
        if version in ("6.2", "6.3"):
            win8.InitializeWindows8Profile(profile)

        elif version == "6.1":
            win7.InitializeWindows7Profile(profile)

        elif version == "6.0":
            vista.InitializeVistaProfile(profile)

        elif version in ("5.2", "5.1"):
            xp.InitializeXPProfile(profile)

    def GetImageBase(self):
        return self.session.GetParameter("kernel_base")
