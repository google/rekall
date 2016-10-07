# Rekall Memory Forensics
# Copyright 2016 Google Inc. All Rights Reserved.
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

"""Declares all the modes Rekall can be in.

The Rekall session can exist in several modes at the same time. Modes are just
simple True/False flags that represent certain aspects of the Rekall
session. For example, a session may be in "mode_image" if it is dealing with an
image.

Plugins can then activate depending on the current mode vector. For example, a
plugin may declare that it is active if all these modes are set
"mode_image,mode_windows_memory" Which means it is only active if a windows
memory image is used.
"""


from rekall import kb

from rekall.plugins.filesystems import ntfs
from rekall.plugins.filesystems import tsk


class NTFSMode(kb.ParameterHook):
    name = "mode_ntfs"

    def calculate(self):
        return isinstance(self.session.profile, ntfs.NTFSProfile)



class TSKMode(kb.ParameterHook):
    name = "mode_tsk"

    def calculate(self):
        return isinstance(self.session.profile, tsk.TSKProfile)



class WinXPMode(kb.ParameterHook):
    name = "mode_xp"

    def calculate(self):
        return self.session.profile.metadata("major") == 5


class AMD64Mode(kb.ParameterHook):
    name = "mode_amd64"

    def calculate(self):
        return self.session.profile.metadata("arch") == "AMD64"


class WinMode(kb.ParameterHook):
    name = "mode_windows"

    def calculate(self):
        return self.session.profile.metadata("os") == "windows"


class LinMode(kb.ParameterHook):
    name = "mode_linux"

    def calculate(self):
        return self.session.profile.metadata("os") == "linux"


class DarwinMode(kb.ParameterHook):
    name = "mode_darwin"

    def calculate(self):
        return self.session.profile.metadata("os") == "darwin"


class LiveMode(kb.ParameterHook):
    name = "mode_live"

    def calculate(self):
        return bool(self.session.GetParameter("live_mode"))



class LiveMemoryMode(kb.ParameterHook):
    name = "mode_live_memory"

    def calculate(self):
        return self.session.GetParameter("live_mode") == "Memory"


class LiveAPIMode(kb.ParameterHook):
    name = "mode_live_api"

    def calculate(self):
        return self.session.GetParameter("live_mode") == "API"


class ImageMode(kb.ParameterHook):
    """Determines if we are reading from an image."""
    name = "mode_image"

    def calculate(self):
        # If there is no physical address space but a filename was specified we
        # try to load the physical_address_space from the filename.
        if (not self.session.physical_address_space and
            self.session.GetParameter("filename")):
            self.session.plugins.load_as().GetPhysicalAddressSpace()

        return (self.session.physical_address_space and
                self.session.physical_address_space.metadata("image"))


class VistaMode(kb.ParameterHook):
    name = "mode_vista_plus"

    def calculate(self):
        return self.session.profile.metadata("major") >= 6


class WinMemoryMode(kb.ParameterHook):
    """Windows memory image or live windows."""
    name = "mode_windows_memory"

    def calculate(self):
        return (self.session.GetParameter("mode_live_memory") or
                self.session.GetParameter("mode_image")) and (
                    self.session.GetParameter("mode_windows"))


class LinMemoryMode(kb.ParameterHook):
    """Windows memory image or live windows."""
    name = "mode_linux_memory"

    def calculate(self):
        return (self.session.GetParameter("mode_live_memory") or
                self.session.GetParameter("mode_image")) and (
                    self.session.GetParameter("mode_linux"))


class DarwinMemoryMode(kb.ParameterHook):
    """Windows memory image or live windows."""
    name = "mode_darwin_memory"

    def calculate(self):
        return (self.session.GetParameter("mode_live_memory") or
                self.session.GetParameter("mode_image")) and (
                    self.session.GetParameter("mode_darwin"))


class MountainLionMode(kb.ParameterHook):
    """Windows memory image or live windows."""
    name = "mode_darwin_mountain_lion_plus"

    def calculate(self):
        return (self.session.profile.get_constant("_BootPML4", False) and
                self.session.GetParameter("mode_darwin_memory"))
