# Rekall Memory Forensics
#
# Copyright 2015 Google Inc. All Rights Reserved.
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
"""Miscelaneous information gathering plugins."""

__author__ = "Michael Cohen <scudette@google.com>"

import hashlib
from rekall import obj
from rekall.plugins import core
from rekall.plugins.linux import common

class LinuxSetProcessContext(core.SetProcessContextMixin,
                             common.LinProcessFilter):
    """A cc plugin for windows."""


class LinVtoP(core.VtoPMixin, common.LinProcessFilter):
    """Describe virtual to physical translation on Linux platforms."""


class LinuxHighestUserAddress(common.AbstractLinuxParameterHook):
    """The highest address for user mode/kernel mode division."""

    name = "highest_usermode_address"

    def calculate(self):
        """Returns TASK_SIZE_MAX."""
        arch = self.session.profile.metadata("arch")
        if arch == "I386" or arch == "ARM":
            return self.session.GetParameter("linux_page_offset")
        elif arch == "AMD64":
            # #define TASK_SIZE_MAX   ((1UL << 47) - PAGE_SIZE)
            return (1 << 47) - 0x1000
        else:
            self.session.logging.warn("Set TASK_SIZE_MAX for arch %s", arch)
            return 2**64


class LinImageFingerprint(common.AbstractLinuxParameterHook):
    """Fingerprint the current image.

    This parameter tries to get something unique about the image quickly. The
    idea is that two different images (even of the same system at different
    points in time) will have very different fingerprints. The fingerprint is
    used as a key to cache persistent information about the system.

    Live systems can not have a stable fingerprint and so return a NoneObject()
    here.

    We return a list of tuples:
       (physical_offset, expected_data)

    The list uniquely identifies the image. If one were to read all physical
    offsets and find the expected_data at these locations, then we have a very
    high level of confidence that the image is unique and matches the
    fingerprint.
    """
    name = "image_fingerprint"

    def calculate(self):
        if not self.session.physical_address_space:
            return None

        if self.session.physical_address_space.volatile:
            return obj.NoneObject("No fingerprint for volatile image.")

        result = []
        profile = self.session.profile
        address_space = self.session.GetParameter("default_address_space")

        banner = profile.get_constant_object("linux_banner", "String")
        result.append((address_space.vtop(banner.obj_offset), banner.v()))

        # Current system tick count.
        jiffies = profile.get_constant_object("jiffies", "String",
                                              dict(length=8, term=None))
        result.append((address_space.vtop(jiffies.obj_offset), jiffies.v()))

        # List of processes should also be pretty unique.
        for task in self.session.plugins.pslist().filter_processes():
            name = task.name.cast("String", length=30)
            task_name_offset = address_space.vtop(name.obj_offset)

            # Read the raw data for the task name. Usually the task name is
            # encoded in utf8 but then we might not be able to compare it
            # exactly - we really want bytes here.
            result.append((task_name_offset, name.v()))

        return dict(
            hash=hashlib.sha1(unicode(result).encode("utf8")).hexdigest(),
            tests=result)
