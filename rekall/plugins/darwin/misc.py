# Rekall Memory Forensics
#
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
"""Miscelaneous information gathering plugins."""

__author__ = "Michael Cohen <scudette@google.com>"
import re

from rekall import obj
from rekall.plugins.darwin import common


class DarwinDMSG(common.DarwinPlugin):
    """Print the kernel debug messages."""

    __name = "dmesg"

    def render(self, renderer):
        renderer.table_header([
                ("Message", "message", "<80")])

        # This is a circular buffer with the write pointer at the msg_bufx
        # member.
        msgbuf = self.profile.get_constant_object(
            "_msgbufp",
            target="Pointer",
            target_args=dict(
                target="msgbuf"
                )
            )

        # Make sure the buffer is not too large.
        size = min(msgbuf.msg_size, 0x400000)
        if 0 < msgbuf.msg_bufx < size:
            data = self.kernel_address_space.read(msgbuf.msg_bufc, size)
            data = data[msgbuf.msg_bufx: size] + data[0:msgbuf.msg_bufx]
            data = re.sub("\x00", "", data)

            for x in data.splitlines():
                renderer.table_row(x)


class DarwinMachineInfo(common.DarwinPlugin):
    """Show information about this machine."""

    __name = "machine_info"

    def render(self, renderer):
        renderer.table_header([("Attribute", "attribute", "20"),
                               ("Value", "value", "10")])

        info = self.profile.get_constant_object(
            "_machine_info", "machine_info")

        for member in info.members:
            renderer.table_row(member, info.m(member))


class DarwinMount(common.DarwinPlugin):
    """Show mount points."""

    __name = "mount"

    def render(self, renderer):
        renderer.table_header([
                ("Device", "device", "30"),
                ("Mount Point", "mount_point", "60"),
                ("Type", "type", "")])

        mount_list = self.profile.get_constant_object(
            "_mountlist", "mount")

        for mount in mount_list.walk_list("mnt_list.tqe_next", False):
            renderer.table_row(mount.mnt_vfsstat.f_mntonname,
                               mount.mnt_vfsstat.f_mntfromname,
                               mount.mnt_vfsstat.f_fstypename)
