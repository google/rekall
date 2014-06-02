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

import logging
import os

from rekall import config
from rekall import obj
from rekall.plugins.linux import common
from rekall.plugins.overlays.linux import vfs


__author__ = "Jordi Sanchez <parki.san@gmail.com>"


def InodeToPermissionString(inode):
    """Represents an inode's permisions as an ls-like string."""

    result = []
    if inode.type == "S_IFSOCK":
        result.append("s")
    elif inode.type == "S_IFLNK":
        result.append("l")
    elif inode.type == "S_IFREG":
        result.append("-")
    elif inode.type == "S_IFBLK":
        result.append("b")
    elif inode.type == "S_IFDIR":
        result.append("d")
    elif inode.type == "S_IFCHR":
        result.append("c")
    elif inode.type == "S_IFIFO":
        result.append("f")

    result.append("r" if inode.mode.S_IRUSR else "-")
    result.append("w" if inode.mode.S_IWUSR else "-")
    if inode.mode.S_ISUID:
        result.append("s" if inode.mode.S_IXUSR else "S")
    else:
        result.append("x" if inode.mode.S_IXUSR else "-")

    result.append("r" if inode.mode.S_IRGRP else "-")
    result.append("w" if inode.mode.S_IWGRP else "-")
    if inode.mode.S_ISGID:
        result.append("s" if inode.mode.S_IXGRP else "S")
    else:
        result.append("x" if inode.mode.S_IXGRP else "-")

    result.append("r" if inode.mode.S_IROTH else "-")
    result.append("w" if inode.mode.S_IWOTH else "-")
    result.append("x" if inode.mode.S_IXOTH else "-")
    if inode.mode.S_ISVTX:
        result.append("t" if inode.mode.S_IXOTH else "T")

    return ''.join(result)


class Mfind(common.LinuxPlugin):
    """Finds a file by name in memory."""
    __name = "mfind"

    @classmethod
    def args(cls, parser):
        """Declare the command line args we accept."""
        super(Mfind, cls).args(parser)
        parser.add_argument("path", default="/",
            help="Path to the file.")
        parser.add_argument(
            "--device", default=None,
            help="Name of the device to match.")

    def __init__(self, path="/", device=None, **kwargs):
        super(Mfind, self).__init__(**kwargs)
        self.path = path
        self.device = device

    def find(self, path, device=None, mountpoint=None):
        """Returns a list of files matching the path on the given mountpoint.
        
        If no mountpoint is specified, all mountpoints are searched.
        This is akin to doing ls -ld, except that a list is returned because
        several mount points may hold files which are candidates for such path.
        """

        if not mountpoint:
            mount_plugin = self.session.plugins.mount(session=self.session)
            mountpoints = mount_plugin.get_mount_points()
        else:
            mountpoints = [mountpoint]

        for mountpoint in mountpoints:
            if (device and not device == mountpoint.device):
                continue

            if (path and not path.startswith(unicode(mountpoint.name))):
                continue

            current_file = vfs.File(mountpoint=mountpoint,
                                    dentry=mountpoint.sb.s_root,
                                    is_root=True)

            if path == unicode(mountpoint.name):
                # Return a file for the mountpoint root
                yield current_file
            else:
                remaining_path = path[len(mountpoint.name):]
                traversal_list = remaining_path.split("/")

                i = 0
                found = True
                while i < len(traversal_list):
                    component_to_search = traversal_list[i]
                    if component_to_search == "." or not component_to_search:
                        i += 1
                        continue

                    found = False
                    for file_ in current_file.walk():
                        if file_.name == component_to_search:
                            found = True
                            current_file = file_

                    i += 1

                # We've found the file 
                if found:
                    yield current_file

    def render(self, renderer):
        mount_plugin = self.session.plugins.mount(session=self.session)
        mountpoints = mount_plugin.get_mount_points()

        for mountpoint in mountpoints:
            files = list(self.find(self.path,
                                   device=self.device,
                                   mountpoint=mountpoint))

            if files:
                renderer.write("Files on device %s mounted at %s.\n" % (
                    mountpoint.device, mountpoint.name))

                self.render_file_header(renderer)
                for file_ in files:
                    self.render_file(renderer, file_)

    def render_file_header(self, renderer):
        renderer.table_header([
            ("Perms", "perms", "11"),
            ("uid", "uid", ">10"),
            ("gid", "gid", ">10"),
            ("size", "size", ">14"),
            ("mtime", "mtime", "24"),
            ("atime", "atime", "24"),
            ("ctime", "ctime", "24"),
            ("inode", "inode", ">10"),
            ("path", "path", "<60"),
            ])

    def render_file(self, renderer, file_):
        inode = file_.dentry.d_inode
        fullpath = file_.fullpath
        atime_string = self.session.profile.UnixTimeStamp(
            value=inode.i_atime.tv_sec)
        mtime_string = self.session.profile.UnixTimeStamp(
            value=inode.i_mtime.tv_sec)
        ctime_string = self.session.profile.UnixTimeStamp(
            value=inode.i_ctime.tv_sec)

        renderer.table_row(InodeToPermissionString(inode),
                           inode.i_uid, inode.i_gid,
                           inode.i_size, mtime_string, atime_string,
                           ctime_string, inode.i_ino, fullpath)



class Mls(Mfind):
    """Lists the files in a mounted filesystem."""
    __name = "mls"

    @classmethod
    def args(cls, parser):
        """Declare the command line args we accept."""
        super(Mls, cls).args(parser)
        parser.add_argument("-r", "--recursive", default=False,
            action="store_true", help="Recursive listing")
        parser.add_argument("-u", "--unallocated", default=False,
                            action="store_true",
                            help="Show files that have no inode information.")

    def __init__(self, unallocated=False, recursive=False, device=None,
                 path="/", **kwargs):
        super(Mls, self).__init__(**kwargs)
        self.device = device
        self.path = path
        self.recursive = recursive
        self.unallocated = unallocated

    def render(self, renderer):
        mfind_plugin = self.session.plugins.mfind(session=self.session)
        for entry in mfind_plugin.find(path=self.path, device=self.device):
            renderer.write("Files on device %s mounted at %s.\n" % (
                entry.mountpoint.device, entry.mountpoint.name))

            self.render_file_header(renderer)

            if not entry.is_directory():
                self.render_file(renderer, entry)
            else:
                for file_ in entry.walk(recursive=self.recursive,
                                        unallocated=self.unallocated):
                    self.render_file(renderer, file_)
            renderer.section()
