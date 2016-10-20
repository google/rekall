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
"""This module implements filesystem-related plugins for Linux."""

from rekall import testlib

from rekall.plugins import core
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
    else:
        result.append(" ")

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

    return "".join(result)


class Mfind(common.LinuxPlugin):
    """Finds a file by name in memory."""

    __name = "mfind"

    __args = [
        dict(name="path", default="/", positional=True,
             help="Path to the file."),
        dict(name="device",
             help="Name of the device to match.")
    ]

    table_header = [
        dict(name="divider", type="Divider"),
        dict(name="device", hidden=True),
        dict(name="mount", hidden=True),
        dict(name="perms", width=11),
        dict(name="uid", width=10, align="r"),
        dict(name="gid", width=10, align="r"),
        dict(name="size", width=14, align="r"),
        dict(name="mtime", width=24),
        dict(name="atime", width=24),
        dict(name="ctime", width=24),
        dict(name="inode", width=10, align="r"),
        dict(name="file", hidden=True),
        dict(name="path"),
    ]


    def find(self, path, device=None, mountpoint=None):
        """Yields a list of files matching the path on the given mountpoint.

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
            if device != None and mountpoint.device != device:
                continue

            if path and not path.startswith(unicode(mountpoint.name)):
                continue

            current_file = vfs.File(mountpoint=mountpoint,
                                    dentry=mountpoint.sb.s_root,
                                    is_root=True,
                                    session=self.session)

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

                if found:
                    yield current_file

    def collect(self):
        mount_plugin = self.session.plugins.mount(session=self.session)
        mountpoints = mount_plugin.get_mount_points()

        for mountpoint in mountpoints:
            files = list(self.find(self.plugin_args.path,
                                   device=self.plugin_args.device,
                                   mountpoint=mountpoint))

            if files:
                divider = "Files on device %s mounted at %s.\n" % (
                    mountpoint.device, mountpoint.name)
                yield dict(divider=divider)

                for file_ in files:
                    yield self.collect_file(mountpoint, file_)

    def collect_file(self, mountpoint, file_):
        inode = file_.dentry.d_inode
        fullpath = file_.fullpath
        atime = self.session.profile.UnixTimeStamp(
            value=inode.i_atime.tv_sec)
        mtime = self.session.profile.UnixTimeStamp(
            value=inode.i_mtime.tv_sec)
        ctime = self.session.profile.UnixTimeStamp(
            value=inode.i_ctime.tv_sec)

        return dict(perms=InodeToPermissionString(inode),
                    uid=inode.i_uid, gid=inode.i_gid,
                    size=inode.i_size, mtime=mtime,
                    atime=atime, ctime=ctime,
                    inode=inode.i_ino,
                    path=fullpath,
                    device=mountpoint.device,
                    file=file_,
                    mount=mountpoint.name)


class Mls(Mfind):
    """Lists the files in a mounted filesystem."""

    __name = "mls"

    __args = [
        dict(name="recursive", type="Boolean",
             help="Recursive listing"),
        dict(name="unallocated", type="Boolean",
             help="Show files that have no inode information."),
    ]

    def collect(self):
        for file_info in super(Mls, self).collect():
            entry = file_info.get("file")
            if entry:
                yield dict(
                    divider="Files on device %s mounted at %s.\n" % (
                        entry.mountpoint.device, entry.mountpoint.name))

                if not entry.is_directory():
                    yield self.collect_file(entry.mountpoint, entry)
                else:
                    for file_ in entry.walk(
                            recursive=self.plugin_args.recursive,
                            unallocated=self.plugin_args.unallocated):
                        yield self.collect_file(entry.mountpoint, file_)


class Mcat(core.DirectoryDumperMixin, Mfind):
    """Returns the contents available in memory for a given file.

    Ranges of the file that are not present in memory are returned blank.
    """

    __name = "mcat"

    table_header = [
        dict(name="start", width=12),
        dict(name="end", width=12),
        dict(name="path", width=80),
        dict(name="dump_name", width=80),
    ]

    def collect(self):
        renderer = self.session.GetRenderer()
        for file_info in super(Mcat, self).collect():
            file_obj = file_info.get("file")
            if not file_obj:
                continue

            page_size = self.session.kernel_address_space.PAGE_SIZE
            buffer_size = 1024*1024
            buffer = ""

            # Write buffered output as a sparse file.
            path = file_info["path"]
            with renderer.open(
                    filename=path,
                    directory=self.plugin_args.dump_dir,
                    mode="wb") as fd:

                for range_start, range_end in file_obj.extents:
                    yield dict(start=range_start, end=range_end,
                               path=path, dump_name=fd.name)

                    fd.seek(range_start)
                    for offset in range(range_start, range_end, page_size):
                        page_index = offset / page_size
                        to_write = min(page_size, file_obj.size - offset)
                        data = file_obj.GetPage(page_index)
                        if data != None:
                            buffer += data[:to_write]
                        else:
                            buffer += "\x00" * to_write

                        # Dump the buffer when it's full.
                        if len(buffer) >= buffer_size:
                            fd.write(buffer)
                            buffer = ""

                    # Dump the remaining data in the buffer.
                    if buffer != "":
                        fd.write(buffer)
                        buffer = ""


class TestMfind(testlib.HashChecker):
    PARAMETERS = dict(
        commandline="mfind %(file)s"
        )


class TestMls(testlib.HashChecker):
    PARAMETERS = dict(
        commandline="mls %(file)s"
        )


class TestMcat(testlib.HashChecker):
    PARAMETERS = dict(
        commandline="mcat %(file)s --dump_dir %(tempdir)s"
        )
