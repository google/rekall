#!/usr/bin/env python2

# Rekall Memory Forensics
# Copyright 2016 Google Inc. All Rights Reserved.
#
# Author: Michael Cohen scudette@google.com
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

__author__ = "Michael Cohen <scudette@google.com>"

"""File operations using the Sleuthkit.

These client actions are designed to maintain the client's Virtual File System
(VFS) view.
"""
import os
import pytsk3
from rekall.plugins.common.efilter_plugins import helpers
from rekall_agent.client_actions import files


FILE_TYPE_LOOKUP = {
    pytsk3.TSK_FS_NAME_TYPE_UNDEF: "-",
    pytsk3.TSK_FS_NAME_TYPE_FIFO: "p",
    pytsk3.TSK_FS_NAME_TYPE_CHR: "c",
    pytsk3.TSK_FS_NAME_TYPE_DIR: "d",
    pytsk3.TSK_FS_NAME_TYPE_BLK: "b",
    pytsk3.TSK_FS_NAME_TYPE_REG: "r",
    pytsk3.TSK_FS_NAME_TYPE_LNK: "l",
    pytsk3.TSK_FS_NAME_TYPE_SOCK: "h",
    pytsk3.TSK_FS_NAME_TYPE_SHAD: "s",
    pytsk3.TSK_FS_NAME_TYPE_WHT: "w",
    pytsk3.TSK_FS_NAME_TYPE_VIRT: "v"
}

META_TYPE_LOOKUP = {
    pytsk3.TSK_FS_META_TYPE_REG: "r",
    pytsk3.TSK_FS_META_TYPE_DIR: "d",
    pytsk3.TSK_FS_META_TYPE_FIFO: "p",
    pytsk3.TSK_FS_META_TYPE_CHR: "c",
    pytsk3.TSK_FS_META_TYPE_BLK: "b",
    pytsk3.TSK_FS_META_TYPE_LNK: "h",
    pytsk3.TSK_FS_META_TYPE_SHAD: "s",
    pytsk3.TSK_FS_META_TYPE_SOCK: "s",
    pytsk3.TSK_FS_META_TYPE_WHT: "w",
    pytsk3.TSK_FS_META_TYPE_VIRT: "v"
}

ATTRIBUTE_TYPES_TO_PRINT = [
    pytsk3.TSK_FS_ATTR_TYPE_NTFS_IDXROOT,
    pytsk3.TSK_FS_ATTR_TYPE_NTFS_DATA,
    pytsk3.TSK_FS_ATTR_TYPE_DEFAULT]


class TSKListDirectoryAction(files.ListDirectoryAction):
    """List Directory via TSK."""
    schema = [
        dict(name="path",
             doc="The name of the directory to list. If a device is also give, "
             "the name is relative to this device otherwise we resolve mount "
             "points to deduce right the name and device."),

        dict(name="device",
             doc="The path to the device to use"),

        dict(name="offset", type="int",
             doc="A device offset to use."),

        dict(name="inode",
             doc="Alternatively an inode may be given."),

    ]

    # We ignore these filenames because they are special TSK virtual files.
    BLACKLIST_FILES = ["$OrphanFiles"]

    def _open_directory(self):
        device = self.device
        self._mntpoint = "/"

        if not device:
            mount_tree = self._session.GetParameter("mount_points")
            device, self._mntpoint, _ = files.lookup_mount_point(
                mount_tree, self.path)

        self._img_info = pytsk3.Img_Info(device)
        self._fs_info = pytsk3.FS_Info(self._img_info, offset=self.offset)

        if self.inode:
            return self._fs_info.open_dir(inode=self.inode)
        else:
            return self._fs_info.open_dir(
                path=os.path.relpath(self.path, self._mntpoint))

    def _process_dirent(self, dirent, dirname=None, stack=None, depth=0):
        if stack is None:
            stack = []

        if depth > self.depth:
            return

        # Make sure we do not recurse into this very directory again.
        stack.append(dirent.info.addr)
        try:
            for fileent in dirent:
                try:
                    info = fileent.info
                    meta = info.meta
                    name = info.name.name
                except AttributeError:
                    continue

                if name in [".", ".."] or name in self.BLACKLIST_FILES:
                    continue

                if meta:
                    result = dict(filename=name, dirname=dirname)
                    result["st_ino"] = meta.addr
                    for attribute in ["mode", "nlink", "uid", "gid", "size",
                                      "atime", "mtime", "ctime", "crtime"]:
                        try:
                            value = int(getattr(meta, attribute))
                            if value < 0:
                                value &= 0xFFFFFFFF

                            result["st_%s" % attribute] = value
                        except AttributeError:
                            pass

                    yield result

                    if self.recursive:
                        # We already did this directory.
                        if result["st_ino"] in stack:
                            continue

                        try:
                            sub_directory = fileent.as_directory()
                            # Yes this is actually a directory - recurse it.
                            for x in self._process_dirent(
                                    sub_directory,
                                    os.path.join(dirname, name),
                                    stack=stack,
                                    depth=depth+1):
                                yield x
                        except IOError:
                            pass

        finally:
            stack.pop(-1)

    def collect(self):
        dirent = self._open_directory()
        for x in helpers.ListFilter().filter(
                self.filter,
                self._process_dirent(dirent, dirname=self.path)):
            yield x
