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

"""File operations.

These client actions are designed to maintain the client's Virtual File System
(VFS) view.
"""
import re
import os

import psutil

from rekall import kb
from rekall import utils
from rekall.plugins.common.efilter_plugins import helpers

from rekall_agent import action
from rekall_agent import location
from rekall_agent import result_collections


class StatEntryCollection(result_collections.GenericSQLiteCollection):
    """A collection of files' stat entries."""
    _tables = [dict(
        name="default",
        columns=[
            dict(name="dirname", type="unicode"),
            dict(name="filename", type="unicode"),
            dict(name="st_mode", type="int"),
            dict(name="st_mode_str", type="unicode"),
            dict(name="st_ino", type="int"),
            dict(name="st_dev", type="int"),
            dict(name="st_nlink", type="int"),
            dict(name="st_uid", type="int"),
            dict(name="st_gid", type="int"),
            dict(name="st_size", type="int"),
            dict(name="st_atime", type="epoch"),
            dict(name="st_mtime", type="epoch"),
            dict(name="st_ctime", type="epoch"),
        ],
        indexes=["dirname"],
    )]


class MountPointHook(kb.ParameterHook):
    # This is linux specific.
    mode = "mode_live"
    name = "mount_points"
    volatile = True

    def _add_to_tree(self, devices, mnt_point, device, fs_type):
        components = ["/"] + mnt_point.split("/")
        node = [devices, None]
        for component in components:
            if not component:
                continue

            next_node = node[0].get(component)
            if next_node is None:
                next_node = [{}, None]
                node[0][component] = next_node

            node = next_node

        node[1] = (device, mnt_point, fs_type)

    def calculate(self):
        """List all the filesystems mounted on the system."""
        devices = {}

        for partition in psutil.disk_partitions(all=True):
            self._add_to_tree(
                devices,
                partition.mountpoint,
                partition.device,
                partition.fstype)


def lookup_mount_point(devices, path):
    """Resolve the mount point that contains the path.

    Args:
      devices: The Tree as returned by the MountPoints hook.

    Returns:
     (device, mnt_point, fs_type) tuple.
    """
    components = ["/"] + path.split("/")
    node = [devices, None]

    for component in components:
        if not component:
            continue

        if component not in node[0]:
            return node[1]

        node = node[0][component]

    return node[1]


class ListDirectoryAction(action.Action):
    """List a directory and store it in the client's VFS.

    This essentially returns a big collection of the file's stats.
    """
    schema = [
        dict(name="path",
             doc="The name of the directory to list."),

        dict(name="recursive", type="bool",
             doc="If set we recursively list all directories."),

        dict(name="depth", type="int", default=100,
             doc="If recursing this is how deep we will go."),

        dict(name="vfs_location", type=location.Location,
             doc="The vfs location where we write the collection."),

        dict(name="filter",
             doc=("A efilter filter (everything following where clause) "
                  "to apply.")),

        dict(name="valid_filesystems", default=[
            "ext2", "ext3", "ext4", "vfat", "ntfs", "Apple_HFS", "hfs", "msdos"
        ], repeated=True,
             doc="The set of valid filesystems we may recurse into."),
    ]

    def normalize_path(self, path):
        return path.replace("\\", "/")

    drive_re = re.compile("/([a-zA-Z]:)(.*)")
    def splitdrive(self, path):
        m = self.drive_re.match(path)
        if m:
            return m.group(1), m.group(2) or "/"

        return "", path or "/"

    def listdir(self, root):
        drive, path = self.splitdrive(root)
        if not drive:
            from rekall.plugins.response import windows

            for drive in windows.get_drives():
                yield drive + os.path.sep

        else:
            for x in os.listdir(path):
                yield x

    def _process_files(self, root, files):
        drive, path = self.splitdrive(root)
        if not drive:
            from rekall.plugins.response import windows

            for drive in windows.get_drives():
                yield dict(filename=self.normalize_path(drive + os.path.sep),
                           dirname="/", st_mode=0775)

            return

        root = utils.normpath(root)
        for f in files:
            path = os.path.join(root, f)
            result = dict(
                filename=self.normalize_path(f),
                dirname=self.normalize_path(root),
                st_mode=0)

            try:
                s = os.lstat(path)
                result["st_mode"] = s.st_mode
                result["st_ino"] = s.st_ino
                result["st_dev"] = s.st_dev
                result["st_nlink"] = s.st_nlink
                result["st_uid"] = s.st_uid
                result["st_gid"] = s.st_gid
                result["st_size"] = s.st_size
                result["st_mtime"] = s.st_mtime
                result["st_ctime"] = s.st_ctime
                result["st_atime"] = s.st_atime
            except Exception:
                pass

            self._session.report_progress("Processing %s", path)
            yield result

    def collect(self):
        if self.recursive:
            for root, directories, files in os.walk(self.path):
                for x in helpers.ListFilter().filter(
                        self.filter,
                        self._process_files(root, files)):
                    yield x

                new_dirs = []
                for x in helpers.ListFilter().filter(
                        self.filter,
                        self._process_files(root, directories)):
                    yield x
                    new_dirs.append(x["filename"])

                # os.walk allows us to control recursion by mutating the
                # data list.
                directories[:] = new_dirs

        else:
            for x in helpers.ListFilter().filter(
                    self.filter,
                    self._process_files(self.path, self.listdir(self.path))):
                yield x

    def run(self, flow_obj=None):
        if not self.is_active():
            return []

        self._collection = StatEntryCollection(session=self._session)
        self._collection.location = self.vfs_location.copy()
        with self._collection.create_temp_file():
            for row in self.collect():
                self._collection.insert(**row)

        return [self._collection]
