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
import os

from rekall.plugins.response import common  as response_common

from rekall_agent import action
from rekall_agent import location
from rekall_agent import result_collections


class StatEntryCollection(result_collections.GenericSQLiteCollection):
    """A collection of files' stat entries."""
    _tables = [dict(
        name="default",
        columns=[
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
        ]
    )]


class ListDirectoryAction(action.Action):
    """List a directory and store it in the client's VFS."""
    schema = [
        dict(name="path",
             doc="The name of the directory to list."),

        dict(name="recursive", type="bool",
             doc="If set we recursively list all directories."),

        dict(name="vfs_location", type=location.Location,
             doc="The vfs location where we write the collection."),
    ]

    def upload_directory(self, directory):
        print "Processing %s" % directory.filename
        for item in directory.list():
            self._collection.insert(row=item)

            # Recursively upload the directory.
            if self.recursive and item.st_mode.is_dir():
                self.upload_directory(item)

    def run(self):
        self._collection = StatEntryCollection(session=self._session)
        self._collection.location = self.vfs_location.copy()
        with self._collection.create_temp_file():
            root_dir = response_common.FileFactory(
                response_common.FileSpec(self.path, path_sep=os.path.sep),
                session=self._session)

            if root_dir.st_mode.is_dir():
                self.upload_directory(root_dir)

        return [self._collection]
