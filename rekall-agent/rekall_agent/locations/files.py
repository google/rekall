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

"""Location handlers.

A location is an object which handles file transfer to a specific place.
"""
import os
import filelock
from rekall_agent import common
from rekall_lib.types import location


class FileLocationImpl(location.FileLocation):
    """A Location specifier that handles file paths on the local filesystem.

    Note that this does not work remotely and so it is mostly useful for tests.
    """
    schema = [
        dict(name="path_prefix",
             doc="The path prefix to enforce."),

        dict(name="path_template", default="",
             doc="The path template to expand."),
    ]

    MAX_FILE_SIZE = 100 * 1024 * 1024
    BUFFSIZE = 1 * 1024 * 1024

    def expand_path(self, **kwargs):
        """Expand the complete path using the client's config."""
        return self.path_template.format(
            **common.Interpolator(self._session, **kwargs))

    def to_path(self, **kwargs):
        # We really want the expansion to be a subdir of the path
        # prefix - even if it has a drive on windows.
        expansion = self.expand_path(**kwargs)
        _, expansion = os.path.splitdrive(expansion)
        expansion = expansion.lstrip(os.path.sep)
        if not expansion:
            return self.path_prefix

        return os.path.join(self.path_prefix, expansion)

    def _ensure_dir_exists(self, path):
        """Create intermediate directories to the ultimate path."""
        dirname = os.path.dirname(path)
        try:
            os.makedirs(dirname)
        except (OSError, IOError):
            pass

    def read_file(self, **kwargs):
        # Assume that the file is not too large.
        try:
            return open(self.to_path(**kwargs)).read(
                self._session.GetParameter("max_file_size", self.MAX_FILE_SIZE))
        except (IOError, OSError):
            pass

    def write_file(self, data, **kwargs):
        path = self.to_path(**kwargs)
        self._ensure_dir_exists(path)

        with open(path, "wb") as fd:
            fd.write(data)

    def read_modify_write_local_file(self, modification_cb, *args, **kwargs):
        path = self.to_path(**kwargs)
        self._ensure_dir_exists(path)
        try:
            lock = filelock.FileLock(path + ".lock")
            with lock.acquire():
                modification_cb(path, *args)
        except OSError:
            modification_cb(path, *args)

    def upload_local_file(self, local_filename, delete=True, **kwargs):
        path = self.to_path(**kwargs)
        # Only copy the files if they are not the same.
        if local_filename != path:
            self._ensure_dir_exists(path)

            with open(local_filename, "rb") as infd:
                with open(path, "wb") as outfd:
                    while 1:
                        data = infd.read(self.BUFFSIZE)
                        if not data:
                            break

                        outfd.write(data)

            # Remove the local copy if the caller does not care about it any
            # more.
            if delete:
                self._session.logging.debug("Removing local file %s",
                                        local_filename)
                os.unlink(local_filename)

    def upload_file_object(self, infd, **kwargs):
        path = self.to_path(**kwargs)
        self._ensure_dir_exists(path)

        with open(path, "wb") as outfd:
            while 1:
                data = infd.read(self.BUFFSIZE)
                if not data:
                    break

                outfd.write(data)

        self._session.logging.warn("Uploaded %s", path)

    def get_local_filename(self, **kwargs):
        # We are already present locally.
        return self.to_path(**kwargs)
