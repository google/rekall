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
import string
import os
import filelock
from rekall_agent import location


class FileLocation(location.Location):
    """A Location specifier that handles file paths on the local filesystem.

    Note that this does not work remotely and so it is mostly useful for tests.
    """
    schema = [
        dict(name="path",
             doc="The file path on the local filesystem."),
    ]

    MAX_FILE_SIZE = 100 * 1024 * 1024
    BUFFSIZE = 1 * 1024 * 1024

    @property
    def full_path(self):
        """Expand the provided path using the agent state."""
        state = self._session.GetParameter("AgentState")
        result = []
        for pre, var, _, _ in string.Formatter().parse(self.path):
            result.append(pre)
            if var is not None:
                expansion = state.GetMember(var)
                # We may only expand a FileLocation into another FileLocation.
                if not isinstance(expansion, self.__class__):
                    raise TypeError(
                        "Unable to expand value of type %s into %s" % (
                            type(expansion), self.__class__))

                result.append(expansion.full_path)

        return "".join(result)

    def to_path(self):
        return self.path

    def _ensure_dir_exists(self):
        """Create intermediate directories to the ultimate path."""
        dirname = os.path.dirname(self.path)
        try:
            os.makedirs(dirname)
        except (OSError, IOError):
            pass

    def read_file(self):
        # Assume that the file is not too large.
        try:
            return open(self.full_path).read(
                self._session.GetParameter("max_file_size", self.MAX_FILE_SIZE))
        except (IOError, OSError):
            pass

    def write_file(self, data):
        self._ensure_dir_exists()

        with open(self.full_path, "wb") as fd:
            fd.write(data)

    def read_modify_write_local_file(self, modification_cb, *args):
        self._ensure_dir_exists()
        lock = filelock.FileLock(self.to_path() + ".lock")
        try:
            with lock.acquire():
                modification_cb(self.to_path(), *args)
        except OSError:
            modification_cb(self.to_path(), *args)

    def upload_local_file(self, local_filename, completion_routine=None,
                          delete=True):
        status = location.Status()
        try:
            if completion_routine is None:
                completion_routine = lambda x: x

            # Only copy the files if they are not the same.
            if local_filename != self.full_path:
                self._ensure_dir_exists()

                with open(local_filename, "rb") as infd:
                    with open(self.full_path, "wb") as outfd:
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

        except Exception as e:
            status = location.Status(500, unicode(e))

        # Done - report status.
        completion_routine(status)

    def upload_file_object(self, infd, completion_routine=None, subpath=None):
        status = location.Status()
        try:
            if completion_routine is None:
                completion_routine = lambda x: x

            full_path = self.full_path
            if subpath:
                full_path = os.path.join(full_path, subpath.lstrip(os.path.sep))

            dirname = os.path.dirname(full_path)
            try:
                os.makedirs(dirname)
            except (OSError, IOError):
                pass

            with open(full_path, "wb") as outfd:
                while 1:
                    data = infd.read(self.BUFFSIZE)
                    if not data:
                        break

                    outfd.write(data)

            self._session.logging.warn("Uploaded %s", full_path)

        except Exception as e:
            self._session.logging.warn("Unable to write %s: %s", full_path, e)
            status = location.Status(500, unicode(e))

        # Done - report status.
        completion_routine(status)

    def get_local_filename(self):
        # We are already present locally.
        return self.full_path
