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

"""A local cache implementation."""
import os

from rekall import cache
from rekall import plugin
from rekall_agent import serializer


class Cache(serializer.SerializedObject):
    """Base cache which does nothing."""

    def update_local_file_generation(self, path, generation, local_filename):
        raise NotImplementedError()

    def get_generation(self, path):
        raise NotImplementedError()

    def get_local_file(self, path, generation):
        raise NotImplementedError()

    def store_at_generation(self, path, generation, data=None, fd=None,
                            iterator=None):
        raise NotImplementedError()


class LocalDiskCache(Cache):
    """Manages local copies of objects on the cloud.

    Each object is stored in the cache with a generation number.
    """

    schema = [
        dict(name="cache_directory",
             doc="Where to store the cached files."),
    ]

    def __init__(self, *args, **kwargs):
        super(LocalDiskCache, self).__init__(*args, **kwargs)
        self._config = self._session.GetParameter("agent_config")
        if not self.cache_directory:
            self.cache_directory = cache.GetCacheDir(self._session)
            if not self.cache_directory:
                raise plugin.InvalidArgs("cache directory not specified.")

            self.cache_directory = os.path.join(
                self.cache_directory, "rekall_agent")

    def update_local_file_generation(self, path, generation, local_filename):
        """Moves the file from local_filename into the correct place."""
        # Where we need to write the file inside the cache.
        destination = self.get_local_file(path, generation)

        # First make sure we remove any current generations of the path.
        current_generation = self.get_generation(path)
        if current_generation:
            current_generation_path = self.get_local_file(
                path, current_generation)

            # The local_filename is actually the same as the
            # current_generation_path so we can not remove it. It will be
            # renamed below.
            if current_generation_path != local_filename:
                # Otherwise remove the old file.
                os.unlink(current_generation_path)

        # Move the local_filename into the position it needs to be in.
        os.renames(local_filename, destination)

    def get_generation(self, path):
        """Returns current generation for this path, or None."""
        containing_dir_path = os.path.join(
            self.cache_directory, path.lstrip(os.path.sep))
        try:
            for generation in os.listdir(containing_dir_path):
                if generation.startswith("@"):
                    return generation[1:]
        except (IOError, OSError):
            pass

    def get_local_file(self, path, generation):
        return os.path.join(self.cache_directory, path.lstrip(os.path.sep),
                            "@" + generation)

    def store_at_generation(self, path, generation, data=None, fd=None,
                            iterator=None):
        """Clear previous generations, and store new data.

        Args:
          path: The path to store in the cache.
          generation: The generation to store at.
          data: If specified this is the data to store in the file.
          fd: If specified we read from the fd and copy to the new file.
          iterator: An iterator that generates data to write.
        """
        file_path = os.path.join(self.cache_directory, path.lstrip(os.path.sep),
                                 "@" + generation)
        containing_dir_path = os.path.dirname(file_path)
        # Clear the previous generations.
        try:
            for stored_generation in os.listdir(containing_dir_path):
                if stored_generation.startswith("@"):
                    os.unlink(
                        os.path.join(containing_dir_path, stored_generation))
        except (IOError, OSError):
            pass

        try:
            os.makedirs(containing_dir_path)
        except (IOError, OSError):
            pass

        print "Creating cached file %s" % file_path
        with open(file_path, "wb") as outfd:
            if data:
                outfd.write(data)
            elif iterator:
                for data in iterator:
                    outfd.write(data)
            else:
                while 1:
                    data = fd.read(1024*1024)
                    if not data:
                        break
                    outfd.write(data)

        return file_path
