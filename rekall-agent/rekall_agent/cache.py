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
import shutil

from rekall import cache
from rekall import plugin
from rekall_agent import common
from rekall_agent import serializer


class Cache(common.AgentConfigMixin, serializer.SerializedObject):
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
                self._session.logging.debug(
                    "Expiring local cache %s", current_generation_path)

                os.unlink(current_generation_path)

        # Move the local_filename into the position it needs to be
        # in. Ensure the output directory exists.
        try:
            os.makedirs(os.path.dirname(destination))
        except (OSError, IOError):
            pass

        shutil.move(local_filename, destination)

    def expire(self, path):
        current_generation = self.get_generation(path)
        if current_generation:
            current_generation_path = self.get_local_file(
                path, current_generation)

            self._session.logging.debug(
                "Expiring local cache %s", current_generation_path)
            os.unlink(current_generation_path)

            # Trim empty directories.
            try:
                dirname = os.path.dirname(current_generation_path)
                while dirname:
                    os.rmdir(dirname)
                    dirname = os.path.dirname(dirname)
            except (IOError, OSError):
                pass

    def get_generation(self, path):
        """Returns current generation for this path, or None."""
        containing_dir_path = os.path.join(
            self.cache_directory, path.lstrip(os.path.sep))
        try:
            for generation in os.listdir(containing_dir_path):
                if generation.startswith("@") and generation.endswith("@"):
                    return generation[1:-1]
        except (IOError, OSError):
            pass

    def get_local_file(self, path, generation):
        return os.path.join(self.cache_directory, path.lstrip(os.path.sep),
                            "@" + generation + "@")

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
                                 "@" + generation + "@")
        containing_dir_path = os.path.dirname(file_path)

        # Clear the previous generations.
        try:
            for stored_generation in os.listdir(containing_dir_path):
                if (stored_generation.startswith("@") and
                    stored_generation.endswith("@")):
                    current_generation_path = os.path.join(
                        containing_dir_path, stored_generation)

                    self._session.logging.debug(
                        "Expiring local cache %s", current_generation_path)
                    os.unlink(current_generation_path)
        except (IOError, OSError):
            pass

        try:
            os.makedirs(containing_dir_path)
        except (IOError, OSError):
            pass

        count = 0
        with open(file_path, "wb") as outfd:
            if data:
                outfd.write(data)
            elif iterator:
                for data in iterator:
                    count += len(data)
                    self._session.report_progress("Downloading %s", count)
                    outfd.write(data)
            else:
                while 1:
                    data = fd.read(1024*1024)
                    if not data:
                        break

                    count += len(data)
                    self._session.report_progress("Downloading %s", count)
                    outfd.write(data)

        self._session.logging.debug(
            "Creating cached file %s (%s bytes)", file_path, count)

        return file_path

    def stat(self, path):
        generation = self.get_generation(path)
        if generation:
            subpath = self.get_local_file(path, generation)
            s = os.lstat(subpath)
            return dict(
                created=s.st_ctime,
                updated=s.st_mtime,
                size=s.st_size,
                generation=generation,
                path=path)


    def list_files(self, path):
        containing_dir_path = os.path.join(
            self.cache_directory, path.lstrip(os.path.sep))
        try:
            for root, _, files in os.walk(containing_dir_path):
                for filename in files:
                    if filename.startswith("@") and filename.endswith("@"):
                        generation = filename[1:-1]
                        subpath = "/" + os.path.relpath(
                            root, self.cache_directory)

                        s = os.lstat(os.path.join(root, filename))
                        yield dict(
                            created=s.st_ctime,
                            updated=s.st_mtime,
                            size=s.st_size,
                            generation=generation,
                            path=subpath)

        except (IOError, OSError):
            pass
