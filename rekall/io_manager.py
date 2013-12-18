# Rekall Memory Forensics
# Copyright 2013 Google Inc. All Rights Reserved.
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

"""IO Abstraction for Rekall.

Since Rekall is a library it should never directly access files: it may be
running on an environment which has no filesystem access for example, or the
files may be stored in an unusual way.

In order to ensure that the file storage mechanism does not need to be hardcoded
in each module, Rekall has an abstracted filesystem access mechanism implemented
through the IO Manager.

The session object should contain an instance of the IOManager() class at the
io_manager attribute, which will be used to create new files, or read from
existing files.
"""
import os
import json
import StringIO
import zipfile

from rekall import registry


class IOManagerError(IOError):
    """An IOError from the IO Manager."""


class IOManager(object):
    """The baseclass for abstracted IO implementations."""

    __metaclass__ = registry.MetaclassRegistry
    __abstract = True

    order = 100

    def __init__(self, mode="r"):
        self.mode = mode

    def ListFiles(self):
        """Returns a generator over all the files in this container."""
        return []

    def Create(self, name):
        """Creates a new file in the container.

        Returns a file like object which should support the context manager
        protocol. If the file already exists in the container, overwrite it.

        For example:

        with self.session.io_manager.Create("foobar") as fd:
           fd.Write("hello world")

        Args:
          name: The name of the new file.
        """

    def Open(self, name):
        """Opens a container member for reading.

        This should return a file like object which provides read access to
        container members.
        """

    def OpenSubContainer(self, name):
        """Opens member as a subcontainer.

        Args:
          name: The name of the subcontainer.

        Returns:
          an instance of IOManager if successful.

        Raises:
          IOManagerError if member is not found or can not be opened as a
          container..
        """

    def GetData(self, name):
        """Get the data object stored at container member.

        This returns an arbitrary python object which is stored in the named
        container member. For example, normally a dict or list. This function
        wraps the Open() method above and add deserialization to retrieve the
        actual object.
        """
        return json.load(self.Open(name))

    def StoreData(self, name, data, sort_keys=True, **options):
        """Stores the data in the named container member.

        This serializes the data and stores it in the named member. Not all
        types of data are serializable, so this may raise. For example, when
        using JSON to store the data, arbitrary python objects may not be used.
        """
        with self.Create(name) as fd:
            fd.write(json.dumps(data, sort_keys=True, **options))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        pass


class DirectoryIOManager(IOManager):
    """An IOManager which stores everything in files."""

    def __init__(self, output_directory=None, **kwargs):
        super(DirectoryIOManager, self).__init__(**kwargs)

        self.dump_dir = os.path.normpath(os.path.abspath(output_directory))
        self.check_dump_dir(self.dump_dir)

    def check_dump_dir(self, dump_dir=None):
        if not dump_dir:
            raise IOManagerError("Please specify a dump directory.")

        if self.mode == "w":
            self.EnsureDirectoryExists(self.dump_dir)

        if not os.path.isdir(dump_dir):
            raise IOManagerError("%s is not a directory" % self.dump_dir)

    def _GetAbsolutePathName(self, name):
        path = os.path.normpath(os.path.join(self.dump_dir, name))
        if not path.startswith(self.dump_dir):
            raise IOManagerError("Path name is outside container.")

        return path

    def EnsureDirectoryExists(self, dirname):
        try:
            os.makedirs(dirname)
        except OSError:
            pass

    def ListFiles(self):
        for root, dirs, files in os.walk(self.dump_dir):
            for f in files:
                path = os.path.normpath(os.path.join(root, f))

                # Return paths relative to the dump dir.
                yield path[len(self.dump_dir) + 1:]

    def Create(self, name):
        path = self._GetAbsolutePathName(name)
        self.EnsureDirectoryExists(os.path.dirname(path))
        return open(path, "wb")

    def Open(self, name):
        path = self._GetAbsolutePathName(name)
        return open(path, "rb")

    def OpenSubContainer(self, name):
        path = self._GetAbsolutePathName(name)

        return Factory(path, mode=self.mode)

    def __str__(self):
        return "Directory:%s" % self.dump_dir


class ZipExtFile(StringIO.StringIO):
    def __init__(self, name, manager):
        self.name = name
        self.manager = manager
        StringIO.StringIO.__init__(self)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is None:
            self.Close()
        else:
            self.manager._Cancel(self.name)

    def Close(self):
        self.manager._Write(self.name, self.getvalue())


class ZipFileManager(IOManager):
    """An IO Manager which stores files in a zip archive."""

    order = 50

    def __init__(self, file_name=None, fd=None, **kwargs):
        super(ZipFileManager, self).__init__(**kwargs)
        if fd is None and not file_name.lower().endswith("zip"):
            if self.mode == "w":
                raise IOManagerError(
                    "Zip files must have the .zip extensions.")
            else:
                # For reading we assume the a name without the .zip extension
                # should have it added.
                file_name = "%s.zip" % file_name

        self.fd = fd
        self.file_name = os.path.normpath(os.path.abspath(file_name))
        self._OpenZipFile()

        # The set of outstanding writers. When all outstanding writers have been
        # closed we can flush the ZipFile.
        self._outstanding_writers = set()

    def _OpenZipFile(self, mode=None):
        try:
            if self.fd is None:
                self.zip = zipfile.ZipFile(
                    self.file_name, mode=mode or self.mode,
                    compression=zipfile.ZIP_DEFLATED)

            elif self.mode == "r":
                self.zip = zipfile.ZipFile(fd=self.fd, mode="r")

            else:
                raise IOManagerError("Need a zip filename to write.")

        except zipfile.BadZipfile:
            raise IOManagerError("Unable to read zipfile.")

    def ListFiles(self):
        return self.zip.namelist()

    def _Cancel(self, name):
        self._outstanding_writers.remove(name)

    def _Write(self, name, data):
        self.zip.writestr(name, data)
        self._outstanding_writers.remove(name)
        if not self._outstanding_writers:
            self.zip.close()

            # Reopen the zip file so we may add new members.
            self._OpenZipFile(mode="a")

    def Create(self, name):
        if self.mode != "w":
            raise IOManagerError("Container not opened for writing.")

        result = ZipExtFile(name, self)
        self._outstanding_writers.add(name)
        return result

    def Open(self, name):
        if self.mode != "r":
            raise IOManagerError("Container not opened for reading.")
        if self.zip is None:
            self._OpenZipFile()

        return self.zip.open(name)

    def OpenSubContainer(self, name):
        if self.mode != "r":
            raise IOManagerError("Only supports nesting for reading.")

        fd = self.Open(name)

        # Currently only support nested zip files here.
        return self.__class__(fd=fd, mode="r")

    def __enter__(self):
        self._outstanding_writers.add(self)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._outstanding_writers.remove(self)
        if exc_type is None and not self._outstanding_writers:
            self.zip.close()
            if self.mode == "w":
                self._OpenZipFile(mode="a")

    def __str__(self):
        return "ZipFile:%s" % self.file_name


def Factory(urn, mode="r", **kwargs):
    """Try to instantiate the IOManager class."""

    for cls in sorted(IOManager.classes.values(), key=lambda x: x.order):
        try:
            return cls(urn, mode=mode, **kwargs)
        except IOError:
            pass

    raise IOManagerError("Unable to find any managers which can work on %s" %
                         urn)
