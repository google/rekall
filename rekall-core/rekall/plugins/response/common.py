# Rekall Memory Forensics
#
# Copyright 2016 Google Inc. All Rights Reserved.
#
# Authors:
# Michael Cohen <scudette@google.com>
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

"""This module adds support for incident response to Rekall."""

__author__ = "Michael Cohen <scudette@google.com>"
import os
import stat

from efilter.protocols import associative
from efilter.protocols import structured

from rekall import obj
from rekall import utils
from rekall import plugin


class FileSpec(object):
    """Specification of a file path."""

    def __init__(self, filename, filesystem="API"):
        self.filesystem = filesystem
        if isinstance(filename, FileSpec):
            # Copy the other file spec.
            self.name = filename.name

        elif isinstance(filename, basestring):
            self.name = unicode(filename)

        else:
            raise TypeError("Filename must be a string or file spec.")

    def __str__(self):
        return self.name


class FileInformation(utils.AttributeDict):
    """An object representing a file on disk.

    This FileInformation uses the API to read data about the file.
    """

    def __init__(self, filename=None, **kwargs):
        super(FileInformation, self).__init__(**kwargs)
        # Ensure the filename is a filespec.
        self.filename = FileSpec(filename)

    _st_mode = 0

    @classmethod
    def from_stat(cls, filename):
        filename = FileSpec(filename)
        if filename.filesystem != "API":
            raise RuntimeError("Unsupported file spec type %s" %
                               filename.filesystem)

        result = cls(filename)

        try:
            stat_result = os.stat(result.filename.name)
        except (IOError, OSError) as e:
            return obj.NoneObject("Unable to stat %s", e)

        for attr in dir(stat_result):
            if attr.startswith("st_"):
                setattr(result, attr, getattr(stat_result, attr))

        return result

    @utils.safe_property
    def st_mode(self):
        return self.get("st_mode")

    @st_mode.setter
    def st_mode(self, value):
        self["st_mode"] = Permissions(int(value))

    def open(self):
        try:
            return open(self.filename.name)
        except (IOError, OSError) as e:
            return obj.NoneObject("Unable to open file: %s", e)

    def list(self):
        """If this is a directory return a list of children."""
        if not self.st_mode.is_dir():
            return

        for name in os.listdir(self.filename.name):
            full_path = os.path.join(self.filename.name, name)
            item = self.from_stat(full_path)
            if item:
                yield item


class Permissions(object):
    """An object to represent permissions."""
    # Taken from Python3.3's stat.filemode.
    _filemode_table = (
        ((stat.S_IFLNK, "l"),
         (stat.S_IFREG, "-"),
         (stat.S_IFBLK, "b"),
         (stat.S_IFDIR, "d"),
         (stat.S_IFCHR, "c"),
         (stat.S_IFIFO, "p")),

        ((stat.S_IRUSR, "r"),),
        ((stat.S_IWUSR, "w"),),
        ((stat.S_IXUSR|stat.S_ISUID, "s"),
         (stat.S_ISUID, "S"),
         (stat.S_IXUSR, "x")),

        ((stat.S_IRGRP, "r"),),
        ((stat.S_IWGRP, "w"),),
        ((stat.S_IXGRP|stat.S_ISGID, "s"),
         (stat.S_ISGID, "S"),
         (stat.S_IXGRP, "x")),

        ((stat.S_IROTH, "r"),),
        ((stat.S_IWOTH, "w"),),
        ((stat.S_IXOTH|stat.S_ISVTX, "t"),
         (stat.S_ISVTX, "T"),
         (stat.S_IXOTH, "x"))
    )

    def __init__(self, value):
        self.value = int(value)

    def filemode(self, mode):
        """Convert a file's mode to a string of the form '-rwxrwxrwx'."""
        perm = []
        for table in self._filemode_table:
            for bit, char in table:
                if mode & bit == bit:
                    perm.append(char)
                    break
            else:
                perm.append("-")
        return "".join(perm)

    def __int__(self):
        return self.value

    def __str__(self):
        return self.filemode(self.value)

    def is_dir(self):
        return stat.S_ISDIR(self.value)


class AbstractIRCommandPlugin(plugin.PhysicalASMixin,
                              plugin.TypedProfileCommand,
                              plugin.Command):
    """A base class for all IR plugins.

    IR Plugins are only active when the session is live.
    """

    __abstract = True

    PROFILE_REQUIRED = False

    @classmethod
    def is_active(cls, session):
        """We are only active if the profile is windows."""
        return (super(AbstractIRCommandPlugin, cls).is_active(session) and
                session.GetParameter("live"))



def FileFactory(filename):
    """Return the correct FileInformation class from the filename.

    Currently we only support OS API accessible files, but in the future we will
    also support NTFS files.
    """
    # Ensure this is a valid file spec.
    filename = FileSpec(filename)

    if filename.filesystem != "API":
        raise RuntimeError("Unsupported file spec type %s" %
                           filename.filesystem)

    return FileInformation.from_stat(filename)


# Efilter Glue code.
associative.IAssociative.implement(
    for_type=FileInformation,
    implementations={
        associative.select: getattr,
        associative.reflect_runtime_key: structured.reflect_runtime_member,
        associative.getkeys_runtime: structured.getmembers_runtime
    }
)

associative.IAssociative.implement(
    for_type=FileSpec,
    implementations={
        associative.select: getattr,
        associative.reflect_runtime_key: lambda c: str,
        associative.getkeys_runtime: lambda _: ["name"]
    }
)
