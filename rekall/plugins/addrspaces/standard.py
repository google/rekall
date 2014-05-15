# Rekall Memory Forensics
# Copyright (C) 2007,2008 Volatile Systems
# Copyright (C) 2004,2005,2006 4tphi Research
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Authors:
# {npetroni,awalters}@4tphi.net (Nick Petroni and AAron Walters)
# Michael Cohen <scudette@users.sourceforge.net>
# Mike Auty <mike.auty@gmail.com>
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

""" These are standard address spaces supported by Rekall Memory Forensics """
import StringIO
import struct
import os

from rekall import addrspace


class FDAddressSpace(addrspace.BaseAddressSpace):
    """An address space which operated on a file like object."""

    __name = "filelike"

    ## We should be first.
    order = 0

    def __init__(self, base=None, fhandle=None, **kwargs):
        self.as_assert(base == None, "Base passed to FDAddressSpace.")
        self.as_assert(fhandle is not None, 'file handle must be provided')

        self.fhandle = fhandle
        self.fhandle.seek(0, 2)
        self.fsize = self.fhandle.tell()
        self.offset = 0

        super(FDAddressSpace, self).__init__(**kwargs)

    def read(self, addr, length):
        length = int(length)
        addr = int(addr)
        try:
            self.fhandle.seek(addr)
            data = self.fhandle.read(length)
            return data + "\x00" * (length - len(data))
        except IOError:
            return "\x00" * length

    def read_long(self, addr):
        string = self.read(addr, 4)
        (longval,) = struct.unpack('=I', string)
        return longval

    def get_available_addresses(self):
        # Since the second parameter is the length of the run
        # not the end location, it must be set to fsize, not fsize - 1
        yield (0, 0, self.fsize)

    def is_valid_address(self, addr):
        if addr == None:
            return False
        return addr <= self.fsize

    def close(self):
        self.fhandle.close()

    def __eq__(self, other):
        return (self.__class__ == other.__class__ and
                self.fname == other.fname)


class FileAddressSpace(FDAddressSpace):
    """ This is a direct file AS.

    For this AS to be instantiated, we need

    1) A valid config.filename

    2) no one else has picked the AS before us

    3) base == None (we dont operate on anyone else so we need to be
    right at the bottom of the AS stack.)
    """

    __name = "file"

    ## We should be the AS of last resort
    order = 100

    # This address space handles images.
    __image = True

    def __init__(self, base=None, filename=None, session=None, **kwargs):
        self.as_assert(base == None, 'Must be first Address Space')

        self.session = session
        path = filename or (session and session.GetParameter("filename"))
        self.as_assert(path, "Filename must be specified in session (e.g. "
                       "session.SetParameter('filename', 'MyFile.raw').")

        self.name = os.path.abspath(path)
        self.fname = self.name
        self.mode = 'rb'

        if path.startswith(r"\\\\.\\"):
            raise RuntimeError(
                "Unable to open a device without the win32file package "
                "installed.")

        fhandle = open(self.fname, self.mode)
        super(FileAddressSpace, self).__init__(
            fhandle=fhandle, session=session, **kwargs)

    def __getstate__(self):
        state = super(FileAddressSpace, self).__getstate__()
        state["filename"] = self.name

        return state


class WriteableAddressSpaceMixIn(object):
    """This address space can be used to create new files.

    NOTE: This does not participate in voting or gets automatically
    selected. It can only be instantiated directly.
    """

    def write(self, addr, data):
        try:
            self.fhandle.seek(addr)
            self.fhandle.write(data)
            self.fhandle.flush()
        except IOError:
            return False

        return True

    def is_valid_address(self, unused_addr):
        # All addresses are valid, we just grow the file there.
        return True

    def read(self, addr, length):
        # Just null pad the file - even if we read past the end.
        self.fhandle.seek(addr)
        data = self.fhandle.read(length)

        if len(data) < length:
            data += "\x00" * (length - len(data))

        return data

class WriteableAddressSpace(WriteableAddressSpaceMixIn, FDAddressSpace):

    def __init__(self, filename=None, mode="w+b", **kwargs):
        self.as_assert(filename, "Filename must be specified.")
        self.name = os.path.abspath(filename)
        self.fname = self.name
        self.mode = mode
        self.writeable = True

        fhandle = open(self.fname, self.mode)
        super(WriteableAddressSpace, self).__init__(fhandle=fhandle, **kwargs)


class DummyAddressSpace(WriteableAddressSpaceMixIn, FDAddressSpace):
    """An AS which always returns nulls."""
    __name = 'dummy'

    def __init__(self, size=10*1024, **kwargs):
        self.mode = "w+b"
        self.writeable = True

        kwargs["fhandle"] = StringIO.StringIO(size * "\x00")
        super(DummyAddressSpace, self).__init__(**kwargs)
