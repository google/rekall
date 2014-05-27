# Rekall Memory Forensics
# Copyright (C) 2012 Michael Cohen
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Authors:
# Michael Cohen <scudette@gmail.com>
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
"""This is a windows specific address space."""
import pywintypes
import struct
import win32file

from rekall import addrspace


def CTL_CODE(DeviceType, Function, Method, Access):
    return (DeviceType<<16) | (Access << 14) | (Function << 2) | Method


# IOCTLS for interacting with the driver.
INFO_IOCTRL = CTL_CODE(0x22, 0x103, 0, 3)

PAGE_SHIFT = 12


class Win32FileAddressSpace(addrspace.RunBasedAddressSpace):
    """ This is a direct file AS for use in windows.

    In windows, in order to open raw devices we need to use the win32 apis. This
    address space allows us to open the raw device as exported by e.g. the
    winpmem driver.
    """

    __name = "win32file"

    ## We should be the AS of last resort but in front of the non win32 version.
    order = 90
    __image = True

    def __init__(self, base=None, filename=None, **kwargs):
        self.as_assert(base == None, 'Must be first Address Space')
        super(Win32FileAddressSpace, self).__init__(**kwargs)

        path = filename or (self.session and self.session.GetParameter(
                "filename"))

        self.as_assert(path, "Filename must be specified in session (e.g. "
                       "session.GetParameter('filename', 'MyFile.raw').")

        self.fname = path

        # If the file is a device we try to talk to the winpmem driver.
        if path.startswith("\\\\"):
            try:
                # First open for write in case the driver is in write mode.
                self._OpenFileForWrite(path)
            except pywintypes.error:
                self._OpenFileForRead(path)

            self.ParseMemoryRuns()

        else:
            # The file is just a regular file, we open for reading.
            self._OpenFileForRead(path)
            self.runs.insert((0, 0, win32file.GetFileSize(self.fhandle)))

    def _OpenFileForRead(self, path):
        self.fhandle = win32file.CreateFile(
            path,
            win32file.GENERIC_READ,
            win32file.FILE_SHARE_READ,
            None,
            win32file.OPEN_EXISTING,
            win32file.FILE_ATTRIBUTE_NORMAL,
            None)

    def _OpenFileForWrite(self, path):
        self.fhandle = win32file.CreateFile(
            path,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
            None,
            win32file.OPEN_EXISTING,
            win32file.FILE_ATTRIBUTE_NORMAL,
            None)

    FIELDS = (["CR3", "NtBuildNumber", "KernBase", "KDBG"] +
              ["KPCR%02d" % i for i in xrange(32)] +
              ["PfnDataBase", "PsLoadedModuleList", "PsActiveProcessHead"] +
              ["Padding%s" % i for i in xrange(0xff)] +
              ["NumberOfRuns"])

    def ParseMemoryRuns(self):
        result = win32file.DeviceIoControl(
            self.fhandle, INFO_IOCTRL, "", 102400, None)

        fmt_string = "Q" * len(self.FIELDS)
        self.memory_parameters = dict(zip(self.FIELDS, struct.unpack_from(
                    fmt_string, result)))

        self.dtb = self.memory_parameters["CR3"]
        self.session.SetParameter("dtb", int(self.dtb))

        offset = struct.calcsize(fmt_string)

        for x in xrange(self.memory_parameters["NumberOfRuns"]):
            start, length = struct.unpack_from("QQ", result, x * 16 + offset)
            self.runs.insert((start, start, length))

    def _read_chunk(self, addr, length):
        offset, available_length = self._get_available_buffer(addr, length)
        if offset is None:
            return "\x00" * min(length, available_length)

        win32file.SetFilePointer(self.fhandle, offset, 0)
        _, data = win32file.ReadFile(
            self.fhandle, min(length, available_length))

        return data

    def write(self, addr, data):
        length = len(data)
        offset, available_length = self._get_available_buffer(addr, length)
        if offset is None:
            return

        to_write = min(len(data), available_length)
        win32file.SetFilePointer(self.fhandle, offset, 0)

        win32file.WriteFile(self.fhandle, data[:to_write])

        return to_write

    def close(self):
        win32file.CloseHandle(self.fhandle)
