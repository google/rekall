# Volatility
# Copyright (C) 2012 Michael Cohen
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
import exceptions
import os
import struct
import win32file

from volatility import addrspace
from volatility import utils


def CTL_CODE(DeviceType, Function, Method, Access):
    return (DeviceType<<16) | (Access << 14) | (Function << 2) | Method


# IOCTLS for interacting with the driver.
INFO_IOCTRL = CTL_CODE(0x22, 0x100, 0, 3)

PAGE_SHIFT = 12


class Win32FileAddressSpace(addrspace.PagedReader):
    """ This is a direct file AS for use in windows.

    In windows, in order to open raw devices we need to use the win32 apis. This
    address space allows us to open the raw device as exported by e.g. the
    winpmem driver.
    """

    __name = "win32file"

    ## We should be the AS of last resort but in front of the non win32 version.
    order = 90

    PAGE_SIZE = 0x10000

    def __init__(self, base=None, filename=None, session=None, **kwargs):
        self.as_assert(base == None, 'Must be first Address Space')

        path = (session and session.filename) or filename
        self.as_assert(path, "Filename must be specified in session (e.g. "
                       "session.filename = 'MyFile.raw').")

        self.fname = path
        self.fhandle = win32file.CreateFile(
            path,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
            None,
            win32file.OPEN_EXISTING,
            win32file.FILE_ATTRIBUTE_NORMAL,
            None)

        # Try to get the memory runs from the winpmem driver.
        self.runs = []
        try:
            self.ParseMemoryRuns()
        except Exception:
            self.runs = [[0, win32file.GetFileSize(self.fhandle)]]

        # IO on windows is extremely slow so we are better off using a
        # cache.
        self.cache = utils.FastStore(1000)

        super(Win32FileAddressSpace, self).__init__(
            session=session, base=base, **kwargs)

    def ParseMemoryRuns(self):
        result = win32file.DeviceIoControl(
            self.fhandle, INFO_IOCTRL, "", 1024, None)

        fmt_string = "QQl"
        self.dtb, _, number_of_runs = struct.unpack_from(fmt_string, result)

        offset = struct.calcsize(fmt_string)

        for x in range(number_of_runs):
            start, length = struct.unpack_from("QQ", result, x * 16 + offset)
            self.runs.append((start,length))

    def _read_chunk(self, addr, length, pad):
        offset, length = self._get_available_buffer(addr, length)
        if offset is None:
            return "\x00" * length

        win32file.SetFilePointer(self.fhandle, offset, 0)
        _, data = win32file.ReadFile(self.fhandle, length)
        return data

    def close(self):
        win32file.CloseHandle(self.fhandle)

    def vtop(self, addr):
        file_offset, _ = self._get_available_buffer(addr, 1)
        return file_offset

    def _get_available_buffer(self, addr, length):
        """Resolves the address into the file offset.

        In a crash dump, pages are stored back to back in runs. This function
        finds the run that contains this page and returns the file address where
        this page can be found.

        Returns:
          A tuple of (physical_offset, available_length). The physical_offset
          can be None to signify that the address if not valid.
        """
        for start, run_length in self.runs:
            # Required address is before this run (i.e. the read is
            # outside any run).
            if addr < start:
                available_length = min(length, start - addr)
                return (None, available_length)

            # The required page is inside this run.
            if addr >= start and addr < start + run_length:
                available_length = min(length, start + run_length - addr)

                # Offset of page in the run.
                return (addr, available_length)

        return None, 0

    def get_available_pages(self):
        for start, length in self.runs:
            yield start >> PAGE_SHIFT, length >> PAGE_SHIFT

    def is_valid_address(self, addr):
        return self.vtop(addr) is not None
