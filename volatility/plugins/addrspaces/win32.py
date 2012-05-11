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
import os
import win32file

from volatility.plugins.addrspaces import standard


class Win32FileAddressSpace(standard.FileAddressSpace):
    """ This is a direct file AS for use in windows.

    In windows, in order to open raw devices we need to use the win32 apis. This
    address space allows us to open the raw device as exported by e.g. the
    winpmem driver.
    """

    __name = "win32file"

    ## We should be the AS of last resort but in front of the non win32 version.
    order = 90

    def __init__(self, filename=None, **kwargs):
        super(standard.FileAddressSpace, self).__init__(**kwargs)

        self.as_assert(self.base == None, 'Must be first Address Space')

        path = (self.session and self.session.filename) or filename
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

        # Lie about our size.
        self.fsize = 1e12

    def read(self, addr, length):
        win32file.SetFilePointer(self.fhandle, addr, 0)
        _, data = win32file.ReadFile(self.fhandle, length)
        return data

    def close(self):
        win32file.CloseHandle(self.fhandle)

