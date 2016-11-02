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
import os
import struct
import weakref

import pywintypes
import win32file

from rekall import addrspace
from rekall.plugins.addrspaces import standard


PMEM_MODE_IOSPACE = 0
PMEM_MODE_PHYSICAL = 1
PMEM_MODE_PTE = 2
PMEM_MODE_PTE_PCI = 3


def CTL_CODE(DeviceType, Function, Method, Access):
    return (DeviceType << 16) | (Access << 14) | (Function << 2) | Method


# IOCTLS for interacting with the driver.
INFO_IOCTRL = CTL_CODE(0x22, 0x103, 0, 3)
CTRL_IOCTRL = CTL_CODE(0x22, 0x101, 0, 3)

PAGE_SHIFT = 12


class Win32FileWrapper(object):
    """A simple wrapper that makes a win32 file handle look like an AS."""

    def __init__(self, fhandle, size=None):
        self.fhandle = fhandle
        self.size = size

    def read(self, offset, length):
        try:
            win32file.SetFilePointer(self.fhandle, offset, 0)
            _, data = win32file.ReadFile(self.fhandle, length)
        except Exception:
            return addrspace.ZEROER.GetZeros(length)

        return data

    def write(self, offset, data):
        win32file.SetFilePointer(self.fhandle, offset, 0)
        # The WinPmem driver returns bytes_written == 0 always. This is probably
        # a bug in its write routine, so we ignore it here. If the operation was
        # successful we assume all bytes were written.
        err, _bytes_written = win32file.WriteFile(self.fhandle, data)
        if err == 0:
            return len(data)
        return 0

    def end(self):
        return self.size

    def close(self):
        win32file.CloseHandle(self.fhandle)


class Win32AddressSpace(addrspace.CachingAddressSpaceMixIn,
                        addrspace.RunBasedAddressSpace):
    """ This is a direct file AS for use in windows.

    In windows, in order to open raw devices we need to use the win32 apis. This
    address space allows us to open the raw device as exported by e.g. the
    winpmem driver.
    """

    CHUNK_SIZE = 0x1000

    def _OpenFileForRead(self, path):
        try:
            fhandle = self.fhandle = win32file.CreateFile(
                path,
                win32file.GENERIC_READ,
                win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
                None,
                win32file.OPEN_EXISTING,
                win32file.FILE_ATTRIBUTE_NORMAL,
                None)

            self._closer = weakref.ref(
                self, lambda x: win32file.CloseHandle(fhandle))

            self.write_enabled = False
            return fhandle

        except pywintypes.error as e:
            raise IOError("Unable to open %s: %s" % (path, e))

    def close(self):
        for run in self.get_mappings():
            run.address_space.close()


class Win32FileAddressSpace(Win32AddressSpace):
    __name = "win32file"

    # We should be the AS of last resort but in front of the non win32 version.
    order = standard.FileAddressSpace.order - 5
    __image = True

    def __init__(self, base=None, filename=None, **kwargs):
        self.as_assert(base == None, 'Must be first Address Space')
        super(Win32FileAddressSpace, self).__init__(**kwargs)

        path = filename or self.session.GetParameter("filename")

        self.as_assert(path, "Filename must be specified in session (e.g. "
                       "session.SetParameter('filename', 'MyFile.raw').")

        self.fname = path

        # The file is just a regular file, we open for reading.
        fhandle = self._OpenFileForRead(path)

        # If we can not get the file size it means this is not a regular file -
        # maybe a device.
        self.fhandle_as = Win32FileWrapper(fhandle)
        try:
            file_size = win32file.GetFileSize(fhandle)
            self.add_run(0, 0, file_size, self.fhandle_as)
        except pywintypes.error:
            # This may be a device, we just read the whole space.
            self.add_run(0, 0, 2**63, self.fhandle_as)
            self.volatile = True


class WinPmemAddressSpace(Win32AddressSpace):
    """An address space specifically designed for communicating with WinPmem."""

    __name = "winpmem"
    __image = True

    # This is a live address space.
    volatile = True

    # We must be in front of the regular file based AS.
    order = Win32FileAddressSpace.order - 5

    # This AS can map files into itself.
    __can_map_files = True

    def __init__(self, base=None, filename=None, session=None, **kwargs):
        self.as_assert(base == None, 'Must be first Address Space')
        path = filename or session.GetParameter("filename")
        self.as_assert(path.startswith("\\\\"),
                       "Filename does not look like a device.")

        super(WinPmemAddressSpace, self).__init__(
            filename=filename, session=session, **kwargs)

        try:
            # First open for write in case the driver is in write mode.
            fhandle = self._OpenFileForWrite(path)
        except IOError:
            fhandle = self._OpenFileForRead(path)

        self.fhandle_as = Win32FileWrapper(fhandle)

        try:
            self.ParseMemoryRuns(fhandle)
        except Exception:
            raise addrspace.ASAssertionError(
                "This is not a WinPmem based driver.")

        # Key: lower cased filename, value: offset where it is mapped.
        self.mapped_files = {}
        self.filesystems = {}

    def _OpenFileForWrite(self, path):
        try:
            fhandle = self.fhandle = win32file.CreateFile(
                path,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
                None,
                win32file.OPEN_EXISTING,
                win32file.FILE_ATTRIBUTE_NORMAL,
                None)
            self.write_enabled = True
            self._closer = weakref.ref(
                self, lambda x: win32file.CloseHandle(fhandle))

            return fhandle

        except pywintypes.error as e:
            raise IOError("Unable to open %s: %s" % (path, e))

    FIELDS = (["CR3", "NtBuildNumber", "KernBase", "KDBG"] +
              ["KPCR%02d" % i for i in xrange(32)] +
              ["PfnDataBase", "PsLoadedModuleList", "PsActiveProcessHead"] +
              ["Padding%s" % i for i in xrange(0xff)] +
              ["NumberOfRuns"])

    def ParseMemoryRuns(self, fhandle):
        # Set acquisition mode. If the driver does not support this mode it will
        # just fall back to the default.
        win32file.DeviceIoControl(
            fhandle, CTRL_IOCTRL,
            struct.pack("I", PMEM_MODE_PTE), 4, None)

        result = win32file.DeviceIoControl(
            fhandle, INFO_IOCTRL, "", 102400, None)

        fmt_string = "Q" * len(self.FIELDS)
        self.memory_parameters = dict(zip(self.FIELDS, struct.unpack_from(
            fmt_string, result)))

        offset = struct.calcsize(fmt_string)
        for x in xrange(self.memory_parameters["NumberOfRuns"]):
            start, length = struct.unpack_from("QQ", result, x * 16 + offset)
            self.add_run(start, start, length, self.fhandle_as)

    def ConfigureSession(self, session):
        dtb = self.memory_parameters["CR3"]
        session.SetCache("dtb", int(dtb), volatile=False)

        # Get the kernel base directly from the winpmem driver if that is
        # available.
        kernel_base = self.memory_parameters["KernBase"]
        if kernel_base > 0:
            self.session.SetCache("kernel_base", kernel_base, volatile=False)

    def _map_raw_filename(self, filename):
        # Parsing the NTFS can be expensive so we only do it when the user
        # specifically wanted to be thorough.
        if self.session.GetParameter("performance") != "thorough":
            return

        drive, base_filename = os.path.splitdrive(filename)
        if not drive:
            return

        try:
            ntfs_session = self.filesystems[drive]
        except KeyError:
            ntfs_session = self.filesystems[drive] = self.session.add_session(
                filename=r"\\.\%s" % drive, verbose=True, autodetect=[],
                profile="ntfs")

        # Stat the MFT inode (MFT 2).
        mft_stat = ntfs_session.plugins.istat(2)

        # Lookup the mft entry by filename.
        mft_entry = mft_stat.ntfs.MFTEntryByName(base_filename)

        # Open the $DATA stream
        return mft_entry.open_file()

    def get_file_address_space(self, filename):
        """Return an address space for filename."""
        try:
            # Try to read the file with OS APIs.
            file_as = Win32FileAddressSpace(filename=filename,
                                            session=self.session)
            return file_as
        except IOError:
            try:
                # Try to read the file with raw access.
                file_as = self._map_raw_filename(filename)
                return file_as
            except IOError:
                # Cant read this file - no mapping available.
                return

    def get_mapped_offset(self, filename, file_offset, length=None):
        # Normalize filename for case insenstive comparisons.
        filename = filename.lower()
        mapped_offset = self.mapped_files.get(filename)
        if mapped_offset is None:
            file_as = self.get_file_address_space(filename)
            if not file_as:
                return

            # Add a guard page and align.
            mapped_offset = self.mapped_files[filename] = (
                (length or self.end()) + 0x10000) & 0xFFFFFFFFFFFFF000

            self.add_run(mapped_offset, 0, file_as.end(), file_as)

        if mapped_offset is not None:
            return mapped_offset + file_offset
