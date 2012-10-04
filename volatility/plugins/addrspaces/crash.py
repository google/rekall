# Volatility
# Copyright (C) 2012
#
# Authors:
# Michael Cohen <scudette@gmail.com> based on code by
# {npetroni,awalters}@4tphi.net (Nick Petroni and AAron Walters)
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

""" An AS for processing crash dumps """
import logging

from volatility import addrspace
from volatility import obj
from volatility.plugins.addrspaces import standard

PAGE_SHIFT = 12


class WindowsCrashDumpSpace32(addrspace.RunBasedAddressSpace):
    """ This AS supports windows Crash Dump format """
    order = 30

    PAGE_SIZE = 0x1000

    _md_image = True

    def __init__(self, **kwargs):
        super(WindowsCrashDumpSpace32, self).__init__(**kwargs)

        self.runs = []
        self.offset = 0
        self.fname = ''

        # Check the file for sanity.
        self.check_file()

        # This is a lookup table: (virtual_address, physical_address, length)
        self.runs = []
        file_offset = self.header.size()

        for run in self.header.PhysicalMemoryBlockBuffer.Run:
            self.runs.append((int(run.BasePage) * self.PAGE_SIZE,
                              file_offset,
                              int(run.PageCount) * self.PAGE_SIZE))

            file_offset += run.PageCount * self.PAGE_SIZE

        self.session.dtb = int(self.header.DirectoryTableBase)
        self.session.kdbg = int(self.header.KdDebuggerDataBlock)

    def check_file(self):
        """Checks the base file handle for sanity."""

        self.as_assert(self.base,
                       "Must stack on another address space")

        ## Must start with the magic PAGEDUMP
        self.as_assert((self.base.read(0, 8) == 'PAGEDUMP'),
                       "Header signature invalid")

        self.as_assert(
            self.profile.has_type("_DMP_HEADER"),
            "_DMP_HEADER not available in profile")

        self.header = self.profile.Object(
            "_DMP_HEADER", offset=self.offset, vm=self.base)

        if self.header.DumpType != "Full Dump":
            raise IOError("This is not a full memory crash dump. "
                          "Kernel crash dumps are not supported.")

    def write(self, vaddr, buf):
        # Support writes straddling page runs.
        while len(buf):
            file_offset, available_length = self._get_available_buffer(vaddr, len(buf))
            if file_offset is None:
                raise IOError("Unable to write unmapped runs yet.")

            self.base.write(baddr, buf[:available_length])
            buf = buf[available_length:]


class WindowsCrashDumpSpace64(WindowsCrashDumpSpace32):
    """This AS supports windows Crash Dump format."""
    order = 30

    def check_file(self):
        """Check specifically for 64 bit crash dumps."""
        ## Must start with the magic PAGEDU64
        self.as_assert((self.base.read(0, 8) == 'PAGEDU64'),
                       "Header signature invalid")

        self.as_assert(self.profile.has_type("_DMP_HEADER64"),
                       "_DMP_HEADER64 not available in profile")
        self.header = self.profile.Object("_DMP_HEADER64",
                                          offset=self.offset, vm=self.base)

        # The following error is fatal - abort the voting mechanism.

        # Unfortunately trunk volatility does not set this field correctly.
        if self.header.DumpType != "Full Dump":
            logging.warning("This is not a full memory crash dump. "
                            "Kernel crash dumps are not supported.")
