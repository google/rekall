# Rekall Memory Forensics
# Copyright (C) 2012
# Copyright 2013 Google Inc. All Rights Reserved.
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

"""An Address Space for processing crash dump files."""
import logging

from rekall import addrspace
from rekall.plugins.overlays.windows import crashdump


class WindowsCrashDumpSpace32(addrspace.RunBasedAddressSpace):
    """ This Address Space supports windows Crash Dump format """
    order = 30

    PAGE_SIZE = 0x1000

    # Participate in Address Space voting.
    __image = True

    def __init__(self, **kwargs):
        super(WindowsCrashDumpSpace32, self).__init__(**kwargs)
        self.offset = 0
        self.fname = ''

        # Check the file for sanity.
        self.check_file()

        file_offset = self.header.size()

        for run in self.header.PhysicalMemoryBlockBuffer.Run:
            self.runs.insert((int(run.BasePage) * self.PAGE_SIZE,
                              file_offset,
                              int(run.PageCount) * self.PAGE_SIZE))

            file_offset += run.PageCount * self.PAGE_SIZE

        self.session.SetParameter(
            "dtb", int(self.header.DirectoryTableBase))

    def check_file(self):
        """Checks the base file handle for sanity."""

        self.as_assert(self.base,
                       "Must stack on another address space")

        ## Must start with the magic PAGEDUMP
        self.as_assert((self.base.read(0, 8) == 'PAGEDUMP'),
                       "Header signature invalid")

        self.profile = crashdump.CrashDump32Profile(
            session=self.session)

        self.header = self.profile.Object(
            "_DMP_HEADER", offset=self.offset, vm=self.base)

        if self.header.DumpType != "Full Dump":
            raise IOError("This is not a full memory crash dump. "
                          "Kernel crash dumps are not supported.")

    def write(self, vaddr, buf):
        # Support writes straddling page runs.
        written = 0
        while len(buf):
            file_offset, available_length = self._get_available_buffer(
                vaddr, len(buf))
            if file_offset is None:
                raise IOError("Unable to write unmapped runs yet.")

            written += self.base.write(
                file_offset, buf[:available_length])

            buf = buf[available_length:]

        return written


class WindowsCrashDumpSpace64(WindowsCrashDumpSpace32):
    """This AS supports windows Crash Dump format."""
    order = 30

    # Participate in Address Space voting.
    __image = True

    def check_file(self):
        """Check specifically for 64 bit crash dumps."""

        ## Must start with the magic PAGEDU64
        self.as_assert((self.base.read(0, 8) == 'PAGEDU64'),
                       "Header signature invalid")

        self.profile = crashdump.CrashDump64Profile(
            session=self.session)

        self.as_assert(self.profile.has_type("_DMP_HEADER64"),
                       "_DMP_HEADER64 not available in profile")
        self.header = self.profile.Object("_DMP_HEADER64",
                                          offset=self.offset, vm=self.base)

        # The following error is fatal - abort the voting mechanism.

        # Unfortunately trunk Volatility does not set this field correctly, so
        # we do not make it a fatal error. It can lead to problems if we try to
        # parse other crash dump formats, (Especially Win8 ones - see below) so
        # we might consider making this a fatal error in future.
        if self.header.DumpType != "Full Dump":
            logging.warning("This is not a full memory crash dump. "
                            "Kernel crash dumps are not supported.")

        # Catch this error early or we will hog all memory trying to parse a
        # huge number of Runs. On Windows 8 we have observed the DumpType to be
        # == 5 and these fields are padded with "PAGE" (i.e. 0x45474150).
        if self.header.PhysicalMemoryBlockBuffer.NumberOfRuns > 100:
            raise RuntimeError(
                "This crashdump file format is not supported. Rekall does not "
                "currently support crashdumps using the Win8 format.")
