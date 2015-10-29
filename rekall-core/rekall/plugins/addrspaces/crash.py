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

from rekall import addrspace
from rekall.plugins.overlays.windows import crashdump

# pylint: disable=protected-access


class WindowsCrashDumpSpace32(addrspace.RunBasedAddressSpace):
    """ This Address Space supports windows Crash Dump format """
    order = 30

    PAGE_SIZE = 0x1000

    # Participate in Address Space voting.
    __image = True

    def __init__(self, **kwargs):
        super(WindowsCrashDumpSpace32, self).__init__(**kwargs)

        self.as_assert(self.base != None, "No base address space provided")

        self.offset = 0
        self.fname = ''

        # Check the file for sanity.
        self.check_file()

        file_offset = self.header.obj_size

        for run in self.header.PhysicalMemoryBlockBuffer.Run:
            self.add_run(int(run.BasePage) * self.PAGE_SIZE,
                         file_offset,
                         int(run.PageCount) * self.PAGE_SIZE)

            file_offset += run.PageCount * self.PAGE_SIZE

        self.session.SetCache(
            "dtb", int(self.header.DirectoryTableBase))

    def check_file(self):
        """Checks the base file handle for sanity."""

        self.as_assert(self.base,
                       "Must stack on another address space")

        # Must start with the magic PAGEDUMP
        self.as_assert((self.base.read(0, 8) == 'PAGEDUMP'),
                       "Header signature invalid")

        self.profile = crashdump.CrashDump32Profile(
            session=self.session)

        self.header = self.profile.Object(
            "_DMP_HEADER", offset=self.offset, vm=self.base)

        if self.header.DumpType != "Full Dump":
            # Here we rely on the WindowsCrashBMP AS to run before us. Therefore
            # we fail hard if this is not a valid legacy crash format.
            raise IOError("This is not a full memory crash dump. "
                          "Kernel crash dumps are not supported.")


class WindowsCrashDumpSpace64(WindowsCrashDumpSpace32):
    """This AS supports windows Crash Dump format."""
    order = 30

    # Participate in Address Space voting.
    __image = True

    def check_file(self):
        """Check specifically for 64 bit crash dumps."""

        # Must start with the magic PAGEDU64
        self.as_assert((self.base.read(0, 8) == 'PAGEDU64'),
                       "Header signature invalid")

        self.profile = crashdump.CrashDump64Profile(
            session=self.session)

        self.as_assert(self.profile.has_type("_DMP_HEADER64"),
                       "_DMP_HEADER64 not available in profile")
        self.header = self.profile.Object("_DMP_HEADER64",
                                          offset=self.offset, vm=self.base)

        # The following error is fatal - abort the voting mechanism.

        # Unfortunately Volatility does not set this field correctly, so we do
        # not make it a fatal error. It can lead to problems if we try to parse
        # other crash dump formats, (Especially Win8 ones - see below) so we
        # might consider making this a fatal error in future.
        if self.header.DumpType != "Full Dump":
            self.session.logging.warning(
                "This is not a full memory crash dump. Kernel crash dumps are "
                "not supported.")

        # Catch this error early or we will hog all memory trying to parse a
        # huge number of Runs. On Windows 8 we have observed the DumpType to be
        # == 5 and these fields are padded with "PAGE" (i.e. 0x45474150).
        if self.header.PhysicalMemoryBlockBuffer.NumberOfRuns > 100:
            raise RuntimeError(
                "This crashdump file format is not supported. Rekall does not "
                "currently support crashdumps using the Win8 format.")


class WindowsCrashBMP(addrspace.RunBasedAddressSpace):
    """This Address Space supports the new windows Crash Dump format.

    This format first appeared in Windows 8 x64 versions. We reversed this
    format by examining the Crash dump file from a Windows 8 system.

    Alternative implementations:
      Volatility 2.4: crashbmp.py (not working at time of writing.).
    """
    # Must try this before the old Crashdump format.
    order = 25

    PAGE_SIZE = 0x1000

    # Participate in Address Space voting.
    __image = True

    def __init__(self, **kwargs):
        super(WindowsCrashBMP, self).__init__(**kwargs)

        self.as_assert(self.base, "Must stack on another address space")

        # Must start with the magic PAGEDU64
        self.as_assert((self.base.read(0, 8) == 'PAGEDU64'),
                       "Header signature invalid")

        self.profile = crashdump.CrashDump64Profile(
            session=self.session)

        self.header = self.profile.Object("_DMP_HEADER64", vm=self.base)
        self.as_assert(
            self.header.DumpType == "BMP Dump", "Only BMP dumps supported.")

        self.bmp_header = self.header.BMPHeader
        PAGE_SIZE = 0x1000

        # First run [Physical Offset, File Offset, Run length]
        first_page = self.bmp_header.FirstPage.v()
        last_run = [0, first_page, 0]

        for pfn, present in enumerate(self._generate_bitmap()):
            if present:
                if pfn * PAGE_SIZE == last_run[0] + last_run[2]:
                    last_run[2] += PAGE_SIZE

                else:
                    # Dump the last run only if it has non zero length.
                    if last_run[2] > 0:
                        self.add_run(*last_run)

                    # The next run starts here.
                    last_run = [
                        pfn * PAGE_SIZE, last_run[1] + last_run[2], PAGE_SIZE]

        # Flush the last run if needed.
        if last_run[2] > 0:
            self.add_run(*last_run)

        # Set the DTB from the crash dump header.
        self.session.SetCache("dtb", self.header.DirectoryTableBase.v(),
                         volatile=False)


    def _generate_bitmap(self):
        """Generate Present/Not Present for each page in the dump."""
        # The bitmap is an array of 32 bit integers. Each bit in each int
        # represents a single memory page.
        for value in self.bmp_header.Bitmap:
            # This is kind of lame but in python it is way faster than bit
            # manipulations.
            for bit in reversed("{0:032b}".format((value.v()))):
                yield bit == "1"
