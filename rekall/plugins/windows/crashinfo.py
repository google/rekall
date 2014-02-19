# Rekall Memory Forensics
#
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Authors:
# Michael Cohen <scudette@gmail.com>
# Based on code by Aaron Walters.
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

import os

from rekall import plugin
from rekall.plugins.windows import common
from rekall.plugins.addrspaces import standard
from rekall.plugins.overlays.windows import windows


class Raw2Dump(common.WindowsCommandPlugin):
    """Convert the physical address space to a crash dump."""

    __name = "raw2dmp"

    def __init__(self, destination=None, overwrite=False,
                 buffer_size=10*1024*1024, **kwargs):
        """Convert the physical address space to a crash dump.

        Args:
          destination: The destination path to write the crash dump.
          overwrite: Should the output be overwritten?
        """
        super(Raw2Dump, self).__init__(**kwargs)
        self.profile = windows.CrashDump64Profile(session=self.session)

        self.buffer_size = buffer_size
        self.destination = destination
        if not destination:
            raise plugin.PluginError("A destination must be provided.")

        if not overwrite and os.access(destination, os.F_OK):
            raise plugin.PluginError(
                "Unable to overwrite the destination file '%s'" % destination)

    def render(self, renderer):
        PAGE_SIZE = 0x1000

        # We write the image to the destination using the WriteableAddressSpace.
        out_as = standard.WriteableAddressSpace(filename=self.destination)

        if self.profile.metadata("arch") == "AMD64":
            header = self.profile.Object('_DMP_HEADER64', offset=0, vm=out_as)

            # Pad the header area with PAGE pattern:
            out_as.write(0, "PAGE" * (header.size() / 4))

            header.KdDebuggerDataBlock = int(self.kdbg) | 0xFFFF000000000000
            out_as.write(4, "DU64")
        else:
            header = self.profile.Object('_DMP_HEADER64', offset=0, vm=out_as)
            header.KdDebuggerDataBlock = int(self.kdbg)

            # Pad the header area with PAGE pattern:
            out_as.write(0, "PAGE" * (header.size() / 4))
            out_as.write(4, "DUMP")

            # PEA address spaces.
            if getattr(self.kernel_address_space, "pae", None):
                header.PaeEnabled = 1

        # Scanning the memory region near KDDEBUGGER_DATA64 for
        # DBGKD_GET_VERSION64
        dbgkd = self.kdbg.dbgkd_version64()

        # Write the runs from our physical address space.
        number_of_pages = 0
        i = None

        for i, (start, length) in enumerate(
            self.physical_address_space.get_available_addresses()):
            # Convert to pages
            start = start / PAGE_SIZE
            length = length / PAGE_SIZE

            header.PhysicalMemoryBlockBuffer.Run[i].BasePage = start
            header.PhysicalMemoryBlockBuffer.Run[i].PageCount = length
            number_of_pages += length

        # Must be at least one run.
        if i is None:
            raise plugin.PluginError(
                "Physical address space has no available data.")

        header.PhysicalMemoryBlockBuffer.NumberOfRuns = i + 1
        header.PhysicalMemoryBlockBuffer.NumberOfPages = number_of_pages

        # Set members of the crash header
        header.MajorVersion = dbgkd.MajorVersion.v()
        header.MinorVersion = dbgkd.MinorVersion.v()
        header.DirectoryTableBase = self.session.GetParameter("dtb")
        header.PfnDataBase = self.kdbg.MmPfnDatabase.v()
        header.PsLoadedModuleList = self.kdbg.PsLoadedModuleList.v()
        header.PsActiveProcessHead = self.kdbg.PsActiveProcessHead.v()
        header.MachineImageType = dbgkd.MachineType.v()

        # Find the number of processors
        header.NumberProcessors = len(list(self.kdbg.kpcrs()))

        # Zero out the BugCheck members
        header.BugCheckCode = 0x00000000
        header.BugCheckCodeParameter[0] = 0x00000000
        header.BugCheckCodeParameter[1] = 0x00000000
        header.BugCheckCodeParameter[2] = 0x00000000
        header.BugCheckCodeParameter[3] = 0x00000000

        # Set the sample run information

        header.RequiredDumpSpace = number_of_pages + header.size() / PAGE_SIZE
        header.SystemTime = 0
        header.DumpType = 1

        # Zero out the remaining non-essential fields from ContextRecordOffset
        # to ExceptionOffset.
        out_as.write(header.ContextRecord.obj_offset,
                     "\x00" * (header.m("Exception").obj_offset -
                               header.ContextRecord.obj_offset))

        # Set the "converted" comment
        out_as.write(header.Comment.obj_offset,
                     "File was converted with Rekall Memory Forensics" + "\x00")

        # Now copy the physical address space to the output file.
        output_offset = header.size()
        for _ in self.physical_address_space.get_available_addresses():
            start, length = _

            # Convert to pages
            start = start / PAGE_SIZE
            length = length / PAGE_SIZE

            renderer.write("\nRun [0x%08X, 0x%08X] \n" % (
                    start, length))
            data_length = length * PAGE_SIZE
            start_offset = start * PAGE_SIZE
            offset = 0
            while data_length > 0:
                to_read = min(data_length, self.buffer_size)

                data = self.physical_address_space.read(
                    start_offset + offset, to_read)

                out_as.write(output_offset, data)
                output_offset += len(data)
                offset += len(data)
                data_length -= len(data)
                renderer.RenderProgress(
                    "Wrote %sMB.", (start_offset + offset)/1024/1024)
