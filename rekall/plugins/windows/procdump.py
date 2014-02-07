# Rekall Memory Forensics
# Copyright (C) 2007,2008 Volatile Systems
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Additional Authors:
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

# pylint: disable=protected-access

import logging
import os
import re

from rekall.plugins.windows import common
from rekall.plugins import core
from rekall import config
from rekall import utils


class PEDump(common.WinProcessFilter):
    """Dump a PE binary from memory."""

    __name = "pedump"

    @classmethod
    def args(cls, parser):
        """Declare the command line args we need."""
        super(PEDump, cls).args(parser)
        parser.add_argument(
            "--image_base", default=0, action=config.IntParser,
            help="The address of the image base (dos header).")

        parser.add_argument("--out_file", default=None,
                            help="The file name to write.")


    def __init__(self, address_space=None, image_base=None, out_fd=None,
                 out_file=None, **kwargs):
        """Dump a PE binary from memory.

        Args:
          address_space: The address space which contains the PE image.
          image_base: The address of the image base (dos header).
          out_fd: The output file like object which will be used to write the
            file onto.

          out_file: Alternatively a filename can be provided to write the PE
            file to.
        """
        super(PEDump, self).__init__(**kwargs)
        self.address_space = address_space
        self.image_base = image_base
        if out_fd:
            self.out_fd = out_fd
            self.out_file = "FD <%s>" % out_fd
        elif out_file:
            self.out_fd = open(out_file, "wb")
            self.out_file = out_file
        else:
            self.out_fd = None
            self.out_file = None

        # Get the pe profile.
        self.pe_profile = self.session.LoadProfile("pe")

    def WritePEFile(self, fd=None, address_space=None, image_base=None):
        """Dumps the PE file found into the filelike object.

        Note that this function can be used for any PE file (e.g. executable,
        dll, driver etc). Only a base address need be specified. This makes this
        plugin useful as a routine in other plugins.

        Args:
          fd: A writeable filelike object which must support seeking.
          address_space: The address_space to read from.
          image_base: The offset of the dos file header.
        """
        dos_header = self.pe_profile._IMAGE_DOS_HEADER(
            offset=image_base, vm=address_space)

        image_base = dos_header.obj_offset
        nt_header = dos_header.NTHeader

        # First copy the PE file header, then copy the sections.
        data = dos_header.obj_vm.read(
            image_base, min(1e6, nt_header.OptionalHeader.SizeOfHeaders))

        if not data:
            return

        fd.seek(0)
        fd.write(data)

        for section in nt_header.Sections:
            # Force some sensible maximum values here.
            size_of_section = min(10e6, section.SizeOfRawData)
            physical_offset = min(100e6, int(section.PointerToRawData))

            data = section.obj_vm.read(
                section.VirtualAddress + image_base, size_of_section)

            fd.seek(physical_offset, 0)
            fd.write(data)

    def render(self, renderer):
        if self.out_fd is None:
            logging.error("No output filename or file handle specified.")
            return

        # Default address space is the kernel if not specified.
        if self.address_space is None:
            self.address_space = self.kernel_address_space

        if self.out_file is None:
            logging.error("output file must be specified.")
        else:
            renderer.format("Dumping PE File at image_base {0:#x} to {1}\n",
                            self.image_base, self.out_file)

            self.WritePEFile(self.out_fd, self.address_space, self.image_base)

            renderer.format("Done!\n")


class ProcExeDump(core.DirectoryDumperMixin, common.WinProcessFilter):
    """Dump a process to an executable file sample"""

    __name = "procdump"

    dump_dir_optional = True

    def __init__(self, out_fd=None, **kwargs):
        """Dump a process from memory into an executable.

        In windows PE files are mapped into memory in sections. Each section is
        mapped into a region within the process virtual memory from a region in
        the executable file:

    File on Disk                 Memory Image
0-> ------------    image base-> ------------
     Header                      Header
    ------------                 ------------
     Section 1
    ------------                 ------------
     Section 2                    Section 1
    ------------                 ------------

                                 ------------
                                  Section 2
                                 ------------

        This plugin simply copies the sections from memory back into the file on
        disk. Its likely that some of the pages in memory are not actually
        memory resident, so we might get invalid page reads. In this case the
        region on disk is null padded. If that happens it will not be possible
        to run the executable, but the executable can still be disassembled and
        analysed statically.

        References:
        http://code.google.com/p/corkami/downloads/detail?name=pe-20110117.pdf

        NOTE: Malware can mess with the headers after loading. The remap option
        allows to remap the sections on the disk file so they do not collide.

        Args:
          remap: If set, allows to remap the sections on disk so they do not
            overlap.

          out_fd: Alternatively, a filelike object can be provided directly.
        """
        # If a fd was not provided, the dump_dir must be specified.
        if out_fd is None:
            self.dump_dir_optional = False

        super(ProcExeDump, self).__init__(**kwargs)
        self.fd = out_fd
        self.pedump = PEDump(session=self.session)

    def render(self, renderer):
        """Renders the tasks to disk images, outputting progress as they go"""
        for task in self.filter_processes():
            pid = task.UniqueProcessId

            task_address_space = task.get_process_address_space()
            if not task_address_space:
                renderer.format("Can not get task address space - skipping.")
                continue

            if self.fd:
                self.pedump.WritePEFile(
                    self.fd, task_address_space, task.Peb.ImageBaseAddress)
                renderer.section()

                renderer.format("Dumping {0}, pid: {1:6} into user provided "
                                "fd.\n", task.ImageFileName, pid)

            # Create a new file.
            else:
                sanitized_image_name = re.sub(
                    "[^a-zA-Z0-9-_]", "_", utils.SmartStr(task.ImageFileName))

                filename = os.path.join(
                    self.dump_dir, u"executable.%s_%s.exe" % (
                        sanitized_image_name, pid))

                renderer.section()

                renderer.format("Dumping {0}, pid: {1:6} output: {2}\n",
                                task.ImageFileName, pid, filename)

                with open(filename, 'wb') as fd:
                    # The Process Environment Block contains the dos header:
                    self.pedump.WritePEFile(
                        fd, task_address_space, task.Peb.ImageBaseAddress)


class DLLDump(ProcExeDump):
    """Dump DLLs from a process address space"""

    __name = "dlldump"

    @classmethod
    def args(cls, parser):
        """Declare the command line args we need."""
        super(DLLDump, cls).args(parser)
        parser.add_argument(
            "--regex", default=".+",
            help="A Regular expression for selecting the dlls to dump.")

    def __init__(self, regex=".+", **kwargs):
        """Dumps dlls from processes into files.

        Args:
          regex: A regular expression that is applied to the modules name.
        """
        super(DLLDump, self).__init__(**kwargs)
        self.regex = re.compile(regex)

    def render(self, renderer):
        for task in self.filter_processes():
            task_as = task.get_process_address_space()

            # Skip kernel and invalid processes.
            for module in task.get_load_modules():
                process_offset = task_as.vtop(task.obj_offset)
                if process_offset:

                    # Skip the modules which do not match the regex.
                    if not self.regex.search(
                        utils.SmartUnicode(module.BaseDllName)):
                        continue

                    dump_file = "module.{0}.{1:x}.{2:x}.dll".format(
                        task.UniqueProcessId, process_offset, module.DllBase)

                    renderer.format(
                        "Dumping {0}, Process: {1}, Base: {2:8x} "
                        "output: {3}\n", module.BaseDllName,
                        task.ImageFileName, module.DllBase, dump_file)

                    # Use the procdump module to dump out the binary:
                    path = os.path.join(self.dump_dir, dump_file)
                    with open(path, "wb") as fd:
                        self.pedump.WritePEFile(fd, task_as, module.DllBase)

                else:
                    renderer.format(
                        "Cannot dump {0}@{1} at {2:8x}\n",
                        task.ImageFileName, module.BaseDllName, module.DllBase)


class ModDump(DLLDump):
    """Dump kernel drivers from kernel space."""

    __name = "moddump"

    address_spaces = None

    def find_space(self, image_base):
        """Search through all process address spaces for a PE file."""
        if self.address_spaces is None:
            self.address_spaces = [self.kernel_address_space]
            for task in self.filter_processes():
                self.address_spaces.append(task.get_process_address_space())

        for address_space in self.address_spaces:
            if address_space.is_valid_address(image_base):
                return address_space

    def render(self, renderer):
        modules_plugin = self.session.plugins.modules(session=self.session)

        for module in modules_plugin.lsmod():
            if self.regex.search(utils.SmartUnicode(module.BaseDllName)):
                address_space = self.find_space(module.DllBase)
                if address_space:
                    dump_file = "driver.{0:x}.sys".format(module.DllBase)
                    renderer.format("Dumping {0}, Base: {1:8x} output: {2}\n",
                                    module.BaseDllName, module.DllBase,
                                    dump_file)

                    path = os.path.join(self.dump_dir, dump_file)
                    with open(path, "wb") as fd:
                        self.pedump.WritePEFile(
                            fd, address_space, module.DllBase)
