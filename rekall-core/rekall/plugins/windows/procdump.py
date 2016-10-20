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

import os

from rekall.plugins.windows import common
from rekall.plugins import core
from rekall import plugin
from rekall import utils


class PEDump(common.WindowsCommandPlugin):
    """Dump a PE binary from memory."""

    __name = "pedump"

    __args = [
        dict(name="image_base", type="SymbolAddress", required=False,
             positional=True,
             help="The address of the image base (dos header)."),

        dict(name="out_file",
             help="The file name to write."),

        dict(name="address_space", type="AddressSpace",
             help="The address space to use."),

        dict(name="out_fd",
             help="A file like object to write the output.")
    ]

    def __init__(self, *args, **kwargs):
        super(PEDump, self).__init__(*args, **kwargs)
        self.pe_profile = self.session.LoadProfile("pe")

    def WritePEFile(self, fd=None, address_space=None, image_base=None):
        """Dumps the PE file found into the filelike object.

        Note that this function can be used for any PE file (e.g. executable,
        dll, driver etc). Only a base address need be specified. This makes this
        plugin useful as a routine in other plugins.

        Args:
          fd: A writable filelike object which must support seeking.
          address_space: The address_space to read from.
          image_base: The offset of the dos file header.
        """
        dos_header = self.pe_profile._IMAGE_DOS_HEADER(
            offset=image_base, vm=address_space)

        image_base = dos_header.obj_offset
        nt_header = dos_header.NTHeader

        # First copy the PE file header, then copy the sections.
        data = dos_header.obj_vm.read(
            image_base, min(1000000, nt_header.OptionalHeader.SizeOfHeaders))

        if not data:
            return

        fd.seek(0)
        fd.write(data)

        for section in nt_header.Sections:
            # Force some sensible maximum values here.
            size_of_section = min(10000000, section.SizeOfRawData)
            physical_offset = min(100000000, int(section.PointerToRawData))

            data = section.obj_vm.read(
                section.VirtualAddress + image_base, size_of_section)

            fd.seek(physical_offset, 0)
            fd.write(data)

    def collect(self):
        renderer = self.session.GetRenderer()
        if self.plugin_args.out_file:
            out_fd = renderer.open(
                filename=self.plugin_args.out_file, mode="wb")
        else:
            out_fd = self.plugin_args.out_fd

        if not out_fd:
            self.session.logging.error(
                "No output filename or file handle specified.")
            return []

        with out_fd:
            self.session.logging.info(
                "Dumping PE File at image_base %#x to %s",
                self.plugin_args.image_base, out_fd.name)

            self.WritePEFile(out_fd, self.plugin_args.address_space,
                             self.plugin_args.image_base)

            return []


class ProcExeDump(core.DirectoryDumperMixin, common.WinProcessFilter):
    """Dump a process to an executable file sample"""

    __name = "procdump"

    dump_dir_optional = True

    __args = [
        dict(name="out_fd",
             help="A file like object to write the output.")
    ]

    table_header = [
        dict(name="_EPROCESS", width=50),
        dict(name="Filename"),
    ]

    def __init__(self, *args, **kwargs):
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
        super(ProcExeDump, self).__init__(*args, **kwargs)
        self.pedump = PEDump(session=self.session)
        if self.dump_dir is None and not self.plugin_args.out_fd:
            raise plugin.PluginError("Dump dir must be specified.")

    def collect(self):
        """Renders the tasks to disk images, outputting progress as they go"""
        for task in self.filter_processes():
            pid = task.UniqueProcessId

            task_address_space = task.get_process_address_space()
            if not task_address_space:
                self.session.logging.info(
                    "Can not get task address space - skipping.")
                continue

            if self.plugin_args.out_fd:
                self.pedump.WritePEFile(
                    self.plugin_args.out_fd,
                    task_address_space, task.Peb.ImageBaseAddress)
                yield task, "User FD"

            # Create a new file.
            else:
                filename = u"executable.%s_%s.exe" % (
                    utils.EscapeForFilesystem(task.name), pid)

                yield task, filename

                with self.session.GetRenderer().open(
                        directory=self.dump_dir,
                        filename=filename,
                        mode="wb") as fd:
                    # The Process Environment Block contains the dos header:
                    self.pedump.WritePEFile(
                        fd, task_address_space, task.Peb.ImageBaseAddress)


class DLLDump(ProcExeDump):
    """Dump DLLs from a process address space"""

    __name = "dlldump"

    __args = [
        dict(name="regex", default=".", type="RegEx",
            help="A Regular expression for selecting the dlls to dump.")
    ]

    table_header = [
        dict(name="_EPROCESS"),
        dict(name="base", style="address"),
        dict(name="module", width=20),
        dict(name="filename")
    ]

    def collect(self):
        for task in self.filter_processes():
            task_as = task.get_process_address_space()

            # Skip kernel and invalid processes.
            for module in task.get_load_modules():
                process_offset = task_as.vtop(task.obj_offset)
                if process_offset:

                    # Skip the modules which do not match the regex.
                    if not self.plugin_args.regex.search(
                            utils.SmartUnicode(module.BaseDllName)):
                        continue

                    base_name = os.path.basename(
                        utils.SmartUnicode(module.BaseDllName))

                    dump_file = "module.{0}.{1:x}.{2:x}.{3}".format(
                        task.UniqueProcessId, process_offset, module.DllBase,
                        utils.EscapeForFilesystem(base_name))

                    yield dict(_EPROCESS=task,
                               base=module.DllBase,
                               module=module.BaseDllName,
                               filename=dump_file)

                    # Use the procdump module to dump out the binary:
                    with self.session.GetRenderer().open(
                            filename=dump_file,
                            directory=self.dump_dir,
                            mode="wb") as fd:
                        self.pedump.WritePEFile(fd, task_as, module.DllBase)

                else:
                    self.session.logging.error(
                        "Cannot dump %s@%s at %#x\n",
                        task.ImageFileName, module.BaseDllName,
                        int(module.DllBase))


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

    table_header = [
        dict(name="Name", width=30),
        dict(name="Base", style="address"),
        dict(name="Filename")
    ]

    def collect(self):
        modules_plugin = self.session.plugins.modules(session=self.session)

        for module in modules_plugin.lsmod():
            if self.plugin_args.regex.search(
                    utils.SmartUnicode(module.BaseDllName)):
                address_space = self.find_space(module.DllBase)
                if address_space:
                    dump_file = "driver.{0:x}.{1}".format(
                        module.DllBase, utils.EscapeForFilesystem(
                            module.BaseDllName))
                    yield (module.BaseDllName, module.DllBase, dump_file)

                    with self.session.GetRenderer().open(
                            filename=dump_file,
                            directory=self.dump_dir,
                            mode="wb") as fd:
                        self.pedump.WritePEFile(
                            fd, address_space, module.DllBase)
