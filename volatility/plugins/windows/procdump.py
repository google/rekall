# Volatility
# Copyright (C) 2007,2008 Volatile Systems
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
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
import os
import re
import struct

from volatility.plugins.windows import common
from volatility import plugin
from volatility import utils


class ProcExeDump(common.WinProcessFilter):
    """Dump a process to an executable file sample"""

    __name = "procdump"

    def __init__(self, dump_dir=None, remap=False, outfd=None, **kwargs):
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
          dump_dir: Directory in which to dump executable files.

          remap: If set, allows to remap the sections on disk so they do not
            overlap.

          fd: Alternatively, a filelike object can be provided directly.
        """
        super(ProcExeDump, self).__init__(**kwargs)
        self.dump_dir = dump_dir or self.session.dump_dir

        # Get the pe profile.
        self.pe_profile = self.profile.classes['PEProfile']()
        self.fd = outfd

    def WritePEFile(self, fd, address_space, image_base):
        """Dumps the PE file found into the filelike object.

        Args:
          fd: A writeable filelike object which must support seeking.
          address_space: The address_space to read from.
          image_base: The offset of the dos file header.
        """
        dos_header = self.pe_profile.Object("_IMAGE_DOS_HEADER", offset=image_base,
                                            vm=address_space)
        image_base = dos_header.obj_offset
        nt_header = dos_header.NTHeader

        # First copy the PE file header, then copy the sections.
        data = dos_header.obj_vm.zread(
            image_base, min(1e6, nt_header.OptionalHeader.SizeOfHeaders))

        fd.seek(0)
        fd.write(data)

        for section in nt_header.Sections:
            # Force some sensible maximum values here.
            size_of_section = min(10e6, section.SizeOfRawData)
            physical_offset = min(100e6, int(section.PointerToRawData))

            data = section.obj_vm.zread(
                section.VirtualAddress + image_base, size_of_section)

            fd.seek(physical_offset, 0)
            fd.write(data)

    def _check_dump_dir(self):
        if not self.dump_dir:
            raise plugin.PluginError("Please specify a dump directory.")

        if not os.path.isdir(self.dump_dir):
            raise plugin.PluginError("%s is not a directory" % self.dump_dir)

    def render(self, outfd):
        """Renders the tasks to disk images, outputting progress as they go"""
        if self.dump_dir:
            self._check_dump_dir()

        for task in self.filter_processes():
            pid = task.UniqueProcessId

            task_address_space = task.get_process_address_space()
            if not task_address_space:
                outfd.write("Can not get task address space - skipping.")
                continue

            if self.fd:
                self.WritePEFile(self.fd, task_address_space, task.Peb.ImageBaseAddress)
                outfd.write("*" * 72 + "\n")

                outfd.write("Dumping {0}, pid: {1:6} into user provided fd.\n".format(
                        task.ImageFileName, pid))

            # Create a new file.
            else:
                sanitized_image_name = re.sub("[^a-zA-Z0-9-_]", "_",
                                              utils.SmartStr(task.ImageFileName))

                filename = os.path.join(self.dump_dir, u"executable.%s_%s.exe" % (
                        sanitized_image_name, pid))

                outfd.write("*" * 72 + "\n")
                outfd.write("Dumping {0}, pid: {1:6} output: {2}\n".format(
                        task.ImageFileName, pid, filename))

                with open(filename, 'wb') as fd:
                    # The Process Environment Block contains the dos header:
                    self.WritePEFile(fd, task_address_space, task.Peb.ImageBaseAddress)



class ProcMemDump(ProcExeDump):
    """Dump a process to an executable memory sample"""

    __name = "procmemdump"

    # Disabled - functionality merged into the procexedump module above.
    __abstract = True

    def replace_header_field(self, sect, header, item, value):
        """Replaces a field in a sector header"""
        field_size = item.size()
        start = item.obj_offset - sect.obj_offset
        end = start + field_size
        newval = struct.pack(item.format_string, int(value))
        result = header[:start] + newval + header[end:]
        return result

    def get_image(self, addr_space, base_addr):
        """Outputs an executable memory image of a process"""
        nt_header = self.get_nt_header(addr_space, base_addr)

        sa = nt_header.OptionalHeader.SectionAlignment
        shs = self.pe_profile.get_obj_size('_IMAGE_SECTION_HEADER')

        yield self.get_code(addr_space, base_addr, nt_header.OptionalHeader.SizeOfImage, 0)

        prevsect = None
        sect_sizes = []
        for sect in nt_header.get_sections(self.unsafe):
            if prevsect is not None:
                sect_sizes.append(sect.VirtualAddress - prevsect.VirtualAddress)
            prevsect = sect
        if prevsect is not None:
            sect_sizes.append(self.round(prevsect.Misc.VirtualSize, sa, up = True))

        counter = 0
        start_addr = nt_header.FileHeader.SizeOfOptionalHeader + (
            nt_header.OptionalHeader.obj_offset - base_addr)

        for sect in nt_header.get_sections(self.unsafe):
            sectheader = addr_space.read(sect.obj_offset, shs)
            # Change the PointerToRawData
            sectheader = self.replace_header_field(
                sect, sectheader, sect.PointerToRawData, sect.VirtualAddress)
            sectheader = self.replace_header_field(
                sect, sectheader, sect.SizeOfRawData, sect_sizes[counter])
            sectheader = self.replace_header_field(
                sect, sectheader, sect.Misc.VirtualSize, sect_sizes[counter])

            yield (start_addr + (counter * shs), sectheader)
            counter += 1
