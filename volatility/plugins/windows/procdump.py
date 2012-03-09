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
import logging
import os
import struct

from volatility.plugins.windows import common
from volatility.plugins.windows import taskmods
from volatility import plugin
from volatility import obj


class ProcExeDump(common.WinProcessFilter):
    """Dump a process to an executable file sample"""

    __name = "procexedump"

    def __init__(self, dump_dir=None, unsafe=True, **kwargs):
        """Dump a process from memory into an executable.

        Args:
          dump_dir: Directory in which to dump executable files.
          unsafe: Bypasses certain sanity checks when creating image
        """
        super(ProcExeDump, self).__init__(**kwargs)
        self.dump_dir = dump_dir or self.session.dump_dir
        self.unsafe = unsafe

        # Get the pe profile.
        self.pe_profile = self.profile.classes['PEProfile']()

    def _check_dump_dir(self):
        if not self.dump_dir:
            raise plugin.PluginError("Please specify a dump directory.")

        if not os.path.isdir(self.dump_dir):
            raise plugin.PluginError("%s is not a directory" % self.dump_dir)

    def render(self, outfd):
        """Renders the tasks to disk images, outputting progress as they go"""
        self._check_dump_dir()

        for task in self.filter_processes():
            pid = task.UniqueProcessId
            
            filename = os.path.join(self.dump_dir, "executable.%s_%s.exe" % (
                    task.ImageFileName, pid))

            outfd.write("*" * 72 + "\n")
            outfd.write("Dumping {0}, pid: {1:6} output: {2}\n".format(
                    task.ImageFileName, pid, filename))

            with open(filename, 'wb') as fd:
                try:
                    self.dump_process(task, fd)
                except plugin.PluginError, e:
                    logging.error("Error: %s", e)

    def dump_process(self, task, of):
        pid = task.UniqueProcessId
        task_space = task.get_process_address_space()
        if task.Peb == None:
            raise plugin.PluginError("PEB not memory resident for "
                                     "process [{0}]\n".format(pid))

        if (task.Peb.ImageBaseAddress == None or task_space == None or
            task_space.vtop(task.Peb.ImageBaseAddress) == None):
            raise plugin.PluginError("ImageBaseAddress not memory resident"
                                     " for process [{0}]\n".format(pid))

        try:
            for offset, code in self.get_image(task.get_process_address_space(),
                                               task.Peb.ImageBaseAddress):
                of.seek(offset)
                of.write(code)

        except ValueError, ve:
            logging.error("Unable to dump executable; sanity check failed:\n"
                          "  %s\nYou can use -u to disable this check.\n" % ve)

    def round(self, addr, align, up = False):
        """Rounds down an address based on an alignment"""
        if addr % align == 0:
            return addr
        else:
            if up:
                return (addr + (align - (addr % align)))
            return (addr - (addr % align))

    def get_nt_header(self, addr_space, base_addr):
        """Returns the NT Header object for a task"""
        dos_header = self.pe_profile.Object("_IMAGE_DOS_HEADER", offset = base_addr,
                                            vm = addr_space)

        return dos_header.get_nt_header()

    def get_code(self, addr_space, data_start, data_size, offset):
        """Returns a single section of re-created data from a file image"""
        data_start = int(data_start)
        first_block = 0x1000 - data_start % 0x1000
        full_blocks = ((data_size + (data_start % 0x1000)) / 0x1000) - 1
        left_over = (data_size + data_start) % 0x1000

        paddr = addr_space.vtop(data_start)
        code = ""

        # Deal with reads that are smaller than a block
        if data_size < first_block:
            data_read = addr_space.zread(data_start, data_size)
            if paddr == None:
                logging.info("Memory Not Accessible: Virtual Address: 0x{0:x} "
                             "File Offset: 0x{1:x} Size: 0x{2:x}".format(
                        data_start, offset, data_size))

            code += data_read

            return (offset, code)

        data_read = addr_space.zread(data_start, first_block)
        if paddr == None:
            logging.info("Memory Not Accessible: Virtual Address: 0x{0:x} "
                         "File Offset: 0x{1:x} Size: 0x{2:x}".format(
                    data_start, offset, first_block))
        code += data_read

        # The middle part of the read
        new_vaddr = data_start + first_block

        for _i in range(0, full_blocks):
            data_read = addr_space.zread(new_vaddr, 0x1000)
            if not new_vaddr or addr_space.vtop(new_vaddr) == None:
                logging.debug("Memory Not Accessible: Virtual Address: 0x{0:x} "
                              "File Offset: 0x{1:x} Size: 0x{2:x}".format(
                        new_vaddr, offset, 0x1000))
            code += data_read
            new_vaddr = new_vaddr + 0x1000

        # The last part of the read
        if left_over > 0:
            data_read = addr_space.zread(new_vaddr, left_over)
            if addr_space.vtop(new_vaddr) == None:
                logging.debug("Memory Not Accessible: Virtual Address: 0x{0:x} "
                              "File Offset: 0x{1:x} Size: 0x{2:x}".format(
                        new_vaddr, offset, left_over))
            code += data_read
        return (offset, code)

    def get_image(self, addr_space, base_addr):
        """Outputs an executable disk image of a process"""
        nt_header = self.get_nt_header(addr_space = addr_space,
                                       base_addr = base_addr)

        soh = nt_header.OptionalHeader.SizeOfHeaders
        header = addr_space.read(base_addr, soh)
        yield (0, header)

        fa = nt_header.OptionalHeader.FileAlignment
        for sect in nt_header.get_sections(self.unsafe):
            foa = self.round(sect.PointerToRawData, fa)
            if foa != sect.PointerToRawData:
                logging.warning("section start on disk not aligned to file alignment.")
                logging.warning("adjusted section start from {0} to {1}.".format(
                        sect.PointerToRawData, foa))
            yield self.get_code(addr_space,
                                sect.VirtualAddress + base_addr,
                                sect.SizeOfRawData, foa)

class ProcMemDump(ProcExeDump):
    """Dump a process to an executable memory sample"""

    __name = "procmemdump"

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
