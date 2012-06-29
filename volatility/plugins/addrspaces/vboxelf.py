# Volatility
#
# Copyright 2012 Philippe Teuwen, Thorsten Sick, Michael Cohen
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

"""An Address Space for processing VirtualBox ELF64 coredumps """
# References:
# VirtualBox core format: http://www.virtualbox.org/manual/ch12.html#guestcoreformat
# ELF64 format: http://downloads.openwatcom.org/ftp/devel/docs/elf-64-gen.pdf

from volatility import addrspace
from volatility.plugins.overlays.linux import elf


class VirtualBoxCoreDumpElf64(addrspace.PagedReader):
    """ This AS supports VirtualBox ELF64 coredump format """
    order = 30

    __name = "vbox"

    def __init__(self, **kwargs):
        super(VirtualBoxCoreDumpElf64, self).__init__(**kwargs)

        self.runs = []
        self.offset = 0
        self.fname = ''

        # Check the file for sanity.
        self.check_file()

        # Now parse the ELF file.
        elf_profile = elf.ELFProfile()
        self.elf64_hdr = elf_profile.elf64_hdr(vm=self.base, offset=0)

        self.as_assert(self.elf64_hdr.e_type == "ET_CORE",
                       "Elf file is not a core file.")

        # This is a lookup table: (virtual_address, physical_address, length)
        self.runs = []

        # Iterate over all the section headers and map the runs.
        for section in self.elf64_hdr.e_phoff:
            if section.p_type == "PT_LOAD":
                # Some load sections are empty.
                if (section.p_filesz == 0 or
                    section.p_filesz != section.p_memsz):
                    continue

                # Add the run to the memory map.
                self.runs.append((int(section.p_vaddr),  # Virtual Addr
                                  int(section.p_offset), # File Addr
                                  int(section.p_memsz))) # Length

    def check_file(self):
        """Checks the base file handle for sanity."""

        self.as_assert(self.base,
                       "Must stack on another address space")

        ## Must start with the magic for elf
        self.as_assert((self.base.read(0, 4) == "\177ELF"),
                       "Header signature invalid")

    def _read_chunk(self, addr, length, pad):
        file_offset, available_length = self._get_available_buffer(addr, length)

        # Mapping not valid.
        if file_offset is None:
            return "\x00" * available_length

        else:
            return self.base.read(file_offset, min(length, available_length))

    def vtop(self, addr):
        file_offset, _ = self._get_available_buffer(addr, 1)
        return file_offset

    def _get_available_buffer(self, addr, length):
        """Resolves the address into the file offset.

        In a crash dump, pages are stored back to back in runs. This function
        finds the run that contains this page and returns the file address where
        this page can be found.

        Returns:
          A tuple of (physical_offset, available_length). The physical_offset
          can be None to signify that the address is not valid.
        """
        for virt_addr, file_address, length in self.runs:
            if addr < virt_addr:
                available_length = min(length, virt_addr - addr)
                return (None, available_length)

            # The required page is inside this run.
            if addr >= virt_addr and addr < virt_addr + length:
                file_offset = file_address + (addr - virt_addr)
                available_length = virt_addr + length - addr

                # Offset of page in the run.
                return (file_offset, available_length)

        return None, 0

    def get_available_addresses(self):
        for virt_addr, _, length in self.runs:
            yield virt_addr, length
