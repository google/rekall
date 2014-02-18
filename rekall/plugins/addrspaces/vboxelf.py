# Rekall Memory Forensics
#
# Copyright 2012 Philippe Teuwen, Thorsten Sick, Michael Cohen
# Copyright 2013 Google Inc. All Rights Reserved.
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

"""An Address Space for processing ELF64 coredumps."""
# References:
# VirtualBox core format: http://www.virtualbox.org/manual/ch12.html#guestcoreformat
# ELF64 format: http://downloads.openwatcom.org/ftp/devel/docs/elf-64-gen.pdf

from rekall import addrspace
from rekall.plugins.overlays.linux import elf


class Elf64CoreDump(addrspace.RunBasedAddressSpace):
    """This AS supports ELF64 coredump format, as used by VirtualBox."""
    order = 30

    __name = "elf64"
    _md_image = True

    def __init__(self, **kwargs):
        super(Elf64CoreDump, self).__init__(**kwargs)

        # Check the file for sanity.
        self.check_file()

        self.offset = 0
        self.fname = ''

        # Now parse the ELF file.
        elf_profile = elf.ELFProfile(session=self.session)
        self.elf64_hdr = elf_profile.elf64_hdr(vm=self.base, offset=0)

        self.as_assert(self.elf64_hdr.e_type == "ET_CORE",
                       "Elf file is not a core file.")

        # Iterate over all the section headers and map the runs.
        for section in self.elf64_hdr.e_phoff:
            if section.p_type == "PT_LOAD":
                # Some load sections are empty.
                if (section.p_filesz == 0 or
                    section.p_filesz != section.p_memsz):
                    continue

                # Add the run to the memory map.
                self.runs.insert((int(section.p_paddr),  # Virtual Addr
                                  int(section.p_offset), # File Addr
                                  int(section.p_memsz))) # Length

    def check_file(self):
        """Checks the base file handle for sanity."""

        self.as_assert(self.base,
                       "Must stack on another address space")

        ## Must start with the magic for elf
        self.as_assert((self.base.read(0, 4) == "\177ELF"),
                       "Header signature invalid")
