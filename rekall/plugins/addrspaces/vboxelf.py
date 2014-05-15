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
# VirtualBox core format:
# http://www.virtualbox.org/manual/ch12.html#guestcoreformat
# ELF64 format: http://downloads.openwatcom.org/ftp/devel/docs/elf-64-gen.pdf

# Note that as of version 1.6.0 WinPmem also uses ELF64 as the default imaging
# format. Except that WinPmem stores image metadata in a YAML file stored in the
# image. This address space supports both formats.

import logging
import yaml

from rekall import addrspace
from rekall.plugins.overlays.linux import elf

PT_PMEM_METADATA = 0x6d656d70  # Spells 'pmem'



class Elf64CoreDump(addrspace.RunBasedAddressSpace):
    """This AS supports ELF64 coredump format, as used by VirtualBox."""
    order = 30

    __name = "elf64"
    __image = True

    def __init__(self, **kwargs):
        super(Elf64CoreDump, self).__init__(**kwargs)

        # Check the file for sanity.
        self.check_file()

        self.offset = 0
        self.fname = ''
        self.metadata = {}

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

            elif section.p_type == PT_PMEM_METADATA:
                # Allow the file to be extended if users want to append
                # metadata to the file.

                to_read = max(1000000, int(section.p_filesz))
                data = self.base.read(section.p_offset, to_read)
                data = data.split("\x00")[0]

                self.LoadMetadata(data)

    def check_file(self):
        """Checks the base file handle for sanity."""

        self.as_assert(self.base,
                       "Must stack on another address space")

        ## Must start with the magic for elf
        self.as_assert((self.base.read(0, 4) == "\177ELF"),
                       "Header signature invalid")

    def LoadMetadata(self, data):
        """Load the WinPmem metadata from the elf file."""
        try:
            self.metadata.update(yaml.safe_load(data))
        except yaml.YAMLError as e:
            logging.error("Invalid file metadata, skipping: %s" % e)
            return

        for session_param, metadata in (("dtb", "CR3"),
                                        ("kernel_base", "KernBase")):
            if metadata in self.metadata:
                self.session.SetParameter(
                    session_param, self.metadata[metadata])
