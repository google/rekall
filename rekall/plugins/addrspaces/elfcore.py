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
        self._metadata = {}

        # Now parse the ELF file.
        elf_profile = elf.ELFProfile(session=self.session)
        self.elf64_hdr = elf_profile.elf64_hdr(vm=self.base, offset=0)

        self.as_assert(self.elf64_hdr.e_type == "ET_CORE",
                       "Elf file is not a core file.")
        self.name = "%s|%s" % (self.__class__.__name__, self.base.name)

        # Iterate over all the program headers and map the runs.
        for segment in self.elf64_hdr.e_phoff:
            if segment.p_type == "PT_LOAD":
                # Some load segments are empty.
                if (segment.p_filesz == 0 or
                        segment.p_filesz != segment.p_memsz):
                    continue

                # Add the run to the memory map.
                virtual_address = int(segment.p_paddr) or int(segment.p_vaddr)
                self.runs.insert((virtual_address,  # Virtual Addr
                                  int(segment.p_offset), # File Addr
                                  int(segment.p_memsz))) # Length

            elif segment.p_type == PT_PMEM_METADATA:
                self.LoadMetadata(segment.p_offset)

        # Search for the pmem footer signature.
        footer = self.base.read(self.base.end() - 10000, 10000)
        if "...\n" in footer[-6:]:
            header_offset = footer.rfind("# PMEM")
            if header_offset > 0:
                self.LoadMetadata(self.base.end() - 10000 + header_offset)

    def check_file(self):
        """Checks the base file handle for sanity."""

        self.as_assert(self.base,
                       "Must stack on another address space")

        ## Must start with the magic for elf
        self.as_assert((self.base.read(0, 4) == "\177ELF"),
                       "Header signature invalid")

    def LoadMetadata(self, offset):
        """Load the WinPmem metadata from the elf file."""
        try:
            data = self.base.read(offset, 1024*1024)
            yaml_file = data.split('...\n')[0]

            metadata = yaml.safe_load(yaml_file)
        except (yaml.YAMLError, TypeError) as e:
            logging.error("Invalid file metadata, skipping: %s" % e)
            return

        for session_param, metadata_key in (("dtb", "CR3"),
                                            ("kernel_base", "KernBase")):
            if metadata_key in metadata:
                self.session.SetParameter(
                    session_param, metadata[metadata_key])

        previous_section = metadata.pop("PreviousHeader", None)
        if previous_section is not None:
            self.LoadMetadata(previous_section)

        pagefile_offset = metadata.get("PagefileOffset", None)
        pagefile_size = metadata.get("PagefileSize", None)

        if pagefile_offset is not None and pagefile_size is not None:
            self.LoadPageFile(pagefile_offset, pagefile_size)

        self._metadata.update(metadata)

    pagefile_offset = 0
    pagefile_end = 0

    def LoadPageFile(self, pagefile_offset, pagefile_size):
        """We map the page file into the physical address space.

        This allows us to treat all physical addresses equally - regardless if
        they come from the memory or the page file.
        """
        # Map the pagefile after the end of the physical address space.
        vaddr = self.end() + 0x10000

        logging.info("Loading pagefile into physical offset %#08x", vaddr)
        self.runs.insert((vaddr, pagefile_offset, pagefile_size))

        # Remember the region for the pagefile.
        self.pagefile_offset = vaddr
        self.pagefile_end = vaddr + pagefile_size

    def describe(self, addr):
        if self.pagefile_offset <= addr <= self.pagefile_end:
            return "%#x@Pagefile" % (
                addr - self.pagefile_offset)

        return "%#x" % addr


class KCoreAddressSpace(Elf64CoreDump):
    """A Linux kernel's /proc/kcore file also maps the entire physical ram.

    http://lxr.free-electrons.com/source/Documentation/x86/x86_64/mm.txt

    ffff880000000000 - ffffc7ffffffffff (=64 TB) direct mapping of all phys. memory
    """

    # We must run before the regular Elf64CoreDump address space in the voting
    # order.
    order = Elf64CoreDump.order - 1

    __name = "elf64"
    __image = True

    def __init__(self, **kwargs):
        super(KCoreAddressSpace, self).__init__(**kwargs)

        # Collect all ranges between ffff880000000000 - ffffc7ffffffffff
        runs = []

        for vaddr, paddr, length in self.runs:
            if 0xffff880000000000 < vaddr < 0xffffc7ffffffffff:
                runs.append((vaddr - 0xffff880000000000, paddr, length))

        self.as_assert(runs, "No kcore compatible virtual ranges.")
        self.runs.clear()
        for x in runs:
            self.runs.insert(x)


def WriteElfFile(address_space, outfd, session=None):
    """Convert the address_space to an ELF Core dump file.

    The Core dump will be written to outfd which is expected to have a .write()
    method.
    """
    runs = list(address_space.get_available_addresses())

    elf_profile = elf.ELFProfile(session=session)
    elf64_pheader = elf_profile.elf64_phdr()
    elf64_pheader.p_type = "PT_LOAD"
    elf64_pheader.p_align = 0x1000
    elf64_pheader.p_flags = "PF_R"

    elf64_header = elf_profile.elf64_hdr()
    elf64_header.e_ident = elf64_header.e_ident.signature
    elf64_header.e_type = 'ET_CORE'
    elf64_header.e_phoff = elf64_header.obj_end
    elf64_header.e_ehsize = elf64_header.obj_size
    elf64_header.e_phentsize = elf64_pheader.obj_size
    elf64_header.e_phnum = len(runs)
    elf64_header.e_shnum = 0  # We don't have any sections.

    # Where we start writing data.
    file_offset = (elf64_header.obj_size +
                   # One Phdr for each run.
                   len(runs) * elf64_pheader.obj_size)

    outfd.write(elf64_header.GetData())
    for offset, _, length in runs:
        elf64_pheader.p_paddr = offset
        elf64_pheader.p_memsz = length
        elf64_pheader.p_offset = file_offset
        elf64_pheader.p_filesz = length

        outfd.write(elf64_pheader.GetData())

        file_offset += length

    # Now just copy all the runs
    total_data = 0
    for offset, _, length in runs:
        while length > 0:
            data = address_space.read(offset, min(10000000, length))
            session.report_progress("Writing %sMb", total_data/1024/1024)
            outfd.write(data)
            length -= len(data)
            offset += len(data)
            total_data += len(data)
