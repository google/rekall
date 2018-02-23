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
import re
import struct
import os
import yaml

from rekall import addrspace
from rekall import constants
from rekall.plugins.addrspaces import standard
from rekall.plugins.overlays.linux import elf

from rekall_lib import utils

PT_PMEM_METADATA = 0x6d656d70  # Spells 'pmem'


def ParseIOMap(string):
    result = {}
    line_re = re.compile("([0-9a-f]+)-([0-9a-f]+)\s*:\s*(.+)")
    for line in string.splitlines():
        m =  line_re.search(line)
        if m:
            result.setdefault(m.group(3), []).append(
                addrspace.Run(
                    start=int("0x"+m.group(1), 16),
                    end=int("0x"+m.group(2), 16)))
        else:
            raise IOError("Unable to parse iomap")

    return result


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
        for segment in self.elf64_hdr.segments:
            if segment.p_type == "PT_LOAD":
                # Some load segments are empty.
                if (segment.p_filesz == 0 or
                        segment.p_filesz != segment.p_memsz):
                    continue

                # Add the run to the memory map.
                virtual_address = int(segment.p_paddr) or int(segment.p_vaddr)
                self.add_run(virtual_address,  # Virtual Addr
                             int(segment.p_offset), # File Addr
                             int(segment.p_memsz)) # Run end.

            elif segment.p_type == PT_PMEM_METADATA:
                self.LoadMetadata(segment.p_offset)

        self.as_assert(len(self.runs) > 0, "No program headers found")

    def check_file(self):
        """Checks the base file handle for sanity."""

        self.as_assert(self.base,
                       "Must stack on another address space")

        ## Must start with the magic for elf
        self.as_assert((self.base.read(0, 4) == b"\177ELF"),
                       "Header signature invalid")

    def LoadMetadata(self, offset):
        """Load the WinPmem metadata from the elf file."""
        self.session.logging.error(
            "DEPRECATED Elf metadata found! "
            "This will not be supported in the next release.")
        try:
            data = utils.SmartUnicode(self.base.read(offset, 1024*1024))
            yaml_file = data.split('...\n')[0]

            metadata = yaml.safe_load(yaml_file)
        except (yaml.YAMLError, TypeError) as e:
            self.session.logging.error(
                "Invalid file metadata, skipping: %s" % e)
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

        self.session.logging.info(
            "Loading pagefile into physical offset %#08x", vaddr)

        # Map the pagefile into the
        self.add_run(vaddr, pagefile_offset, pagefile_size)

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

    ffff880000000000 - ffffc7ffffffffff (=64 TB) direct mapping of all
    physical memory.

    In recent versions of Ubuntu the CONFIG_RANDOMIZE_MEMORY is
    enabled. This makes the ELF headers randomized and so we need to
    read /proc/iomap to work out the correct mapped range for physical
    memory mapping.
    """
    # We must run before the regular Elf64CoreDump address space in the voting
    # order.
    order = Elf64CoreDump.order - 1

    __name = "elf64"
    __image = True

    def __init__(self, **kwargs):
        super(KCoreAddressSpace, self).__init__(**kwargs)

        # This is a live address space.
        self.volatile = True
        self.mapped_files = {}

        runs = []
        range_start = 0xffff880000000000
        range_end = 0xffffc7ffffffffff
        range_len = range_end - range_start

        io_map_vm = self.get_file_address_space("/proc/iomem")
        if io_map_vm != None:
            io_map_data = utils.SmartUnicode(io_map_vm.read(0, 100000).split(b"\x00")[0])
            io_map = ParseIOMap(io_map_data)

            # Mapping in the ELF program header of the first physical
            # memory range.
            first_run = self.runs[0][2]

            # Mapping in physical memory of the first physical memory
            # range.
            first_system_ram = io_map["System RAM"][0]

            # The random offset added to all physical memory ranges
            # when exported via the ELF header.
            range_start = first_run.start - first_system_ram.start

            # Only add the runs which correspond with the System RAM Io map.
            for start, _, run in self.runs:
                normalized_start = start - range_start
                for ram_run in io_map["System RAM"]:
                    if normalized_start == ram_run.start:
                        runs.append((normalized_start,
                                     run.file_offset, run.length))
                        break
        else:
            for start, _, run in self.runs:
                if range_start < run.start < range_end:
                    runs.append((start - range_start,
                                 run.file_offset, run.length))

        self.as_assert(runs, "No kcore compatible virtual ranges.")
        self.runs.clear()

        # At this point, we think this is a valid, usable kcore file.
        # RHEL, however, disables read access to /proc/kcore past the ELF
        # headers and the file size reflects this. /proc/kcore usually has a
        # size of at least 64TB (46bits of physical address space in x64).
        # We use the file size to detect cases where kcore will be unusable.
        if getattr(self.base, "fhandle", None):
            try:
                size = os.fstat(self.base.fhandle.fileno()).st_size
            except IOError:
                size = 0

            self.as_assert(size > 2**45,
                           "This kcore file is too small (%d bytes) and likely "
                           "invalid for memory analysis. You may want to use pmem "
                           "instead." % size)

        for x in runs:
            self.add_run(*x)

    def get_file_address_space(self, filename):
        try:
            # Try to read the file with OS APIs.
            return standard.FileAddressSpace(filename=filename,
                                             session=self.session)
        except IOError:
            return


class XenElf64CoreDump(addrspace.PagedReader):
    """An Address space to support XEN memory dumps.

    https://xenbits.xen.org/docs/4.8-testing/misc/dump-core-format.txt
    """
    order = 30
    __name = "xenelf64"
    __image = True

    def __init__(self, **kwargs):
        super(XenElf64CoreDump, self).__init__(**kwargs)
        self.check_file()

        self.offset = 0
        self.fname = ''
        self._metadata = {}

        # Now parse the ELF file.
        self.elf_profile = elf.ELFProfile(session=self.session)
        self.elf64_hdr = self.elf_profile.elf64_hdr(vm=self.base, offset=0)
        self.as_assert(self.elf64_hdr.e_type == "ET_CORE",
                       "Elf file is not a core file.")
        xen_note = self.elf64_hdr.section_by_name(".note.Xen")
        self.as_assert(xen_note, "Image does not contain Xen note.")

        self.name = "%s|%s" % (self.__class__.__name__, self.base.name)
        self.runs = self.build_runs()

    def build_runs(self):
        pages = self.elf64_hdr.section_by_name(".xen_pages")
        self.pages_offset = pages.sh_offset.v()

        self.as_assert(pages, "Image does not contain Xen pages.")

        pfn_map = self.elf64_hdr.section_by_name(".xen_pfn")
        self.max_pfn = 0

        # Build a map for all the pages.
        runs = {}
        if pfn_map:
            pfn_map_data = self.base.read(pfn_map.sh_offset,
                                          pfn_map.sh_size)

            # Use struct directly to make this very fast since there are so many
            # entries.
            for i, pfn in enumerate(
                struct.unpack("Q" * (len(pfn_map_data) // 8 ),
                              pfn_map_data)):
                self.session.report_progress(
                    "Adding run %s to PFN %08x", i, pfn)
                runs[pfn] = i
                self.max_pfn = max(self.max_pfn, pfn)

        return runs

    def vtop(self, vaddr):
        try:
            return (self.runs[vaddr // self.PAGE_SIZE] * self.PAGE_SIZE +
                    self.pages_offset + vaddr % self.PAGE_SIZE)
        except KeyError:
            return None

    def check_file(self):
        """Checks the base file handle for sanity."""

        self.as_assert(self.base,
                       "Must stack on another address space")

        ## Must start with the magic for elf
        self.as_assert((self.base.read(0, 4) == b"\177ELF"),
                       "Header signature invalid")

    def get_mappings(self, start=0, end=2**64):
        for run_pfn in sorted(self.runs):
            start = run_pfn * self.PAGE_SIZE
            run = addrspace.Run(start=start,
                                end=start + self.PAGE_SIZE,
                                file_offset=self.vtop(start),
                                address_space=self.base)
            yield run

    def end(self):
        return self.max_pfn


def WriteElfFile(address_space, outfd, session=None):
    """Convert the address_space to an ELF Core dump file.

    The Core dump will be written to outfd which is expected to have a .write()
    method.
    """
    runs = list(address_space.get_mappings())

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
    for run in runs:
        elf64_pheader.p_paddr = run.start
        elf64_pheader.p_memsz = run.length
        elf64_pheader.p_offset = file_offset
        elf64_pheader.p_filesz = run.length

        outfd.write(elf64_pheader.GetData())

        file_offset += run.length

    # Now just copy all the runs
    total_data = 0
    for run in runs:
        offset = run.start
        length = run.length
        while length > 0:
            data = address_space.read(offset, min(10000000, length))
            session.report_progress("Writing %sMb", total_data//1024//1024)
            outfd.write(data)
            length -= len(data)
            offset += len(data)
            total_data += len(data)
