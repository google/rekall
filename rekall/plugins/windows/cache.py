# Rekall Memory Forensics
# Copyright 2014 Google Inc. All Rights Reserved.
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

"""This module adds plugins to inspect the windows cache manager.

The windows cache manager is responsible for maintaining file cache for files
read from disk. The manager maintains a large arena of 256kb cached
blocks. These blocks are controlled using the VACB (Virtual Address Control
Block) arrays.

References:
http://www.codemachine.com/article_kernelstruct.html

"""

__author__ = "Michael Cohen <scudette@google.com>"

from rekall import testlib

from rekall.plugins import core
from rekall.plugins.windows import common


class EnumerateVacbs(common.WindowsCommandPlugin):
    """Enumerate all blocks cached in the cache manager."""
    name = "vacbs"

    def GetVACBs(self):
        """Yield all system VACBs.

        Walks the VACB tables and produce all valid VACBs. This essentially
        produces the entire contents of the cache manager.
        """
        # The Kernel variable CcVacbArrays is a pointer to an array of pointers
        # to the _VACB_ARRAY_HEADER tables. The total number of tables is stored
        # in CcVacbArraysAllocated.
        total_vacb_arrays = self.profile.get_constant_object(
            'CcVacbArraysAllocated', 'unsigned int')

        vacb_arrays = self.profile.get_constant_object(
            'CcVacbArrays',
            target="Pointer",
            target_args=dict(
                target='Array',
                target_args=dict(
                    target="Pointer",
                    target_args=dict(
                        target='_VACB_ARRAY_HEADER'
                    ),
                    count=int(total_vacb_arrays),
                )
            )
        )

        for table in vacb_arrays:
            self.session.report_progress(
                "Scanning VACB table %s", table.VacbArrayIndex)

            for vacb in table.VACBs:
                if vacb.ArrayHead != table:
                    continue

                yield vacb

    def render(self, renderer):
        renderer.table_header([
            ("_VACB", "vacb", "[addrpad]"),
            ("Present", 'valid', '7'),
            ("Base", "base", "[addrpad]"),
            ("Offset", "offset", "[addr]"),
            ("Filename", "filename", ""),
        ])

        for vacb in self.GetVACBs():
            filename = vacb.SharedCacheMap.FileObjectFastRef.FileName
            if filename:
                renderer.table_row(
                    vacb,
                    bool(self.kernel_address_space.vtop(
                        vacb.BaseAddress.v()
                    )),
                    vacb.BaseAddress.v(),

                    vacb.Overlay.FileOffset.QuadPart,
                    filename,
                )


class DumpFiles(core.DirectoryDumperMixin, common.WinProcessFilter):
    """Dump files from memory.

    The interface is loosely based on the Volatility plugin of the same name,
    although the implementation is quite different.
    """
    name = "dumpfiles"

    @classmethod
    def args(cls, parser):
        """Declare the command line args we need."""
        super(DumpFiles, cls).args(parser)

        parser.add_argument(
            "--file_objects",
            type="ArrayIntParser", default=[],
            help="Kernel addresses of _FILE_OBJECT structs.")

    def __init__(self, *args, **kwargs):
        self.file_objects = kwargs.pop("file_objects", [])

        super(DumpFiles, self).__init__(*args, **kwargs)

    def CollectFileObject(self):
        """Collect all known file objects."""
        self.file_objects = set()
        self.vacb_by_cache_map = {}

        # Collect known file objects for selected processes.
        for task in self.filter_processes():
            # First scan the vads.
            self.session.report_progress("Inspecting VAD for %s", task.name)
            for vad in task.RealVadRoot.traverse():
                file_object = vad.m("Subsection").ControlArea.FilePointer
                if file_object:
                    self.file_objects.add(file_object)

            # Now check handles.
            self.session.report_progress("Inspecting Handles for %s", task.name)
            for handle in task.ObjectTable.handles():
                if handle.get_object_type() == "File":
                    self.file_objects.add(handle.Object)

        # Now scan all the objects in the cache manager.
        for vacb in self.session.plugins.vacbs().GetVACBs():
            shared_cache_map = vacb.SharedCacheMap.v()
            if shared_cache_map:
                # Keep a tally of all VACBs for each file_object.
                self.vacb_by_cache_map.setdefault(
                    shared_cache_map, []).append(vacb)

    def _dump_ca(self, ca, out_fd, type, filename, renderer):
        sectors_per_page = 0x1000 / 512

        for subsection in ca.FirstSubsection.walk_list("NextSubsection"):
            for i, pte in enumerate(subsection.SubsectionBase):
                phys_address = self.kernel_address_space.ResolveProtoPTE(
                    pte, 0)

                if phys_address == None:
                    continue

                # The file offset of this page.
                file_sector_offset = (
                    subsection.StartingSector + i * sectors_per_page)

                # Sometimes not the entire page is mapped in.
                file_sectors_mapped_in_page = min(
                    sectors_per_page,
                    subsection.NumberOfFullSectors - i * sectors_per_page)

                if file_sectors_mapped_in_page < 0:
                    continue

                # This should not happen by it does if the data is corrupt.
                if phys_address > self.physical_address_space.end():
                    continue

                renderer.table_row(
                    type, phys_address, file_sector_offset * 512,
                    file_sectors_mapped_in_page * 512, filename)

                # This writes a sparse file.
                out_fd.seek(file_sector_offset * 512)
                out_fd.write(self.physical_address_space.read(
                    phys_address, file_sectors_mapped_in_page * 512))

    def render(self, renderer):
        renderer.table_header([
            ("Type", "type", "20"),
            ("Phys Offset", "POffset", "[addrpad]"),
            ("File Offset", "FOffset", "[addrpad]"),
            ("File Length", "Flength", ">#05x"),
            ("Filename", "filename", "")
            ])

        self.CollectFileObject()
        seen_filenames = set()
        for file_object in self.file_objects:
            filename = unicode(
                file_object.file_name_with_device()).replace("\\", "_")

            if filename in seen_filenames:
                continue

            seen_filenames.add(filename)

            self.session.report_progress(" Dumping %s", filename)
            with renderer.open(directory=self.dump_dir,
                               filename=filename, mode="w") as out_fd:

                filename = out_fd.name

                # Sometimes we get both subsections.
                ca = file_object.SectionObjectPointer.ImageSectionObject
                if ca:
                    self._dump_ca(ca, out_fd, "ImageSectionObject",
                                  filename, renderer)

                ca = file_object.SectionObjectPointer.DataSectionObject
                if ca:
                    self._dump_ca(ca, out_fd, "DataSectionObject",
                                  filename, renderer)

                scm = file_object.SectionObjectPointer.SharedCacheMap.v()

                # Augment the data with the cache manager.
                for vacb in self.vacb_by_cache_map.get(scm, []):
                    base_address = vacb.BaseAddress.v()
                    file_offset = vacb.Overlay.FileOffset.QuadPart.v()

                    # Each VACB controls a 256k buffer.
                    for offset in xrange(0, 0x40000, 0x1000):
                        phys_address = self.kernel_address_space.vtop(
                            base_address + offset)

                        if phys_address:
                            renderer.table_row(
                                "VACB", phys_address, file_offset+offset,
                                0x1000, filename)

                            # This writes a sparse file.
                            out_fd.seek(file_offset + offset)
                            out_fd.write(self.physical_address_space.read(
                                phys_address, 0x1000))


class TestDumpFiles(testlib.HashChecker):
    PARAMETERS = dict(
        commandline="dumpfiles --dump_dir %(tempdir)s"
    )
