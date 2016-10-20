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
from rekall import obj
from rekall import utils
from rekall import testlib

from rekall.plugins import core
from rekall.plugins.windows import common


class EnumerateVacbs(common.WindowsCommandPlugin):
    """Enumerate all blocks cached in the cache manager."""
    name = "vacbs"

    def GetVACBs_Win7(self):
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

    def GetVACBs_WinXP(self):
        """Yield all system VACBs for older Windows XP based kernels.

        Walks the VACB tables and produce all valid VACBs. This essentially
        produces the entire contents of the cache manager.
        """
        # The Kernel variable CcVacbArrays is a pointer to an array of pointers
        # to the _VACB_ARRAY_HEADER tables. The total number of tables is stored
        # in CcVacbArraysAllocated.
        total_vacb_arrays = self.profile.get_constant_object(
            'CcNumberVacbs', 'unsigned int')

        vacb_array = self.profile.get_constant_object(
            'CcVacbs',
            target="Pointer",
            target_args=dict(
                target='Array',
                target_args=dict(
                    target="_VACB",
                    count=int(total_vacb_arrays),
                )
            )
        )

        for vacb in vacb_array:
            yield vacb

    def GetVACBs(self):
        # Support the old XP way.
        if self.session.profile.get_constant("CcVacbs"):
            return self.GetVACBs_WinXP()

        return self.GetVACBs_Win7()

    table_header = [
        dict(name="_VACB", style="address"),
        dict(name='valid', width=7),
        dict(name="base", style="address"),
        dict(name="offset", style="address"),
        dict(name="filename"),
    ]

    def column_types(self):
        return dict(_VACB=self.session.profile._VACB(),
                    valid=True,
                    base=0,
                    offset=0,
                    filename="")

    def collect(self):
        for vacb in self.GetVACBs():
            filename = vacb.SharedCacheMap.FileObject.file_name_with_drive()
            if filename:
                yield (vacb,
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

    __args = [
        dict(name="file_objects", type="ArrayIntParser",
             help="Kernel addresses of _FILE_OBJECT structs.")
    ]

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
                pte_value = pte.u.Long.v()
                try:
                    phys_address = self.kernel_address_space.ResolveProtoPTE(
                        pte_value, 0)
                except AttributeError:
                    # For address spaces which do not support prototype
                    # (currently non PAE 32 bits) just support the absolute
                    # basic - valid PTE only.
                    if pte & 1:
                        phys_address = pte_value & 0xffffffffff000
                    else:
                        continue

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

                # This should not happen but it does if the data is corrupt.
                if phys_address > self.physical_address_space.end():
                    continue

                renderer.table_row(
                    type, phys_address, file_sector_offset * 512,
                    file_sectors_mapped_in_page * 512, filename)

                # This writes a sparse file.
                out_fd.seek(file_sector_offset * 512)
                out_fd.write(self.physical_address_space.read(
                    phys_address, file_sectors_mapped_in_page * 512))

    table_header = [
        dict(name="type", width=20),
        dict(name="p_offset", style="address"),
        dict(name="f_offset", style="address"),
        dict(name="f_length", style="address"),
        dict(name="filename")
    ]

    def column_types(self):
        return dict(type="VACB", p_offset=0, f_offset=0,
                    f_length=0x1000, filename="")

    def collect(self):
        renderer = self.session.GetRenderer()
        if not self.plugin_args.file_objects:
            self.CollectFileObject()
        else:
            self.file_objects = set(
                [self.session.profile._FILE_OBJECT(int(x))
                 for x in self.plugin_args.file_objects])

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
                    for offset in utils.xrange(0, 0x40000, 0x1000):
                        phys_address = self.kernel_address_space.vtop(
                            base_address + offset)

                        if phys_address:
                            yield dict(type="VACB",
                                       p_offset=phys_address,
                                       f_offset=file_offset+offset,
                                       f_length=0x1000,
                                       filename=filename)

                            # This writes a sparse file.
                            out_fd.seek(file_offset + offset)
                            out_fd.write(self.physical_address_space.read(
                                phys_address, 0x1000))


class TestDumpFiles(testlib.HashChecker):
    PARAMETERS = dict(
        commandline="dumpfiles --dump_dir %(tempdir)s"
    )


class SparseArray(dict):
    def __getitem__(self, key):
        return self.get(key, obj.NoneObject())


class MftDump(common.WindowsCommandPlugin):
    """Enumerate MFT entries from the cache manager."""
    name = "mftdump"

    def __init__(self, *args, **kwargs):
        super(MftDump, self).__init__(*args, **kwargs)
        self.ntfs_profile = self.session.LoadProfile("ntfs")
        self.mft_size = 0x400
        self.vacb_size = 0x40000
        # A sparse MFT table - basically a map between mft id and MFT entry.
        self.mfts = SparseArray()

        # A directory tree. For each MFT id a dict of its direct children.
        self.dir_tree = {2: {}}

    def extract_mft_entries_from_vacb(self, vacb):
        base = vacb.BaseAddress.v()
        for offset in utils.xrange(base, base + self.vacb_size, self.mft_size):
            # Fixups are not applied in memory.
            mft = self.ntfs_profile.MFT_ENTRY(
                offset, context=dict(mft=self.mfts, ApplyFixup=False))
            if mft.magic != "FILE":
                continue

            mft_id = mft.mft_entry
            self.mfts[mft_id] = mft
            self.session.report_progress(
                "Added: %s", lambda mft=mft: mft.filename.name)

            parent_id = mft.filename.mftReference.v()
            if parent_id not in self.dir_tree:
                self.dir_tree[parent_id] = set()

            self.dir_tree[parent_id].add(mft_id)

    def collect_tree(self, root, seen, depth=0):
        if root not in self.mfts or root in seen:
            return

        mft = self.mfts[root]
        standard_info = mft.get_attribute(
            "$STANDARD_INFORMATION").DecodeAttribute()

        yield dict(MFT=root,
                   mft_entry=mft,
                   file_modified=standard_info.file_altered_time,
                   mft_modified=standard_info.mft_altered_time,
                   access=standard_info.file_accessed_time,
                   create_time=standard_info.create_time,
                   Name=self.mfts[root].filename.name,
                   depth=depth)
        seen.add(root)

        for child in sorted(self.dir_tree.get(root, [])):
            if child not in seen:
                for x in self.collect_tree(child, seen, depth=depth+1):
                    yield x

    table_header = [
        dict(name="MFT", width=5, align="r"),
        dict(name="mft_entry", hidden=True),
        dict(name="file_modified", width=25),
        dict(name="mft_modified", width=25),
        dict(name="access", width=25),
        dict(name="create_time", width=25),
        dict(name="Name", type="TreeNode", max_depth=15, width=100),
    ]

    def column_types(self):
        wft = self.session.profile.WinFileTime()
        return dict(MFT=int,
                    mft_entry=self.ntfs_profile.MFT_ENTRY(),
                    file_modified=wft,
                    mft_modified=wft,
                    access=wft,
                    create_time=wft,
                    Name=self.session.profile.UnicodeString())

    def collect(self):
        for vacb in self.session.plugins.vacbs().GetVACBs():
            filename = vacb.SharedCacheMap.FileObject.FileName
            if filename == r"\$Mft":
                self.extract_mft_entries_from_vacb(vacb)

        # Avoid loops.
        seen = set()
        for mft_id in self.dir_tree:
            for x in self.collect_tree(mft_id, seen, depth=0):
                yield x


class TestMftDump(testlib.SortedComparison):
    """The order is someone non-deterministic."""
