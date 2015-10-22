# Rekall Memory Forensics
#
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
"""Enumerate and dump all compressed memory pages on Darwin."""

__author__ = "Andreas Moser <amoser@google.com>"

import os

from rekall.plugins import core
from rekall.plugins.darwin import common
from rekall.plugins.darwin import WKdm


class DarwinDumpCompressedPages(core.DirectoryDumperMixin, common.AbstractDarwinCommand):
    """Dumps all compressed pages."""

    __name = "dumpcompressedmemory"

    SLOT_ARRAY_SIZE = 64
    PAGE_SIZE = 4096

    def UnpackCSize(self, c_slot):

        size = c_slot.c_size
        if size == self.PAGE_SIZE - 1:
            return self.PAGE_SIZE
        else:
            return size

    def render(self, renderer):

        pages = self.profile.get_constant_object("_c_segment_count", "int")

        renderer.format("Going to dump {0} segments.\n", pages)

        p_segu = self.profile.get_constant_object(
            "_c_segments", "Pointer", target_args={
                "target": "Array",
                "target_args": {
                    "target": "c_segu",
                    "count": int(pages),
                }})

        segu_array = p_segu.deref()

        for i, segu in enumerate(segu_array):
            renderer.RenderProgress("Segment: %d" % i)

            c_seg = segu.c_seg

            if (c_seg.c_ondisk or
                    c_seg.c_on_swappedout_q or
                    c_seg.c_on_swappedout_sparse_q):
                # Data swapped out.
                continue

            c_buffer = c_seg.c_store.c_buffer
            if c_buffer == 0:
                # No data in this segment.
                continue

            seg_buffer = c_buffer.obj_vm.read(c_buffer.v(),
                                              c_seg.c_nextoffset * 4)

            c_slot_arrays = []
            for slot in c_seg.c_slots:
                c_slot_arrays.append(
                    slot.dereference_as(
                        target="Array", target_args=dict(target="c_slot")))

            for slot_nr in xrange(c_seg.c_nextslot):
                c_slot_array = c_slot_arrays[slot_nr / self.SLOT_ARRAY_SIZE]
                c_slot = c_slot_array[slot_nr % self.SLOT_ARRAY_SIZE]

                if not (c_slot.c_offset and c_slot.c_size):
                    continue

                c_size = self.UnpackCSize(c_slot)

                # This should never happen.
                if c_slot.c_offset * 4 + c_size >= len(seg_buffer):
                    continue

                data = seg_buffer[c_slot.c_offset * 4:
                                  c_slot.c_offset * 4 + c_size]

                offset_alignment_mask = 0x3

                c_rounded_size = (c_size + offset_alignment_mask)
                c_rounded_size &= ~offset_alignment_mask

                if (c_rounded_size == self.PAGE_SIZE):
                    # Page was not compressible.
                    # Copy anyways?

                    # with renderer.open(
                    #         directory=self.dump_dir,
                    #         filename="seg%d_slot%d.dat" % (i, slot_nr),
                    #         mode="wb") as fd:
                    #     fd.write(data)
                    continue

                try:
                    decompressed = WKdm.WKdm_decompress_apple(data)
                    if decompressed:
                        dirname = os.path.join(self.dump_dir, "segment%d" % i)
                        try:
                            os.mkdir(dirname)
                        except OSError:
                            pass

                        with renderer.open(
                                directory=dirname,
                                filename="slot%d.dmp" % slot_nr,
                                mode="wb") as fd:
                            fd.write(decompressed)

                except Exception as e:
                    renderer.report_error(str(e))
