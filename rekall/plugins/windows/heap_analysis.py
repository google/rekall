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

"""The module implements user mode heap analysis.

Recent versions of windows use the Low Fragmentation Heap (LFH).

http://illmatics.com/Windows%208%20Heap%20Internals.pdf
http://illmatics.com/Understanding_the_LFH.pdf
http://www.leviathansecurity.com/blog/understanding-the-windows-allocator-a-redux/

"""
from rekall import utils

from rekall.plugins.windows import common


class InspectHeap(common.WinProcessFilter):
    """Inspect the process heap.

    This prints a lot of interesting facts about the process heap. It is also
    the foundation to many other plugins which find things in the process heaps.

    NOTE: Currently we only support Windows 7 64 bit.
    """

    name = "inspect_heap"

    @classmethod
    def args(cls, parser):
        super(InspectHeap, cls).args(parser)
        parser.add_argument("--free", type="Boolean", default=False,
                            help="Also show freed chunks.")

        parser.add_argument("--heaps", type="ArrayIntParser", default=None,
                            help="Only show these heaps (default show all)")

    @classmethod
    def is_active(cls, session):
        return (super(InspectHeap, cls).is_active(session) and
                session.profile.metadata("arch") == 'AMD64')

    def __init__(self, *args, **kwargs):
        self.heaps = kwargs.pop("heaps", None)
        self.free = kwargs.pop("free", False)
        super(InspectHeap, self).__init__(*args, **kwargs)

        self.segments = utils.SortedCollection()

    def render(self, renderer):
        ntdll_prof = None

        cc = self.session.plugins.cc()
        with cc:
            for task in self.filter_processes():
                cc.SwitchProcessContext(task)

                resolver = self.session.address_resolver
                # Try to load the ntdll profile.
                if ntdll_prof == None:
                    ntdll_prof = resolver.LoadProfileForName("ntdll")
                    if not ntdll_prof:
                        continue

                # Set the ntdll profile on the _PEB member.
                peb = task.m("Peb").cast(
                    "Pointer", target="_PEB", profile=ntdll_prof,
                    vm=task.get_process_address_space())

                renderer.section()
                renderer.format("{0:r}\n", task)
                self.render_process_heap_info(peb, renderer)

    def render_low_frag_info(self, heap, renderer):
        """Displays information about the low fragmentation front end."""
        renderer.format("Low Fragmentation Front End Information:\n")
        renderer.table_header([
            dict(name="Entry", style="address"),
            ("Alloc", "allocation_length", "6"),
            ("Length", "length", ">6"),
            dict(name="Data", style="hexdump", hex_width=16),
        ])

        for segment_info in heap.FrontEndHeap.LocalData[0].SegmentInfo:
            active_segment = segment_info.ActiveSubsegment
            if active_segment:
                # Size of bucket including header.
                allocation_length = active_segment.BlockSize * 16

                for entry in active_segment.UserBlocks.Entries:
                    # http://www.leviathansecurity.com/blog/understanding-the-windows-allocator-a-redux/
                    # Skip freed blocks if requested.
                    if not self.free and not entry.UnusedBytes & 0x38:
                        continue

                    UnusedBytes = entry.UnusedBytes & 0x3f - 0x8

                    # The actual length of user allocation is the difference
                    # between the HEAP allocation bin size and the unused bytes
                    # at the end of the allocation.
                    data_len = allocation_length - UnusedBytes

                    # The data length can not be larger than the allocation
                    # minus the critical parts of _HEAP_ENTRY. Sometimes,
                    # allocations overrun into the next element's _HEAP_ENTRY so
                    # they can store data in the next entry's
                    # entry.PreviousBlockPrivateData. In this case the
                    # allocation length seems to be larger by 8 bytes.
                    if data_len > allocation_length - 0x8:
                        data_len -= 0x8

                    data_len = min(data_len, 64)

                    data = heap.obj_vm.read(entry.obj_end, data_len)

                    renderer.table_row(
                        entry,
                        allocation_length,
                        data_len,
                        data,
                    )

    def render_process_heap_info(self, peb, renderer):
        for heap in peb.ProcessHeaps:
            if self.heaps and heap.ProcessHeapsListIndex not in self.heaps:
                continue

            if 1 <= heap.ProcessHeapsListIndex <= 64:
                renderer.format("Heap {0}: {1:#x} ({2})\nBackend Info:\n\n",
                                heap.ProcessHeapsListIndex,
                                heap.BaseAddress,
                                heap.FrontEndHeapType)

                renderer.table_header([
                    dict(name="Segment", type="TreeNode", width=15,
                         child=dict(style="address")),
                    ("End", "segment_end", "[addr]"),
                    ("Length", "length", "10"),
                    dict(name="Data", style="hexdump", hex_width=16),
                ])

                for seg in heap.Segments:
                    seg_start = seg.FirstEntry.obj_offset
                    seg_end = seg.LastValidEntry.v()

                    renderer.table_row(
                        seg_start, seg_end, seg_end - seg_start, depth=1)

                    for entry in seg.FirstEntry.walk_list("NextEntry", True):
                        # If this is the last entry it goes until the end of the
                        # segment.
                        start = entry.obj_offset + 0x10
                        if start > seg_end:
                            break

                        if entry.Flags.LAST_ENTRY:
                            end = seg.LastValidEntry.v()
                        else:
                            end = entry.obj_offset + entry.Size * 16

                        data = heap.obj_vm.read(start, min(16, end-start))

                        renderer.table_row(
                            entry,
                            end, end - start,
                            data,
                            depth=2)


                if heap.FrontEndHeapType.LOW_FRAG:
                    self.render_low_frag_info(heap, renderer)
