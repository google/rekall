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
from rekall import scan
from rekall import utils

from rekall.plugins import core
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

    def enumerate_heap_allocations(self, task):
        """Enumerate all allocations for _EPROCESS instance."""
        cc = self.session.plugins.cc()
        with cc:
            cc.SwitchProcessContext(task)
            resolver = self.session.address_resolver
            ntdll_prof = resolver.LoadProfileForName("ntdll")
            if not ntdll_prof:
                return

            # Set the ntdll profile on the _PEB member.
            peb = task.m("Peb").cast(
                "Pointer", target="_PEB", profile=ntdll_prof,
                vm=task.get_process_address_space())

            for heap in peb.ProcessHeaps:
                if self.heaps and heap.ProcessHeapsListIndex not in self.heaps:
                    continue

                # First dump the backend allocations.
                for seg in heap.Segments:
                    for entry in seg.FirstEntry.walk_list("NextEntry", True):
                        yield entry.Allocation

                # Now do the low fragmentation heap.
                for segment_info in heap.FrontEndHeap.LocalData[0].m("SegmentInfo"):
                    active_segment = segment_info.ActiveSubsegment
                    if active_segment:
                        allocation_length = active_segment.BlockSize * 16

                        for entry in active_segment.UserBlocks.Entries:
                            UnusedBytes = entry.UnusedBytes & 0x3f - 0x8
                            data_len = allocation_length - UnusedBytes

                            if data_len > allocation_length - 0x8:
                                data_len -= 0x8

                            yield heap.obj_profile.String(
                                entry.obj_end, term=None, length=data_len)

    def GenerateHeaps(self):
        task = self.session.GetParameter("process_context")
        resolver = self.session.address_resolver

        # Try to load the ntdll profile.
        ntdll_prof = resolver.LoadProfileForName("ntdll")
        if not ntdll_prof:
            return

        # Set the ntdll profile on the _PEB member.
        peb = task.m("Peb").cast(
            "Pointer", target="_PEB", profile=ntdll_prof,
            vm=task.get_process_address_space())

        for heap in peb.ProcessHeaps:
            yield heap

    def render(self, renderer):
        cc = self.session.plugins.cc()
        with cc:
            for task in self.filter_processes():
                cc.SwitchProcessContext(task)

                renderer.section()
                renderer.format("{0:r}\n", task)
                for heap in self.GenerateHeaps():
                    self.render_process_heap_info(heap, renderer)

    def render_low_frag_info(self, heap, renderer):
        """Displays information about the low fragmentation front end."""
        renderer.format("Low Fragmentation Front End Information:\n")
        renderer.table_header([
            dict(name="Entry", style="address"),
            ("Alloc", "allocation_length", "4"),
            ("Length", "length", ">4"),
            dict(name="Data", style="hexdump"),
        ])

        for segment_info in heap.FrontEndHeap.LocalData[0].m("SegmentInfo"):
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

    def render_process_heap_info(self, heap, renderer):
        if self.heaps and heap.ProcessHeapsListIndex not in self.heaps:
            return

        if 1 <= heap.ProcessHeapsListIndex <= 64:
            renderer.format("Heap {0}: {1:#x} ({2})\nBackend Info:\n\n",
                            heap.ProcessHeapsListIndex,
                            heap.BaseAddress,
                            heap.FrontEndHeapType)

            renderer.table_header([
                dict(name="Segment", type="TreeNode", width=18,
                     child=dict(style="address")),
                ("End", "segment_end", "[addr]"),
                ("Length", "length", "8"),
                dict(name="Data", style="hexdump"),
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


class ShowAllocation(common.WindowsCommandPlugin):
    """Show the allocation containing the address."""

    name = "show_allocation"

    @classmethod
    def args(cls, parser):
        super(ShowAllocation, cls).args(parser)
        parser.add_argument(
            "address", type="ArrayIntParser",
            help="The address to display")

        parser.add_argument(
            "--preamble", type="IntParser", default=32,
            help="How many bytes prior to the address to display.")

    def __init__(self, addresses=None, preamble=32, **kwargs):
        super(ShowAllocation, self).__init__(**kwargs)
        if isinstance(addresses, int):
            addresses = [addresses]

        self.addresses = addresses
        self.offset = None
        self.preamble = preamble
        self.allocations = getattr(
            self.session.address_resolver, "heap_allocations", None)

        if self.allocations is None:
            allocations = utils.RangedCollection()
            inspect_heap = self.session.plugins.inspect_heap()
            for allocation in inspect_heap.enumerate_heap_allocations(
                    self.session.GetParameter("process_context")):

                # Include the header in the allocation.
                allocations.insert(
                    allocation.obj_offset - 16,
                    allocation.obj_offset + allocation.length + 16,
                    (allocation.obj_offset, allocation.length))

                self.session.address_resolver.heap_allocations = allocations
                self.allocations = allocations
                self.session.report_progress(
                    "Enumerating alllocation: %#x",
                    lambda: allocation.obj_offset)

    def GetAllocationForAddress(self, address):
        return self.allocations.get_range(address)

    def CreateAllocationMap(self, start, length):
        address_map = core.AddressMap()
        allocation = self.allocations.get_range(start)
        if allocation:
            address_map.AddRange(start, start + 16, "_HEAP_ENTRY")

        count = length / 8
        for pointer in self.profile.Array(
                offset=start, count=count, target="Pointer"):
            name = None
            allocation = self.allocations.get_range(pointer.v())
            if allocation:
                alloc_start, alloc_length = allocation

                # First check if the pointer points inside this allocation.
                if alloc_start == start + 16:
                    name = "+%#x(%#x)" % (pointer.v() - start, pointer.v())
                else:
                    name = "%#x(%s@%#x)" % (
                        pointer.v(), alloc_length, alloc_start)

            else:
                # Maybe it is a resolvable address.
                name = self.session.address_resolver.format_address(
                    pointer.v(), max_distance=1024*1024)


            if name:
                address_map.AddRange(
                    pointer.obj_offset, pointer.obj_offset + 8,
                    "%s" % name)

        return address_map

    def render(self, renderer):
        for address in self.addresses:
            allocation = self.allocations.get_range(address)
            if not allocation:
                renderer.format("Allocation not found for address "
                                "{0:style=address} in any heap.\n", address)
                start = address
                length = 50 * 16

            else:
                start, length = allocation

                renderer.format(
                    "Address {0:style=address} is {1} bytes into "
                    "allocation of size {2} "
                    "({3:style=address} - {4:style=address})\n",
                    address, address - start,
                    length, start, start + length)

            # Also show the _HEAP_ENTRY before the allocation.
            start -= 16
            length += 16

            # Start dumping preamble before the address if self.offset is not
            # specified. It will be specified when we run the plugin again using
            # v().
            if self.offset is None:
                self.offset = max(0, address - start - self.preamble)

            dump = self.session.plugins.dump(
                offset=start + self.offset, length=length - self.offset,
                address_map=self.CreateAllocationMap(start, length))

            dump.render(renderer)

            self.offset = dump.offset - start


class FindReferenceAlloc(common.WindowsCommandPlugin):
    """Show allocations that refer to an address."""

    name = "show_referrer_alloc"

    @classmethod
    def args(cls, parser):
        super(FindReferenceAlloc, cls).args(parser)
        parser.add_argument(
            "address", type="IntParser",
            help="The address to display")

    def __init__(self, address=None, **kwargs):
        super(FindReferenceAlloc, self).__init__(**kwargs)
        self.address = address

    def get_referrers(self, address):
        addr = self.profile.address()
        addr.write(address)

        pointer_scanner = scan.BaseScanner(
            address_space=self.session.GetParameter("default_address_space"),
            session=self.session,
            checks=[
                ('StringCheck', dict(needle=addr.obj_vm.getvalue()))
            ])

        inspect_heap = self.session.plugins.inspect_heap()
        for heap in inspect_heap.GenerateHeaps():
            for seg in heap.Segments:
                seg_start = seg.FirstEntry.obj_offset
                seg_end = seg.LastValidEntry.v()
                length = min(seg_end - seg_start, 1024*1024*10)

                for hit in pointer_scanner.scan(
                        seg_start, maxlen=length):
                    yield hit

    def render(self, renderer):
        show_allocation = None

        for hit in self.get_referrers(self.address):
            show_allocation = self.session.plugins.show_allocation(hit)
            show_allocation.render(renderer)

        return show_allocation
