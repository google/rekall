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

    __args = [
        dict(name="free", type="Boolean",
             help="Also show freed chunks."),

        dict(name="heaps", type="ArrayIntParser",
             help="Only show these heaps (default show all)")
    ]

    mode = "mode_amd64"

    def __init__(self, *args, **kwargs):
        super(InspectHeap, self).__init__(*args, **kwargs)
        self.segments = utils.SortedCollection()

    def enumerate_lfh_heap_allocations(self, heap, skip_freed=False):
        """Dump the low fragmentation heap."""
        seen_blocks = set()

        for lfh_block in heap.FrontEndHeap.SubSegmentZones.list_of_type(
                "_LFH_BLOCK_ZONE", "ListEntry"):
            block_length = lfh_block.FreePointer.v() - lfh_block.obj_end
            segments = heap.obj_profile.Array(
                target="_HEAP_SUBSEGMENT",
                offset=lfh_block.obj_end,
                size=block_length)

            for segment in segments:
                allocation_length = segment.BlockSize * 16

                if segment.UserBlocks.v() in seen_blocks:
                    break

                seen_blocks.add(segment.UserBlocks.v())

                for entry in segment.UserBlocks.Entries:
                    # http://www.leviathansecurity.com/blog/understanding-the-windows-allocator-a-redux/
                    # Skip freed blocks if requested.
                    if skip_freed and entry.UnusedBytes & 0x38:
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

                    yield (heap.obj_profile.String(entry.obj_end, term=None,
                                                   length=data_len),
                           allocation_length)

    def enumerate_backend_heap_allocations(self, heap):
        """Enumerate all allocations for _EPROCESS instance."""

        for seg in heap.Segments:
            seg_end = seg.LastValidEntry.v()

            # Ensure sanity.
            if seg.Heap.deref() != heap:
                continue

            # The segment is empty - often seg_end is zero here.
            if seg_end < seg.FirstEntry.v():
                break

            for entry in seg.FirstEntry.walk_list("NextEntry", True):
                # If this is the last entry it goes until the end of the
                # segment.
                start = entry.obj_offset + 0x10
                if start > seg_end:
                    break

                allocation = entry.Allocation
                yield allocation

    def GenerateHeaps(self):
        task = self.session.GetParameter("process_context")
        resolver = self.session.address_resolver

        # Try to load the ntdll profile.
        ntdll_mod = resolver.GetModuleByName("ntdll")
        if not ntdll_mod:
            return

        ntdll_prof = ntdll_mod.profile

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
            dict(name="Data"),
        ])

        # Render the LFH allocations in increasing allocation sizes. Collect
        # them first, then display by sorted allocation size, and offset.
        entries_by_size = {}
        for entry, allocation_length in self.enumerate_lfh_heap_allocations(
                heap):
            entries_by_size.setdefault(allocation_length, []).append(entry)

        for allocation_length, entries in sorted(entries_by_size.iteritems()):
            for entry in sorted(entries, key=lambda x: x.obj_offset):
                data = entry.v()[:64]

                renderer.table_row(
                    entry,
                    allocation_length,
                    entry.length,
                    utils.HexDumpedString(data),
                    )

    def render_process_heap_info(self, heap, renderer):
        if (self.plugin_args.heaps and
            heap.ProcessHeapsListIndex not in self.plugin_args.heaps):
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
                dict(name="Data"),
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
                        utils.HexDumpedString(data),
                        depth=2)


            if heap.FrontEndHeapType.LOW_FRAG:
                self.render_low_frag_info(heap, renderer)


class ShowAllocation(common.WindowsCommandPlugin):
    """Show the allocation containing the address."""

    name = "show_allocation"

    __args = [
        dict(name="address", type="ArrayIntParser", positional=True,
             help="The address to display"),

        dict(name="preamble", type="IntParser", default=32,
             help="How many bytes prior to the address to display."),

        dict(name="length", type="IntParser", default=50 * 16,
             help="How many bytes after the address to display.")
    ]

    def BuildAllocationMap(self):
        """Build a map of all allocations for fast looksup."""
        allocations = utils.RangedCollection()
        inspect_heap = self.session.plugins.inspect_heap()
        for heap in inspect_heap.GenerateHeaps():
            # First do the backend allocations.
            for allocation in inspect_heap.enumerate_backend_heap_allocations(
                    heap):

                # Include the header in the allocation.
                allocations.insert(
                    allocation.obj_offset - 16,
                    allocation.obj_offset + allocation.length + 16,
                    (allocation.obj_offset, allocation.length, "B"))

                self.session.report_progress(
                    "Enumerating backend allocation: %#x",
                    lambda allocation=allocation: allocation.obj_offset)

            # Now do the LFH allocations (These will mask the subsegments in the
            # RangedCollection).
            for _ in inspect_heap.enumerate_lfh_heap_allocations(
                    heap, skip_freed=False):
                allocation, allocation_length = _
                self.session.report_progress(
                    "Enumerating frontend allocation: %#x",
                    lambda: allocation.obj_offset)

                # Front end allocations do not have their own headers.
                allocations.insert(
                    allocation.obj_offset,
                    allocation.obj_offset + allocation_length,
                    (allocation.obj_offset, allocation_length, "F"))

        return allocations

    def __init__(self, *args, **kwargs):
        super(ShowAllocation, self).__init__(*args, **kwargs)
        self.offset = None

        # Get cached allocations for current process context.
        task = self.session.GetParameter("process_context")
        cache_key = "heap_allocations_%x" % task.obj_offset
        self.allocations = self.session.GetParameter(cache_key)
        if self.allocations == None:
            self.allocations = self.BuildAllocationMap()

            # Cache the allocations for next time.
            self.session.SetCache(cache_key, self.allocations)

    def GetAllocationForAddress(self, address):
        return self.allocations.get_containing_range(address)

    def CreateAllocationMap(self, start, length, alloc_start, alloc_type):
        address_map = core.AddressMap()
        # For backend allocs we highlight the heap entry before them.
        if alloc_type == "B":
            address_map.AddRange(alloc_start-16, alloc_start, "_HEAP_ENTRY")

        # Try to interpret pointers to other allocations and highlight them.
        count = length / 8
        for pointer in self.profile.Array(
                offset=start, count=count, target="Pointer"):
            name = None
            alloc_start, alloc_length, alloc_type = (
                self.allocations.get_containing_range(pointer.v()))

            if alloc_type is not None:
                # First check if the pointer points inside this allocation.
                if alloc_start == start + 16:
                    name = "+%#x(%#x)" % (pointer.v() - start, pointer.v())
                else:
                    name = "%#x(%s@%#x)" % (
                        pointer.v(), alloc_length, alloc_start)

            else:
                # Maybe it is a resolvable address.
                name = ",".join(self.session.address_resolver.format_address(
                    pointer.v(), max_distance=1024*1024))


            if name:
                address_map.AddRange(
                    pointer.obj_offset, pointer.obj_offset + 8,
                    # Color it using a unique color related to the address. This
                    # helps to visually relate the same address across different
                    # dumps.
                    "%s" % name, color_index=pointer.obj_offset)

        return address_map

    def render(self, renderer):
        for address in self.plugin_args.address:
            # If the user requested to view more than one address we do not
            # support plugin continuation (with v() plugin).
            if len(self.plugin_args.address) > 1:
                self.offset = None

            alloc_start, alloc_length, alloc_type = (
                self.allocations.get_containing_range(address))

            if not alloc_type:
                renderer.format("Allocation not found for address "
                                "{0:style=address} in any heap.\n", address)
                alloc_start = address
                alloc_length = 50 * 16
                alloc_type = None

            else:
                renderer.format(
                    "Address {0:style=address} is {1} bytes into "
                    "{2} allocation of size {3} "
                    "({4:style=address} - {5:style=address})\n",
                    address, address - alloc_start, alloc_type,
                    alloc_length, alloc_start, alloc_start + alloc_length)

            # Start dumping preamble before the address if self.offset is not
            # specified. It will be specified when we run the plugin again using
            # v().
            if self.offset is None:
                # Start dumping a little before the requested address, but do
                # not go before the start of the allocation.
                start = max(alloc_start, address - self.plugin_args.preamble)
            else:
                # Continue dumping from the last run.
                start = self.offset

            # Also show the _HEAP_ENTRY before backend allocations (Front end
            # allocations do not have a _HEAP_ENTRY).
            if alloc_type == "B":
                start -= 16

            length = min(alloc_start + alloc_length - start,
                         self.plugin_args.length)

            dump = self.session.plugins.dump(
                offset=start, length=length,
                address_map=self.CreateAllocationMap(
                    start, length, alloc_start, alloc_type))

            dump.render(renderer)

            self.offset = dump.offset


class FindReferenceAlloc(common.WindowsCommandPlugin):
    """Show allocations that refer to an address."""

    name = "show_referrer_alloc"

    __args = [
        dict(name="address", type="IntParser", positional=True, required=True,
             help="The address to display")
    ]

    def get_referrers(self, address, maxlen=None):
        addr = self.profile.address()
        addr.write(address)

        pointer_scanner = scan.BaseScanner(
            address_space=self.session.GetParameter("default_address_space"),
            session=self.session,
            checks=[
                ('StringCheck', dict(needle=addr.obj_vm.getvalue()))
            ])

        # Just scan the entire userspace address space. This means we might find
        # hits outside the heap but this is usually useful as it would locate
        # static pointers in dlls.
        if maxlen is None:
            maxlen = self.session.GetParameter("highest_usermode_address")

        for hit in pointer_scanner.scan(maxlen=maxlen):
            yield hit

    def render(self, renderer):
        show_allocation = None

        for hit in self.get_referrers(self.address):
            show_allocation = self.session.plugins.show_allocation(hit)
            show_allocation.render(renderer)

        return show_allocation
