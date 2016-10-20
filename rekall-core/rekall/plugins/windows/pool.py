# Rekall Memory Forensics
#
# Copyright 2016 Google Inc. All Rights Reserved.
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
"""Plugins to inspect the windows pools."""

__author__ = "Michael Cohen <scudette@google.com>"

# pylint: disable=protected-access

from rekall import obj
from rekall import utils
from rekall.plugins.windows import common


# Some pool related utility functions.
def find_pool_alloc_before(session, offset, pool_tag):
    """Searches address_space for a pool allocation containing offset."""
    # This method is only effective for small allocations right now because we
    # need to find a pool tag (so allocation size is limited to one page).
    # TODO: Extend this to big page pools.
    base_offset = offset & ~0xFFF
    data = session.kernel_address_space.read(base_offset, offset & 0xFFF)
    buffer_offset = offset % 0x1000
    pool_header_prototype = session.profile._POOL_HEADER()

    while 1:
        buffer_offset = data.rfind(pool_tag, 0, buffer_offset)
        if buffer_offset == -1:
            break

        result = session.profile._POOL_HEADER(
            (base_offset + buffer_offset -
             pool_header_prototype.PoolTag.obj_offset),
            vm=session.kernel_address_space)

        end_of_allocation = result.obj_offset + result.size

        # Allocation encompasses the required offset.
        if end_of_allocation > offset:
            yield result.obj_end

    # After searching in small allocation, assume this is an allocation from
    # Big Pool and go back several pages.
    while base_offset > offset - 0x10000:
        yield base_offset
        base_offset -= 0x1000


class Pools(common.WindowsCommandPlugin):
    """Prints information about system pools.

    Ref:
    http://illmatics.com/Windows%208%20Heap%20Internals.pdf
    https://media.blackhat.com/bh-dc-11/Mandt/BlackHat_DC_2011_Mandt_kernelpool-wp.pdf
    https://immunityinc.com/infiltrate/archives/kernelpool_infiltrate2011.pdf
    http://gate.upm.ro/os/LABs/Windows_OS_Internals_Curriculum_Resource_Kit-ACADEMIC/WindowsResearchKernel-WRK/WRK-v1.2/base/ntos/ex/pool.c
    """

    name = "pools"

    _pool_lookup = None

    table_header = [
        dict(name="descriptor", width=20, style="address"),
        dict(name="type", width=20),
        dict(name="index", width=5),
        dict(name="size", width=10, align="r"),
        dict(name="start", style="address"),
        dict(name="end", style="address"),
        dict(name="comment")
    ]

    def find_non_paged_pool(self):
        vector_pool = self.profile.get_constant_object(
            "PoolVector",
            target="Array",
            target_args=dict(
                count=2,
                target="Pointer",
                )
            )

        resolver = self.session.address_resolver

        for desc in vector_pool[0].dereference_as(
                "Array",
                target_args=dict(
                    count=self.profile.get_constant_object(
                        "ExpNumberOfNonPagedPools", "unsigned int").v(),
                    target="_POOL_DESCRIPTOR",
                    )
            ):
            # Windows XP uses these globals.
            start_va = resolver.get_constant_object(
                "nt!MmNonPagedPoolStart", "Pointer").v()

            end_va = resolver.get_constant_object(
                "nt!MmNonPagedPoolEnd", "Pointer").v()


            # Windows 7.
            if start_va == None:
                # First determine the addresses of non paged pool:
                # dis 'nt!MiReturnNonPagedPoolVa'
                start_va = resolver.get_constant_object(
                    "nt!MiNonPagedPoolStartAligned", "Pointer").v()

                end_va = resolver.get_constant_object(
                    "nt!MiNonPagedPoolEnd", "Pointer").v()

            if end_va == None:
                bitmap = resolver.get_constant_object(
                    "nt!MiNonPagedPoolBitMap", "_RTL_BITMAP")
                # ? MiNonPagedPoolVaBitMap
                # We dont bother to check the bitmap itself, just consider the
                # maximum size of the pool as the maximum allocated bitmap
                # currently. This will overestimate the actual size somewhat.
                end_va = start_va + bitmap.SizeOfBitMap * 8 * 0x1000

            # In windows 10 the start va moved to the MiState global.
            if start_va == None:
                mistate = resolver.get_constant_object(
                    "nt!MiState", "_MI_SYSTEM_INFORMATION")

                for node_index, node_info in enumerate(mistate.multi_m(
                        "Hardware.SystemNodeInformation", # Win10 2016
                        "SystemNodeInformation"  # Win10 2015
                )):
                    start_va = node_info.NonPagedPoolFirstVa.v()
                    end_va = start_va
                    # Just go to the last bitmap
                    for bitmap in node_info.NonPagedBitMap:
                        end_va = max(end_va, start_va + bitmap.SizeOfBitMap * 8)

                    desc.PoolStart = start_va
                    desc.PoolEnd = end_va
                    desc.Comment = "Node %i" % node_index

                    yield desc

            else:
                desc.PoolStart = start_va
                desc.PoolEnd = end_va
                desc.Comment = ""

                yield desc

    def find_paged_pool(self):
        vector_pool = self.profile.get_constant_object(
            "PoolVector",
            target="Array",
            target_args=dict(
                count=2,
                target="Pointer",
                )
            )

        # Paged pool.
        paged_pool_start = self.profile.get_constant_object(
            "MmPagedPoolStart", "Pointer").v()

        if paged_pool_start == None:
            paged_pool_start = self.profile.get_constant_object(
                "MiPagedPoolStart", "Pointer").v()

        paged_pool_end = (
            paged_pool_start + self.profile.get_constant_object(
                "MmSizeOfPagedPoolInBytes", "address"))

        if paged_pool_start == None:
            # Windows 7 stores the end of the pool only
            # (nt!MiFreePagedPoolPages).
            paged_pool_end = self.profile.get_constant_object(
                "MmPagedPoolEnd", "Pointer").v()

            bitmap = self.profile.get_constant_object(
                "MmPagedPoolInfo", "_MM_PAGED_POOL_INFO").PagedPoolAllocationMap

            if bitmap:
                paged_pool_start = (
                    paged_pool_end - bitmap.SizeOfBitMap * 8 * 0x1000)

            else:
                paged_pool_start = (
                    paged_pool_end - self.profile.get_constant_object(
                        "MmSizeOfPagedPoolInBytes", "unsigned long long"))

        # Windows 10 build 10586.th2_release.160126-1819 uses dynamic Paged Pool
        # VA.
        if paged_pool_start == None:
            mistate = self.session.address_resolver.get_constant_object(
                "nt!MiState", "_MI_SYSTEM_INFORMATION")
            dynamic_paged_pool = mistate.multi_m(
                # 10586.th2_release.160126-1819
                "SystemVa.DynamicBitMapPagedPool",

                # 10074.fbl_impressive.150424-1350
                "DynamicBitMapPagedPool"
            )
            paged_pool_start = dynamic_paged_pool.BaseVa.v()
            paged_pool_end = (
                paged_pool_start +
                dynamic_paged_pool.MaximumSize * 0x1000)

        comment = ""
        if not paged_pool_start:
            if self.profile.metadata("arch") == "I386":
                # On Win7x86 the paged pool is distributed (see virt_map
                # plugin).
                comment = "Fragmented (See virt_map plugin)"
                paged_pool_start = paged_pool_end = None

            else:
                # Hard coded on Windows 7.
                # http://www.codemachine.com/article_x64kvas.html
                # http://www.reactos.org/wiki/Techwiki:Memory_Layout
                paged_pool_start = obj.Pointer.integer_to_address(
                    0xFFFFF8A000000000)
                paged_pool_end = obj.Pointer.integer_to_address(
                    0xFFFFF8CFFFFFFFFF)

        for desc in vector_pool[1].dereference_as(
                "Array",
                target_args=dict(
                    count=self.profile.get_constant_object(
                        "ExpNumberOfPagedPools", "unsigned int").v() + 1,
                    target="_POOL_DESCRIPTOR",
                )
            ):
            # Hard coded for 64 bit OS.
            desc.PoolStart = paged_pool_start
            desc.PoolEnd = paged_pool_end
            desc.Comment = comment

            yield desc

    def find_session_pool_descriptors(self):
        descriptors = {}
        for task in self.session.plugins.pslist().list_eprocess():
            desc = task.Session.PagedPool.cast(
                vm=task.get_process_address_space())
            if desc:
                desc.PoolStart = task.Session.PagedPoolStart.v()
                desc.PoolEnd = task.Session.PagedPoolEnd.v()
                desc.Comment = "Session %s" % task.Session.SessionId
                descriptors[desc.obj_offset] = desc

        return descriptors.values()

    def find_all_pool_descriptors(self):
        """Finds all unique pool descriptors."""
        descriptors = set(self.find_non_paged_pool())
        descriptors.update(self.find_paged_pool())
        descriptors.update(self.find_session_pool_descriptors())
        return descriptors

    def is_address_in_pool(self, address):
        if self._pool_lookup is None:
            self._pool_lookup = utils.RangedCollection()
            for descriptor in self.find_all_pool_descriptors():
                self._pool_lookup.insert(descriptor.PoolStart,
                                         descriptor.PoolEnd,
                                         descriptor)

        return self._pool_lookup.get_containing_range(address)

    def collect(self):
        descriptors = self.find_all_pool_descriptors()
        for desc in sorted(descriptors):
            yield dict(descriptor=desc,
                       type=desc.PoolType,
                       index=desc.PoolIndex,
                       size=desc.m("TotalBytes") or desc.TotalPages * 0x1000,
                       start=desc.PoolStart,
                       end=desc.PoolEnd,
                       comment=getattr(desc, "Comment", ""))


class PoolTracker(common.WindowsCommandPlugin):
    """Enumerate pool tag usage statistics."""

    name = "pool_tracker"

    table_header = [
        dict(name="tag", width=4),
        dict(name="nonpaged", width=20, align="r"),
        dict(name="nonpaged_bytes", width=10, align="r"),
        dict(name="paged", width=20, align="r"),
        dict(name="paged_bytes", width=10, align="r"),
    ]

    def collect(self):
        table = self.profile.get_constant_object(
            "PoolTrackTable",
            target="Pointer",
            target_args=dict(
                target="Array",
                target_args=dict(
                    count=self.profile.get_constant_object(
                        "PoolTrackTableSize", "unsigned int").v(),
                    target="_POOL_TRACKER_TABLE",
                    )
                )
            )

        for item in table:
            if item.Key == 0:
                continue

            self.session.report_progress()
            yield (# Show the pool tag as ascii.
                item.Key.cast("String", length=4),
                "%s (%s)" % (item.NonPagedAllocs,
                             item.NonPagedAllocs - item.NonPagedFrees),
                item.NonPagedBytes,
                "%s (%s)" % (item.PagedAllocs,
                             item.PagedAllocs - item.PagedFrees),
                item.PagedBytes,
            )
