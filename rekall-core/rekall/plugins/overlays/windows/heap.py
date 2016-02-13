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

"""The module implements user mode heap overlays.

Recent versions of windows use the Low Fragmentation Heap (LFH).

http://illmatics.com/Understanding_the_LFH.pdf

"""

__author__ = "Michael Cohen <scudette@google.com>"

from rekall import addrspace
from rekall import utils
from rekall import obj
from rekall.plugins.overlays.windows import common
from rekall.plugins.overlays.windows import pe_vtypes


_HEAP_Flags = dict(
    NO_SERIALIZE=0x00000001L,
    GROWABLE=0x00000002L,
    GENERATE_EXCEPTIONS=0x00000004L,
    ZERO_MEMORY=0x00000008L,
    REALLOC_IN_PLACE_ONLY=0x00000010L,
    TAIL_CHECKING_ENABLED=0x00000020L,
    FREE_CHECKING_ENABLED=0x00000040L,
    DISABLE_COALESCE_ON_FREE=0x00000080L,
    CREATE_ALIGN_16=0x00010000L,
    CREATE_ENABLE_TRACING=0x00020000L,
    CREATE_ENABLE_EXECUTE=0x00040000L,
)

_HEAP_ENTRY_Flags = dict(
    BUSY=0x01,
    EXTRA_PRESENT=0x02,
    FILL_PATTERN=0x04,
    VIRTUAL_ALLOC=0x08,
    LAST_ENTRY=0x10,
    SETTABLE_FLAG1=0x20,
    SETTABLE_FLAG2=0x40,
    SETTABLE_FLAG3=0x80,
)

overlays = {
    '_PEB': [None, {
        'ProcessHeaps': [None, ['Pointer', dict(
            target='Array',
            target_args=dict(
                count=lambda x: x.NumberOfHeaps,
                target='Pointer',
                target_args=dict(
                    target='_HEAP'
                    )
                )
            )]],
    }],

    '_HEAP': [None, {
        'BlocksIndex': [None, ['Pointer', dict(
            target='_HEAP_LIST_LOOKUP'
            )]],

        'Flags': [None, ['Flags', dict(
            maskmap=_HEAP_Flags,
            target="unsigned long"
            )]],

        'FrontEndHeapType': lambda x: x.cast(
            "Enumeration",
            # LOOK_ASIDE is not available on Win7+.
            choices={
                0: "BACKEND",    # Only using backend allocator.
                1: "LOOK_ASIDE",
                2: "LOW_FRAG",
                },
            value=x.m("FrontEndHeapType")
        ),

        'FrontEndHeap': [None, ["Pointer", dict(
            target="_LFH_HEAP"
            )]],

        }],

    '_HEAP_ENTRY': [None, {
        'Flags': [None, ['Flags', dict(
            maskmap=_HEAP_ENTRY_Flags,
            target="unsigned char"
            )]],

        }],

    '_HEAP_FREE_ENTRY': [None, {
        'Flags': [None, ['Flags', dict(
            maskmap=_HEAP_ENTRY_Flags,
            target="unsigned char"
            )]],

        }],

    '_HEAP_LIST_LOOKUP': [None, {
        'ListHints': [None, ["Array", dict(
            target="_LIST_ENTRY",
            count=lambda x: x.ArraySize
        )]],
    }],

    '_HEAP_USERDATA_HEADER': [None, {
        'Entries': [lambda x: x.obj_end, ["Array", dict(
            target="_HEAP_ENTRY",
            count=lambda x: x.obj_parent.BlockCount,
            target_size=lambda x: x.obj_parent.BlockSize * 16,
            )]],
    }],
}


class _HEAP_ENTRY(obj.Struct):
    """A heap entry.

    Note that heap entries for a given heap are encoded by using a random field
    XORed with the heap entry. This object automatically decodes the heap entry
    if the heap is encoded.
    """

    def __init__(self, **kwargs):
        super(_HEAP_ENTRY, self).__init__(**kwargs)

        encoding = self.obj_context.get("Encoding")
        if encoding:
            heap_as = self.obj_context["HeapAS"]
            self.obj_vm = addrspace.BufferAddressSpace(
                session=self.obj_session,
                base_offset=self.obj_offset,
                data=utils.XOR(
                    heap_as.read(self.obj_offset, self.obj_size),
                    encoding)
                )

    @utils.safe_property
    def PrevEntry(self):
        if self.PreviousSize == 0:
            return obj.NoneObject("First Entry")

        return self.cast(
            "Pointer",
            target="_HEAP_ENTRY",
            value=(self.obj_offset +
                   self.PreviousSize * self.obj_size))

    @utils.safe_property
    def NextEntry(self):
        if self.Flags.LAST_ENTRY or self.Size == 0:
            return obj.NoneObject("Last Entry")

        return self.cast(
            "Pointer",
            target="_HEAP_ENTRY",
            value=(self.obj_offset +
                   self.Size * self.obj_profile.get_obj_size("_HEAP_ENTRY")))

    @utils.safe_property
    def Allocation(self):
        allocation_size = self.Size * self.obj_size

        # On 64 bit platforms allocations are allowed to overflow into the first
        # 8 bytes of the next allocation.
        if self.obj_profile.metadata("arch") == "AMD64":
            allocation_size -= 8

        return self.obj_profile.String(offset=self.obj_end,
                                       term=None,
                                       length=allocation_size)


class _HEAP(obj.Struct):
    """
    Ref:
    http://www.informit.com/articles/article.aspx?p=1081496
    """

    def __init__(self, **kwargs):
        super(_HEAP, self).__init__(**kwargs)

        # This passes the heap's encoding to all members of this heap.
        if self.m("Encoding"):
            self.obj_context["Encoding"] = self.obj_vm.read(
                self.Encoding.obj_offset, self.Encoding.obj_size)

        self.obj_context["HeapAS"] = self.obj_vm

    @utils.safe_property
    def Segments(self):
        """Returns an iterator over the segments."""
        # Windows XP has an array of segments.
        segment_array = self.m("Segments")
        if segment_array:
            for segment in segment_array:
                segment = segment.dereference()

                # Since we operate in the process address space address 0 may be
                # valid.
                if not segment:
                    break

                yield segment

            return

        # Windows 7 has a linked list of segments.
        for segment in self.SegmentList.list_of_type(
                "_HEAP_SEGMENT", "SegmentListEntry"):
            yield segment


    @utils.safe_property
    def Entries(self):
        """Iterates over all the entries in all the segments."""
        for segment in self.Segments:
            for entry in segment.FirstEntry.walk_list("NextEntry", True):
                yield entry



class Ntdll(pe_vtypes.BasicPEProfile):
    """A profile for the ntdll user mode DLL."""

    @classmethod
    def Initialize(cls, profile):
        super(cls, Ntdll).Initialize(profile)

        InitializeHeapProfile(profile)
        common.InitializeWindowsProfile(profile)


def InitializeHeapProfile(profile):
    profile.add_overlay(overlays)
    profile.add_classes(
        _HEAP=_HEAP,
        _HEAP_ENTRY=_HEAP_ENTRY,
        _HEAP_FREE_ENTRY=_HEAP_ENTRY,
    )
