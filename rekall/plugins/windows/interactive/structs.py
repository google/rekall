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

"""Interactive plugins.

This file contains a bunch of plugins which are useful when interactively
examining a memory image.
"""
import itertools

# pylint: disable=protected-access
from rekall import obj
from rekall import utils
from rekall.plugins.windows import common


class AnalyzeStruct(common.WindowsCommandPlugin):
    """A plugin to analyze a memory location."""
    name = "analyze_struct"

    @classmethod
    def args(cls, parser):
        super(AnalyzeStruct, cls).args(parser)

        parser.add_argument("offset",
                            help="A virtual address to analyze.")

        parser.add_argument("--search", type="IntParser", default=0x100,
                            help="How far back to search for pool tag.")

        parser.add_argument("--size", type="IntParser", default=0x100,
                            help="How many elements to identify.")

    def __init__(self, offset=0, search=0x100, size=0x100, **kwargs):
        super(AnalyzeStruct, self).__init__(**kwargs)
        self.offset = self.session.address_resolver.get_address_by_name(offset)
        self.search = search
        self.size = size
        self.highest_user_address = self.profile.get_constant_object(
            "MmHighestUserAddress", "unsigned long long")

    def SearchForPoolHeader(self, offset, search=0x100):
        """Search backwards from offset for a pool header."""
        pool_alignment = self.profile.get_constant("PoolAlignment")
        offset = int(offset) - offset % pool_alignment

        # Cant use xrange() on windows since it must fit into a long.
        for o in itertools.count(offset, -pool_alignment):
            if o < offset-search:
                break

            pool_header = self.profile._POOL_HEADER(o)

            # If this is the pool header for this allocation it must be big
            # enough to contain it.
            if pool_header.BlockSize < (offset - o) / pool_alignment + 1:
                continue

            #if not pool_header.PoolType.is_valid():
            #    continue

            # Verify it.
            if pool_header.PreviousSize > 0:
                previous_pool_header = self.profile._POOL_HEADER(
                    o - pool_alignment * pool_header.PreviousSize)

                if previous_pool_header.BlockSize == pool_header.PreviousSize:
                    return pool_header

            # Check the next allocation.
            next_pool_header = self.profile._POOL_HEADER(
                o + pool_alignment * pool_header.BlockSize)

            if next_pool_header.PreviousSize == pool_header.BlockSize:
                return pool_header

        return obj.NoneObject("No pool tag found")

    def GuessMembers(self, offset, size=0x100, search=0x100):
        offset = int(offset)
        resolver = self.session.address_resolver
        result = []

        for member in self.profile.Array(offset, target="Pointer",
                                         count=size/8):
            address_info = ["Data:%#x" % member.v()]
            relative_offset = member.obj_offset - offset
            result.append((relative_offset, address_info))

            # If the last member was a _LIST_ENTRY skip this one since its just
            # the Blink of it.
            if len(result) > 1 and "_LIST_ENTRY" in result[-2][1]:
                continue

            # Check for _LIST_ENTRYs
            list_member = member.cast("_LIST_ENTRY")
            if list_member.obj_offset == list_member.Flink.Blink.v():
                address_info.append("_LIST_ENTRY")
                address_info.append("@%#x" % list_member.Flink.v())

            if list_member.obj_offset == list_member.Flink.v():
                address_info.append("Empty")

            # Try to find pointers to known pool allocations.
            pool = self.SearchForPoolHeader(member.v(), search=search)
            if pool:
                address_info.append("Tag:%s" % pool.Tag)
                proc = pool.m("ProcessBilled")
                # Does the tag refer to a real _EPROCESS? If so it must have a
                # valid environment block (and a corresponding address space).
                if proc.Peb:
                    address_info.append("ProcessBilled:%s" % proc.name)

                address_info.append("@%#x" % member.v())

            else:
                # Look for pointers to global symbols.
                sym_offset, symbol = resolver.get_nearest_constant_by_address(
                    member.v())

                if symbol and sym_offset == member.v():
                    address_info.append("Const:%s" % symbol)

        return result

    def render(self, renderer):
        pool_header = self.SearchForPoolHeader(self.offset, search=self.search)

        if pool_header:
            name = (pool_header.ProcessBilled.name or
                    str(pool_header.Tag).encode("string-escape"))

            renderer.format(
                "{0:#x} is inside pool allocation with tag '{1}' ({2:#x})\n",
                self.offset, name, pool_header)

        renderer.table_header([("Offset", "offset", "[addr]"),
                               ("Content", "content", "")])

        for relative_offset, info in self.GuessMembers(
                self.offset, size=self.size, search=self.search):
            renderer.table_row(relative_offset, " ".join(
                [utils.SmartStr(x).encode("string-escape") for x in info]))
