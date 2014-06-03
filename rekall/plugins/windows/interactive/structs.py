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
# pylint: disable=protected-access
from rekall import config
from rekall.plugins.windows import common


class AnalyzeStruct(common.AbstractWindowsCommandPlugin):
    """A plugin to analyze a memory location."""
    name = "analyze_struct"

    @classmethod
    def args(cls, parser):
        super(AnalyzeStruct, cls).args(parser)

        parser.add_argument("offset",
                            help="A virtual address to analyze.")

        parser.add_argument("search", type=config.IntParser, default=0x100,
                            help="How far back to search for pool tag.")


    def __init__(self, offset=0, search=0x100, **kwargs):
        super(AnalyzeStruct, self).__init__(**kwargs)
        self.offset = self.session.address_resolver.get_address_by_name(offset)
        self.search = search

    def SearchForPoolHeader(self, offset, size=0x100):
        """Search backwards from offset for a pool header."""
        offset = int(offset)

        for o in xrange(offset, offset-size, -0x8):
            pool_header = self.profile._POOL_HEADER(o)
            if pool_header.BlockSize == 0:
                continue

            if pool_header.PoolType > 4:
                continue

            # Verfiy it.
            if pool_header.PreviousSize > 0:
                previous_pool_header = self.profile._POOL_HEADER(
                    o - 0x10 * pool_header.PreviousSize)

                if previous_pool_header.BlockSize == pool_header.PreviousSize:
                    return pool_header

            # Check the next allocation.
            next_pool_header = self.profile._POOL_HEADER(
                o + 0x10 * pool_header.BlockSize)

            if next_pool_header.PreviousSize == pool_header.BlockSize:
                return pool_header

    def GuessMembers(self, offset, size=0x100):
        offset = int(offset)

        for member in self.profile.Array(offset, target="Pointer",
                                         count=size/8):
            result = []
            relative_offset = member.obj_offset - offset

            # Check for _LIST_ENTRYs
            list_member = member.cast("_LIST_ENTRY")
            if list_member.obj_offset == list_member.Flink.Blink.v():
                result.append("_LIST_ENTRY")
                result.append("@%#x" % list_member.Flink.obj_offset)

            # Try to find pointers to known pool allocations.
            pool = self.SearchForPoolHeader(member.v(), size=size)
            if pool:
                result.append("Tag:%s" % pool.Tag)
                result.append("@%#x" % member.v())

            if result:
                yield relative_offset, result


    def render(self, renderer):
        pool_header = self.SearchForPoolHeader(self.offset, size=self.search)
        if pool_header:
            renderer.format("{0:#x} is inside pool allocation with tag '{1}'\n",
                            self.offset,
                            str(pool_header.Tag).encode("string-escape"))

        renderer.table_header([("Offset", "offset", "[addr]"),
                               ("Content", "content", "")])

        for relative_offset, info in self.GuessMembers(
            self.offset, size=self.search):
            renderer.table_row(relative_offset, " ".join(
                [x.encode("string-escape") for x in info]))
