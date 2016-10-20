# Rekall Memory Forensics
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright 2013 Google Inc. All Rights Reserved.
#
# This file is part of Rekall Memory Forensics.
#
# Rekall Memory Forensics is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General Public
# License.
#
# Rekall Memory Forensics is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# Rekall Memory Forensics.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization:
"""
from rekall import testlib
from rekall.plugins.linux import common


class CheckIdt(common.LinuxPlugin):
    """ Checks if the IDT has been altered """

    __name = "check_idt"

    table_header = [
        dict(name="index", style="address"),
        dict(name="address", style="address"),
        dict(name="type", width=18, align="r"),
        dict(name="present", width=7, align="r"),
        dict(name="dpl", width=3, align="r"),
        dict(name="symbol")
    ]

    def CheckTable(self, table, check_indexes=None):
        """Given an IDT table yields information about all its entries.

        Args:
          table: An IDT table object (gate_struct64 or desc_struct).
          check_indexes: A list of indexes to check. If not set we do 0:255.

        Yields:
          slot, address, function or module containing this function.
        """
        if check_indexes is None:
            check_indexes = range(256)

        for i in check_indexes:
            entry = table[i]
            yield i, entry

    def CheckIDTTables(self):
        """
        This works by walking the IDT table for the entries that Linux uses
        and verifies that each is a symbol in the kernel
        """
        # arch/x86/include/asm/desc_defs.h
        # hw handlers + system call
        if self.profile.metadata('arch') == "I386":
            idt_type = "desc_struct"
        else:
            idt_type = "gate_struct64"

        # idt_table is defined in arch/x86/kernel/traps.c for 32-bit kernels
        # and in arch/x86/kernel/head_64.S on 64-bit kernels.
        # idt_table entries are set via the set_*_gate set of functions in
        # arch/x86/include/asm/desc.h.
        idt_table = self.profile.get_constant_object(
            "idt_table",
            target="Array",
            target_args=dict(
                target=idt_type,
                count=256)
            )

        return self.CheckTable(idt_table)

    def collect(self):
        for (i, entry) in self.CheckIDTTables():
            symbol = ", ".join(
                self.session.address_resolver.format_address(
                    entry.address))

            # Point out suspicious constants.
            highlight = None if symbol.startswith("linux") else "important"

            yield dict(index=i, address=entry.address, type=entry.gate_type,
                       present=entry.present, dpl=entry.dpl, symbol=symbol,
                       highlight=highlight)


class TestCheckIdt(testlib.SimpleTestCase):
    PARAMETERS = dict(commandline="check_idt")
