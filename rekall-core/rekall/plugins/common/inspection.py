# Rekall Memory Forensics
# Copyright 2015 Google Inc. All Rights Reserved.
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

"""This module implements some general purpose plugins for inspecting the
state of memory images.
"""

__author__ = "Michael Cohen <scudette@google.com>"

from rekall import plugin


class MemoryTranslation(plugin.KernelASMixin,
                        plugin.PhysicalASMixin,
                        plugin.TypedProfileCommand,
                        plugin.Command):
    """Inspect the mapping of a virtual address."""

    name = "inspect_vaddr"

    __args = [
        dict(name="address", required=True, type="SymbolAddress",
             positional=True, help="Virtual address to inspect.")
    ]

    table_header = [
        dict(name="Address Space", width=30),
        dict(name="Offset", style="address", padding="0"),
        dict(name="Base AS", width=30),
        dict(name="Base AS Offset", style="address", padding="0"),
    ]

    def _GetASName(self, address_space):
        if address_space is None:
            return ""

        if address_space.name:
            return address_space.name
        return address_space.__class__.__name__

    def collect(self):
        address_space = self.session.GetParameter("default_address_space")
        address = self.plugin_args.address

        # Traverse the address space stack and report each address space.
        while address_space is not None:
            run = address_space.vtop_run(address)

            if address_space == run.address_space:
                break

            yield (self._GetASName(address_space),
                   address,
                   self._GetASName(run.address_space),
                   run.file_offset)

            address_space = run.address_space
            address = run.file_offset
