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
                        plugin.Command):
    """Inspect the mapping of a virtual address."""

    name = "inspect_vaddr"

    @classmethod
    def args(cls, metadata):
        metadata.add_argument(
            "address", required=True, type="SymbolAddress",
            help="Virtual address to inspect.")

    def __init__(self, address=None, **kwargs):
        super(MemoryTranslation, self).__init__(**kwargs)
        self.address = self.session.address_resolver.get_address_by_name(
            address)

    def _GetASName(self, address_space):
        if address_space.name:
            return unicode(address_space.name)[:30]
        return address_space.__class__.__name__

    def render(self, renderer):
        renderer.table_header([
            dict(name="Address Space", width=30),
            dict(name="Offset", style="address", padding="0"),
            dict(name="Base AS", width=30),
            dict(name="Base AS Offset", style="address", padding="0"),
        ])

        address_space = self.session.GetParameter("default_address_space")
        address = self.address

        # Traverse the address space stack and report each address space.
        while 1:
            paddr = address_space.vtop(address)

            if address_space == address_space.phys_base:
                break

            renderer.table_row(
                self._GetASName(address_space),
                address,
                self._GetASName(address_space.phys_base),
                paddr,
            )

            address_space = address_space.phys_base
            address = paddr
