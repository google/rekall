# Rekall Memory Forensics
#
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

from rekall.plugins.linux import common


class NotifierChainPlugin(common.LinuxPlugin):
    """Outputs and verifies kernel notifier chains."""

    __name = "notifier_chains"
    _chains = ["vt_notifier_list",
               "keyboard_notifier_list",
              ]

    def walk_chain(self, chain_symbol):
        chain = self.session.profile.get_constant_object(
            chain_symbol,
            target="atomic_notifier_head",
            vm=self.kernel_address_space)

        return chain.head.walk_list("next")

    def walk_chains(self):
        for chain_symbol in self._chains:
            for index, item in enumerate(self.walk_chain(chain_symbol)):
                yield (chain_symbol, index, item)

    def render(self, renderer):
        renderer.table_header([("Chain symbol", "symbol", ">25"),
                               ("Index", "index", ">5"),
                               ("Priority", "prio", ">8"),
                               ("Address", "address", "[addrpad]"),
                               ("Module", "module", "20"),
                               ("Symbol", "symbol", "40"),
                              ])

        for symbol_name, index, notifier_block in self.walk_chains():
            symbol_name = self.session.address_resolver.format_address(
                notifier_block.notifier_call)

            renderer.table_row(symbol_name,
                               index, notifier_block.priority,
                               notifier_block.notifier_call,
                               related_module.name, symbol_name)
