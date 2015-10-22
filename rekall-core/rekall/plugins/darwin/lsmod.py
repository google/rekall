# Rekall Memory Forensics
#
# Copyright 2013 Google Inc. All Rights Reserved.
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
"""Enumerate all kernel modules."""

__author__ = "Michael Cohen <scudette@google.com>"

from rekall.plugins.darwin import common


class DarwinLsmod(common.AbstractDarwinCommand):
    """Lists all kernel modules."""

    __name = "lsmod"

    modlist = None
    mod_lookup = None

    def get_module_list(self):
        # The kernel is also included in the module list to make it easier to
        # local pointers inside it.
        # See: xnu-2422.1.72/bsd/dev/dtrace/dtrace.c: 19843
        kernel = self.profile.get_constant_object(
            "_g_kernel_kmod_info", "kmod_info")
        if kernel:
            yield kernel

        module = self.profile.get_constant_object(
            "_kmod",
            target="Pointer",
            target_args=dict(
                target="kmod_info"
            ),
            vm=self.kernel_address_space)

        # walk the modules list
        for m in module.walk_list("next", True):
            yield m

    def render(self, renderer):
        renderer.table_header([("Address", "address", "[addrpad]"),
                               ("Size", "size", "[addrpad]"),
                               ("Refs", "refs", ">8"),
                               ("Version", "version", ">12"),
                               ("Name", "name", "")])

        for mod in self.get_module_list():
            renderer.table_row(mod.address,
                               mod.m("size"),
                               mod.reference_count,
                               mod.version,
                               mod.name)
