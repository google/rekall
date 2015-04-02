# Rekall Memory Forensics
#
# Copyright Digital Forensics Solutions.
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

__author__ = ("Andrew Case <atcuno@gmail.com>",
              "Michael Cohen <scudette@google.com>")


from rekall.plugins.linux import common


class IOmem(common.LinuxPlugin):
    '''mimics /proc/iomem.'''

    __name = "iomem"

    def GetResources(self):
        # Resources are organized in a tree structure.
        resource_tree_root = self.profile.get_constant_object(
            "iomem_resource", target="resource")

        seen = set()

        return self._GetResources(resource_tree_root, seen)

    def _GetResources(self, node, seen, depth=0):
        """Traverse the resource tree depth first."""
        if not node or node in seen:
            return

        seen.add(node)

        yield node, depth

        if node.child:
            for x in self._GetResources(node.child.deref(), seen, depth+1):
                yield x

        for sibling in node.walk_list("sibling"):
            for x in self._GetResources(sibling, seen, depth):
                yield x


    def render(self, renderer):
        renderer.table_header([
            ("Resource", "resource", "[addrpad]"),
            ("Start", "start", "[addrpad]"),
            ("End", "end", "[addrpad]"),
            dict(name="Name", type="TreeNode"),
            ])

        for node, depth in self.GetResources():
            renderer.table_row(
                node, node.start, node.end, node.name.deref(), depth=depth)

