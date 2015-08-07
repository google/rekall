# Rekall Memory Forensics
#
# Copyright 2015 Google Inc. All Rights Reserved.
#
# Authors:
# Michael Cohen <scudette@google.com>
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

from rekall.plugins.common import pfn
from rekall.plugins.darwin import common


class DarwinVadMap(pfn.VADMapMixin,
                   common.DarwinProcessFilter):

    def _FillMetadata(self, vaddr, metadata):
        address_space = self.session.GetParameter("default_address_space")
        for type, _, addr in address_space.describe_vtop(vaddr):
            if type == "pte" and addr:
                metadata["type"] = "Valid"
                return self.profile._MMPTE(
                    addr, vm=self.physical_address_space)

    def GeneratePageMetatadata(self, task):
        for map in proc.task.map.hdr.walk_list(
                "links.next", include_current=False):

            metadata = {}

            # Find the vnode this mapping is attached to.
            vnode = map.find_vnode_object()
            if vnode.path:
                metadata["filename"] = vnode.path

            pte_plugin = self.session.plugins.pte()
            offset = map.links.start
            end = map.links.end

            while offset < end:
                if self.start <= offset <= self.end:
                    pte = self._GetPTE(offset)
                    metadata = pte_plugin.ResolvePTE(pte, offset)

                    yield offset, metadata
                    self.session.report_progress("Inspecting 0x%08X", offset)

                offset += 0x1000
