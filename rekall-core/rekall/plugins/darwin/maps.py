# Rekall Memory Forensics
# Authors:
# Michael Cohen <scudette@gmail.com>
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


# pylint: disable=protected-access
from rekall import utils
from rekall.plugins.addrspaces import intel
from rekall.plugins.common import pfn
from rekall.plugins.darwin import common


class DarwinVADMap(pfn.VADMapMixin, common.ProcessFilterMixin,
                   common.AbstractDarwinCommand):
    """Inspect each page in the VAD and report its status.

    This allows us to see the address translation status of each page in the
    VAD.
    """

    def _CreateMetadata(self, collection):
        metadata = {}
        for descriptor_cls, _, kwargs in reversed(collection.descriptors):
            if issubclass(descriptor_cls, intel.PhysicalAddressDescriptor):
                metadata["offset"] = kwargs["address"]
                metadata.setdefault("type", "Valid")

            elif issubclass(descriptor_cls, intel.InvalidAddress):
                metadata["type"] = "Invalid"

        return metadata

    def GeneratePageMetatadata(self, proc):
        address_space = self.session.GetParameter("default_address_space")

        for map in proc.task.map.hdr.walk_list(
                "links.next", include_current=False):

            start = map.links.start
            end = map.links.end

            # Skip the entire region.
            if end < self.plugin_args.start:
                continue

            # Done.
            if start > self.plugin_args.end:
                break

            for vaddr in utils.xrange(start, end, 0x1000):
                if self.plugin_args.start <= vaddr <= self.plugin_args.end:
                    yield vaddr, self._CreateMetadata(
                        address_space.describe_vtop(vaddr))
