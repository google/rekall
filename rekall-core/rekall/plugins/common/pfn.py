# Rekall Memory Forensics
#
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



class PhysicalAddressContext(object):
    """A lazy evaluator for context information around physical addresses."""

    def __init__(self, session, address):
        self.session = session
        self.address = address

    def summary(self):
        rammap_plugin = self.session.plugins.rammap(
            start=self.address, end=self.address+1)
        for row in rammap_plugin.collect():
            return row

    def __str__(self):
        rammap_plugin = self.session.plugins.rammap(
            start=self.address, end=self.address+1)
        if rammap_plugin != None:
            return rammap_plugin.summary()[0]

        return "Phys: %#x" % self.address


class VADMapMixin(object):
    """A plugin to display information about virtual address pages."""

    name = "vadmap"

    __args = [
        dict(name="start", default=0, type="IntParser",
             help="Start reading from this page."),

        dict(name="end", default=2**63, type="IntParser",
             help="Stop reading at this offset."),
    ]

    def FormatMetadata(self, type, metadata, offset=None):
        result = ""
        if not metadata:
            result = "Invalid PTE "

        if "filename" in metadata:
            result += "%s " % metadata["filename"]

        if "number" in metadata:
            result = "PF %s " % metadata["number"]

        if type == "Valid" or type == "Transition":
            result += "PhysAS "

        if offset:
            result += "@ %#x " % offset

        if "ProtoType" in metadata:
            result += "(P) "

        return result

    def GeneratePageMetatadata(self, task):
        """A Generator of vaddr, metadata for each page."""
        _ = task
        return []

    def render_metadata(self, renderer, old_metadata, old_vaddr, type,
                        offset, length, old_offset):
        comment = self.FormatMetadata(
            type, old_metadata, offset=old_offset)
        if self.plugin_args.verbosity < 5:
            renderer.table_row(old_vaddr, length, type, comment)
        else:
            renderer.table_row(old_vaddr, old_offset, length, type, comment)

    def render(self, renderer):
        for task in self.filter_processes():
            renderer.section()
            renderer.format("Pid: {0} {1}\n", task.pid, task.name)

            headers = [
                ('Virt Addr', 'virt_addr', '[addrpad]'),
                ('Offset', 'offset', '[addrpad]'),
                ('Length', 'length', '[addr]'),
                ('Type', 'type', '20s'),
                ('Comments', 'comments', "")]

            if self.plugin_args.verbosity < 5:
                headers.pop(1)

            renderer.table_header(headers)

            with self.session.plugins.cc() as cc:
                cc.SwitchProcessContext(task)

                old_offset = 0
                old_vaddr = 0
                length = 0x1000
                old_metadata = {}
                for vaddr, metadata in self.GeneratePageMetatadata(task):
                    # Remove the offset so we can merge on identical
                    # metadata (offset will change for each page).
                    offset = metadata.pop("offset", None)

                    # Coalesce similar rows.
                    if ((offset is None or old_offset is None or
                         self.plugin_args.verbosity < 5 or
                         offset == old_offset + length) and
                            metadata == old_metadata and
                            vaddr == old_vaddr + length):
                        length += 0x1000
                        continue

                    type = old_metadata.get("type", None)
                    if type:
                        self.render_metadata(renderer, old_metadata, old_vaddr,
                                             type, offset, length, old_offset)

                    old_metadata = metadata
                    old_vaddr = vaddr
                    old_offset = offset
                    length = 0x1000

            if old_metadata:
                self.render_metadata(renderer, old_metadata, old_vaddr,
                                     type, offset, length, old_offset)
