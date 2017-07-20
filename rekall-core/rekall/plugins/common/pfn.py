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

    table_header = [
        dict(name='_EPROCESS', type="_EPROCESS", hidden=True),
        dict(name="Divider", type="Divider"),
        dict(name="VAddr", style="address"),
        dict(name="PAddr", style="address", hidden=True),
        dict(name="length", style="address"),
        dict(name="type", width=20),
        dict(name="comment"),
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

    def collect(self):
        for task in self.filter_processes():
            yield dict(_EPROCESS=task,
                       Divider="Pid: {0} {1}\n".format(task.pid, task.name))

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
                        comment = self.FormatMetadata(type, old_metadata,
                                                      vaddr)

                        yield dict(VAddr=vaddr, PAddr=offset, length=length,
                                   type=type, comment=comment)

                    old_metadata = metadata
                    old_vaddr = vaddr
                    old_offset = offset
                    length = 0x1000

            if old_metadata:
                comment = self.FormatMetadata(type, old_metadata, vaddr)
                yield dict(VAddr=vaddr, PAddr=offset, length=length,
                           type=type, comment=comment)
