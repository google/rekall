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

__author__ = "Adam Sindelar <adam.sindelar@gmail.com>"

from rekall.plugins.darwin import common

class DarwinListFiles(common.DarwinPlugin):
    """List all files that can be identified in the image."""

    __name = "list_files"

    def render(self, renderer):
        renderer.table_header([
            ("Type", "type", "10"),
            ("Source(s)", "sources", "30"),
            ("Created", "ctime", "15"),
            ("Modified", "mtime", "15"),
            ("Path", "path", "80")])

        for entity in self.session.entities.find_by_component("File"):
            renderer.table_row(
                entity["File/type"],
                ",".join(entity["Entity/collectors"]),
                entity["Timestamps/created_at"],
                entity["Timestamps/modified_at"],
                entity["File/path"])
