# Rekall Memory Forensics
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
#

"""This module implements entity renderers."""

from rekall.ui import text


class Entity_TextObjectRenderer(text.TextObjectRenderer):
    renders_type = "Entity"
    renderers = ["TextRenderer", "TestRenderer"]

    def __init__(self, *args, **options):
        self.name = options.pop("name", "Entity")
        self.style = options.pop("style", "short")

        super(Entity_TextObjectRenderer, self).__init__(*args, **options)
        self.table = text.TextTable(
            columns=[dict(name="Name", cname="name", width=30),
                     dict(kind="Kind", cname="kind", width=20)],
            renderer=self.renderer,
            session=self.session)

    def render_header(self, **options):
        if self.style == "full":
            return self.table.render_header()
        else:
            result = text.Cell.FromString(
                self.formatter.format_field(self.name, "^40s"))
            result.append("-" * result.width)

            return result

    def render_row(self, target, **options):
        if self.style == "full":
            cells = self.table.get_row(target.name, target.kind)
            return text.Cell.Join(cells)
        else:
            return text.Cell.FromString(
                self.formatter.format("{0}: {1}", target.kind, target.name))
