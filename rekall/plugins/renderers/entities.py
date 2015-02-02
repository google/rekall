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

from rekall.entities import entity

from rekall.plugins.renderers import data_export
from rekall.ui import text


class Dependency_TextObjectRenderer(text.TextObjectRenderer):
    renders_type = "Dependency"
    renderers = ["TextRenderer", "TestRenderer"]

    def render_row(self, target, **_):
        if target.flag:
            prefix = "+"
        else:
            prefix = "-"

        template = "{prefix} {component}"
        if target.attribute:
            template += "/{attribute}"

        if target.value:
            template += "={value}"

        return text.Cell(template.format(component=target.component,
                                         prefix=prefix,
                                         attribute=target.attribute,
                                         value=target.value))


class Query_TextObjectRenderer(text.TextObjectRenderer):
    renders_type = "Query"
    renderers = ["TextRenderer", "TestRenderer"]

    def render_row(self, target, query_highlight=None, **_):
        if query_highlight is None:
            return text.Cell(unicode(target))

        start, end = target.locate_expression(query_highlight)
        highlights = [(start, end, "RED", None)]

        return text.Cell(value=target.source, highlights=highlights)


class Identity_TextObjectRenderer(text.TextObjectRenderer):
    renders_type = "Identity"
    renderers = ["TextRenderer", "TestRenderer"]

    def render_row(self, target, **_):
        return text.Cell(
            "%s: %s" % (target.first_index[1], target.first_index[2]))


class Entity_DataExportObjectRenderer(data_export.DataExportObjectRenderer):
    renders_type = "Entity"
    renderers = ["DataExportRenderer"]

    def GetState(self, item, **_):
        return item.asdict()


class Entity_TextObjectRenderer(text.TextObjectRenderer):
    renders_type = "Entity"
    renderers = ["TextRenderer", "TestRenderer"]

    @staticmethod
    def _column_getter(path):
        return lambda e: e[path]

    def __init__(self, *args, **kwargs):
        self.style = kwargs.pop("style", "value")
        self.name = kwargs.pop("name", "Entity")

        # Build up the list of columns we want to display.
        columns = kwargs.pop("columns", [])
        self.column_getters = []
        renderer_headers = []

        for column in columns:
            column_attr = None
            column_name = None
            column_style = None
            column_width = None
            column_getter = None

            if isinstance(column, basestring):
                column_attr = column
            elif isinstance(column, dict):
                column_name = column.get("name")
                column_getter = column.get("fn")
                column_attr = column.get("attribute")
                column_style = column.get("style")
                column_width = column.get("width")
            else:
                raise ValueError(
                    "Column must be dict or a basestring. Got %s." % (
                        type(column)))

            if not column_getter:
                if not column_attr:
                    raise ValueError(
                        "Must specify either 'attribute' or 'fn'.")
                attribute_obj = entity.Entity.reflect_attribute(column_attr)
                if not attribute_obj:
                    raise ValueError(
                        "Attribute %s doesn't exist." % column_attr)
                column_getter = self._column_getter(attribute_obj.path)
                column_width = column_width or attribute_obj.width
                column_style = column_style or attribute_obj.style

            if not column_name:
                if column_attr:
                    column_name = column_attr.split("/")[-1]
                else:
                    column_attr = "untitled column"

            renderer_headers.append(dict(name=column_name,
                                         width=column_width,
                                         style=column_style))
            self.column_getters.append(column_getter)

        super(Entity_TextObjectRenderer, self).__init__(*args, **kwargs)

        self.table = text.TextTable(columns=renderer_headers,
                                    renderer=self.renderer,
                                    session=self.session)

    def render_header(self, **options):
        if self.style == "full":
            return self.table.render_header()
        else:
            result = text.Cell(self.name, width=40)

            return result

    def render_row(self, target, **options):
        if self.style == "full":
            values = [getter(target) for getter in self.column_getters]
            return self.table.get_row(*values)
        elif self.style in ("compact", "value"):
            return text.Cell(target.name)
