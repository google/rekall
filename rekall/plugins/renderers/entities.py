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

        return text.Cell.FromString(
            self.formatter.format(template, component=target.component,
                                  prefix=prefix, attribute=target.attribute,
                                  value=target.value))


class Query_TextObjectRenderer(text.TextObjectRenderer):
    renders_type = "Query"
    renderers = ["TextRenderer", "TestRenderer"]

    def render_row(self, target, query_highlight=None, **_):
        if query_highlight is None:
            return text.Cell.FromString(unicode(target))

        return text.Cell.FromString(
            self.formatter.format("{0} >>> {1} <<< {2}",
                                  *target.expression_source(query_highlight)))


class Identity_TextObjectRenderer(text.TextObjectRenderer):
    renderes_type = "Identity"
    renderers = ["TextRenderer", "TestRenderer"]

    def render_row(self, target, **_):
        return text.Cell.FromString(
            self.formatter.format("({0}: {1})",
                                  target.first_index[1],
                                  target.first_index[2]))


class Entity_TextObjectRenderer(text.TextObjectRenderer):
    renders_type = "Entity"
    renderers = ["TextRenderer", "TestRenderer"]

    def __init__(self, *args, **kwargs):
        self.style = kwargs.pop("style", "name")

        self.name = kwargs.pop("name", "Entity")
        self.attributes = []

        for component in kwargs.pop("components", []) or []:
            component_cls = entity.Entity.reflect_component(component)
            for field in component_cls.component_fields:
                if field.hidden:
                    continue
                self.attributes.append(field)

        for attribute in kwargs.pop("attributes", []) or []:
            self.attributes.append(entity.Entity.reflect_attribute(attribute))

        super(Entity_TextObjectRenderer, self).__init__(*args, **kwargs)

        columns = []
        for attribute in self.attributes:
            columns.append(dict(name=attribute.name,
                                # type=attribute.typedesc.type_name,
                                width=attribute.width))

        self.table = text.TextTable(columns=columns,
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
            values = [target[a.path] for a in self.attributes]
            cells = self.table.get_row(*values)
            return text.Cell.Join(cells)
        elif self.style == "short":
            return text.Cell.FromString(
                self.formatter.format("{0}: {1}", target.kind, target.name))
        elif self.style == "name":
            return text.Cell.FromString(target.name)
