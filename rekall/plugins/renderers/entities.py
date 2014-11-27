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
    renderes_type = "Identity"
    renderers = ["TextRenderer", "TestRenderer"]

    def render_row(self, target, **_):
        return text.Cell(
            "%s: %s" % (target.first_index[1], target.first_index[2]))


class Entity_TextObjectRenderer(text.TextObjectRenderer):
    renders_type = "Entity"
    renderers = ["TextRenderer", "TestRenderer"]

    def __init__(self, *args, **kwargs):
        self.style = kwargs.pop("style", "value")
        self.name = kwargs.pop("name", "Entity")

        # Build up the list of columns we want to display.
        columns = kwargs.pop("columns", [])
        self.attributes = []
        for column in columns:
            if "/" in column:
                attribute_obj = entity.Entity.reflect_attribute(column)
                if not attribute_obj:
                    raise ValueError("Attribute %s doesn't exist." % column)
                self.attributes.append(attribute_obj)
            else:
                component_cls = entity.Entity.reflect_component(column)
                if not component_cls:
                    raise ValueError("Component %s doesn't exist." % column)

                for attribute in component_cls.component_fields:
                    if attribute.hidden:
                        continue

                    self.attributes.append(attribute)

        if not self.attributes:
            self.attributes = [entity.Entity.reflect_attribute("Named/name"),
                               entity.Entity.reflect_attribute("Named/kind")]

        super(Entity_TextObjectRenderer, self).__init__(*args, **kwargs)

        renderer_columns = []
        for attribute in self.attributes:
            renderer_columns.append(dict(name=attribute.name,
                                         style=attribute.style,
                                         # type=attribute.typedesc.type_name,
                                         width=attribute.width))

        self.table = text.TextTable(columns=renderer_columns,
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
            values = [target[a.path] for a in self.attributes]
            return self.table.get_row(*values)
        elif self.style == "compact":
            return text.Cell("%s: %s" % (target.kind, target.name))
        elif self.style == "value":
            return text.Cell(target.name)
