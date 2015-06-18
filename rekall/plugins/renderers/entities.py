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

from efilter.protocols import superposition

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


class Identity_DataExportObjectRenderer(data_export.DataExportObjectRenderer):
    renders_type = "Identity"
    renderers = ["DataExportRenderer"]

    def GetState(self, item, **_):
        return dict(
            name=item.name,
            kind=item.kind,
            query="<unsupported>")  # TODO: This is pending EFILTER exporter.


class Identity_TextObjectRenderer(text.TextObjectRenderer):
    renders_type = "Identity"
    renderers = ["TextRenderer", "TestRenderer"]

    def render_row(self, target, **_):
        return text.Cell(
            "%s: %s" % (target.first_index[1], target.first_index[2]))


class Superposition_DataExportObjectRenderer(
    data_export.DataExportObjectRenderer):
    renders_type = "DelegatingSuperposition"
    renderers = ["DataExportRenderer"]

    def GetState(self, item, **kwargs):
        states = []
        for state in superposition.getstates(item):
            renderer = self.DelegateObjectRenderer(state)
            states.append(renderer.EncodeToJsonSafe(state))

        if len(states) == 1:
            return states[0]

        return dict(states=states)


class Superposition_TextObjectRenderer(text.TextObjectRenderer):
    renders_type = "DelegatingSuperposition"
    renderers = ["TextRenderer", "TestRenderer"]

    def render_row(self, target, **kwargs):
        states = []
        for state in superposition.getstates(target):
            renderer = self.DelegateObjectRenderer(state)
            states.append(renderer.render_row(target=state, **kwargs))

        if len(states) == 1:
            return states[0]

        joined = ", ".join(sorted([unicode(state) for state in states]))
        return text.Cell("(%d values): %s" % (len(states), joined))


class Entity_DataExportObjectRenderer(data_export.DataExportObjectRenderer):
    renders_type = "Entity"
    renderers = ["DataExportRenderer"]

    def GetState(self, item, **opts):
        if opts.get("style") == "full":
            return item.export()
        else:
            # Serialize as Identity only. (But with name/kind.)

            # It's alright to mutate these fields on the identity since they
            # have no meaning to the entity system (they're just human labels).
            item.identity.name = item.name
            item.identity.kind = item.kind
            renderer = self.DelegateObjectRenderer(item.identity)
            return renderer.EncodeToJsonSafe(item.identity)


class Entity_TextObjectRenderer(text.TextObjectRenderer):
    renders_type = "Entity"
    renderers = ["TextRenderer", "TestRenderer"]

    def render_full(self, item, **_):
        return text.Cell("%s (%s)" % (item.name, item.kind))

    def render_compact(self, item, **_):
        return text.Cell(unicode(item.name))
