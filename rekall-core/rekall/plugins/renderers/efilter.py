# Rekall Memory Forensics
#
# Copyright 2016 Google Inc. All Rights Reserved.
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

"""Renderers for Efilter.."""
from rekall.ui import renderer as renderer_module
from rekall.ui import text
from rekall.plugins.renderers import data_export


class RowTupleTextObjectRenderer(text.TextObjectRenderer):
    renders_type = "RowTuple"
    renderers = ["TextRenderer", "TestRenderer", "WideTextRenderer"]

    def render_row(self, item, **_):
        result = []
        for element in item:
            delegate_cls = renderer_module.ObjectRenderer.ForTarget(
                element, renderer=self.renderer)
            result.append(delegate_cls(
                session=self.session,
                renderer=self.renderer).render_row(element))

        return text.JoinedCell(*result)


class RowTupleDataExportObjectRenderer(data_export.DataExportObjectRenderer):
    renders_type = "RowTuple"

    def GetState(self, item, **_):
        return dict(items=list(item))
