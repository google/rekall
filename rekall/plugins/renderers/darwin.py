# Rekall Memory Forensics
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

"""This module implements renderers specific to darwin structures."""

from rekall import utils
from rekall.ui import text
from rekall.ui import json_renderer
from rekall.plugins.renderers import data_export


class ProcDataExport(data_export.DataExportBaseObjectRenderer):
    renders_type = "proc"

    def EncodeToJsonSafe(self, task, **_):
        result = super(ProcDataExport, self).EncodeToJsonSafe(task)
        result["Cybox"] = dict(
            type=u"ProcessObj:ProcessObjectType",
            Name=task.name,
            PID=task.pid,
            Creation_Time=task.p_start,
            Parent_PID=task.p_ppid,
            Image_Info=dict(
                type=u"ProcessObj:ImageInfoType",
                Path=task.p_comm,
                Command_Line=task.p_comm,
                File_Name=task.p_comm,
                )
            )

        res = json_renderer.JsonObjectRenderer.EncodeToJsonSafe(self, result)
        return res

    def Summary(self, item, **_):
        return "%s (%s)" % (item.get("Cybox", {}).get("Name", ""),
                            item.get("Cybox", {}).get("PID", ""))


class Proc_TextObjectRenderer(text.TextObjectRenderer):
    renders_type = "proc"
    renderers = ["TextRenderer", "TestRenderer"]

    def __init__(self, *args, **options):
        """We make a sub table for rendering the _EPROCESS."""
        self.name = options.pop("name", "proc")
        self.style = options.pop("style", "full")

        super(Proc_TextObjectRenderer, self).__init__(*args, **options)
        self.table = text.TextTable(
            columns=[
                dict(name=self.name,
                     style="address"),
                dict(name="Name", width=20, align="c"),
                dict(name="PID", width=5, align="r")],
            renderer=self.renderer,
            session=self.session)

    def render_header(self, **options):
        if self.style == "full":
            return self.table.render_header()
        else:
            result = text.Cell(self.name, width=40)
            result.append_line("-" * result.width)

            return result

    def render_row(self, target, **options):
        if self.style == "full":
            return self.table.get_row(target.obj_offset, target.name,
                                      target.pid)

        else:
            return text.Cell("%s %s (%d)" % (
                self.format_address(target.obj_offset),
                target.name, target.pid))
