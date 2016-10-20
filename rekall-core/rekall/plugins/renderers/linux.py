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

"""This module implements renderers specific to Linux structures."""

import os

from rekall.ui import json_renderer
from rekall.ui import text
from rekall.plugins.addrspaces import amd64
from rekall.plugins.renderers import base_objects
from rekall.plugins.renderers import data_export


class kuid_t_TextObjectRenderer(text.TextObjectRenderer):
    renders_type = "kuid_t"
    renderers = ["TextRenderer", "TestRenderer", "WideTextRenderer"]

    def render_row(self, target, **_):
        return text.Cell(unicode(target))

class kgid_t_TextObjectRenderer(kuid_t_TextObjectRenderer):
    renders_type = "kgid_t"


class kuid_t_JsonObjectRenderer(json_renderer.JsonObjectRenderer):
    renders_type = ["kuid_t", "kgid_t"]
    renderers = ["JsonRenderer", "DataExportRenderer"]

    def EncodeToJsonSafe(self, task, **_):
        return task.val.v()


class XenM2PMapperObjectRenderer(json_renderer.JsonObjectRenderer):
    renders_type = "XenM2PMapper"

    def EncodeToJsonSafe(self, item, **_):
        result = {}
        result["m2p_map"] = dict(item)
        result["mro"] = ":".join(self.get_mro(item))

        return result

    def DecodeFromJsonSafe(self, value, _):
        return amd64.XenM2PMapper(value["m2p_map"])


class TaskStruct_TextObjectRenderer(base_objects.StructTextRenderer):
    renders_type = "task_struct"
    COLUMNS = [
        dict(style="address", name="obj_offset"),
        dict(width=20, align="l", name="name"),
        dict(width=6, align="r", name="pid")
    ]


class TaskStruct_DataExport(data_export.DataExportBaseObjectRenderer):
    renders_type = "task_struct"

    def EncodeToJsonSafe(self, task, **_):
        result = super(TaskStruct_DataExport, self).EncodeToJsonSafe(task)
        fullpath = task.get_path(task.mm.m("exe_file"))
        result["Cybox"] = dict(
            type=u"ProcessObj:ProcessObjectType",
            Name=task.name,
            PID=task.pid,
            Creation_Time=task.task_start_time,
            Parent_PID=task.parent.pid,
            Image_Info=dict(
                type=u"ProcessObj:ImageInfoType",
                Path=fullpath,
                Command_Line=task.commandline,
                TrustedPath=fullpath,
                File_Name=os.path.basename(fullpath),
                )
            )

        res = json_renderer.JsonObjectRenderer.EncodeToJsonSafe(self, result)
        return res

    def Summary(self, item, **_):
        return "%s (%s)" % (item.get("Cybox", {}).get("Name", ""),
                            item.get("Cybox", {}).get("PID", ""))
