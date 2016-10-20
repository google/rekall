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

"""This module implements renderers specific to windows structures."""

from rekall import utils
from rekall.ui import text
from rekall.ui import json_renderer
from rekall.plugins.renderers import data_export


class EPROCESSDataExport(data_export.DataExportBaseObjectRenderer):
    renders_type = "_EPROCESS"

    def EncodeToJsonSafe(self, task, **_):
        result = super(EPROCESSDataExport, self).EncodeToJsonSafe(task)
        process_params = task.Peb.ProcessParameters
        result["Cybox"] = dict(
            type=u"ProcessObj:ProcessObjectType",
            Name=task.name,
            PID=task.pid,
            Creation_Time=task.CreateTime,
            Parent_PID=task.InheritedFromUniqueProcessId,
            Image_Info=dict(
                type=u"ProcessObj:ImageInfoType",
                Path=process_params.ImagePathName,
                Command_Line=process_params.CommandLine,
                TrustedPath=task.FullPath,
                File_Name=task.SeAuditProcessCreationInfo.ImageFileName.Name,
                )
            )

        res = json_renderer.JsonObjectRenderer.EncodeToJsonSafe(self, result)
        return res

    def Summary(self, item, **_):
        return "%s (%s)" % (item.get("Cybox", {}).get("Name", ""),
                            item.get("Cybox", {}).get("PID", ""))


class UNICODE_STRING_Text(text.TextObjectRenderer):
    renders_type = "_UNICODE_STRING"
    renderers = ["TextRenderer", "TestRenderer", "WideTextRenderer"]

    def render_compact(self, target, width=None, **_):
        return text.Cell(unicode(target), width=width)


class SID_Text(UNICODE_STRING_Text):
    renders_type = "_SID"


class UNICODE_STRINGDataExport(data_export.DataExportBaseObjectRenderer):
    renders_type = "_UNICODE_STRING"

    def EncodeToJsonSafe(self, item, **_):
        return unicode(item)


class STRINGDataExport(UNICODE_STRINGDataExport):
    renders_type = "String"

    def EncodeToJsonSafe(self, item, **_):
        return utils.SmartStr(item)


class EPROCESS_TextObjectRenderer(text.TextObjectRenderer):
    renders_type = "_EPROCESS"
    renderers = ["TextRenderer", "TestRenderer"]

    def __init__(self, *args, **options):
        """We make a sub table for rendering the _EPROCESS."""
        self.name = options.pop("name", "_EPROCESS")

        super(EPROCESS_TextObjectRenderer, self).__init__(*args, **options)

        # pstree requests light output so we ovverride the style
        self.output_style = options.pop("style", self.output_style)

        if self.output_style == "full":
            self.table = text.TextTable(
                columns=[
                    dict(name=self.name,
                         formatstring="[addrpad]"),
                    dict(name="name", width=20),
                    dict(name="fullpath", width=60),
                    dict(name="pid", width=5, align="r"),
                    dict(name="ppid", width=5, align="r")],
                renderer=self.renderer,
                session=self.session)
        else:
            self.table = text.TextTable(
                columns=[
                    dict(name=self.name,
                         formatstring="[addrpad]"),
                    dict(name="name", width=20),
                    dict(name="pid", width=5, align="r")],
                renderer=self.renderer,
                session=self.session)

    def render_header(self, **options):
        if self.output_style in ["full", "concise"]:
            return self.table.render_header()
        else:
            result = text.Cell(self.name, width=40)
            result.append_line("-" * result.width)

            return result

    def render_row(self, target, **options):
        if self.output_style == "full":
            return self.table.get_row(
                target.obj_offset, target.name, target.FullPath, target.pid,
                target.InheritedFromUniqueProcessId)
        elif self.output_style == "concise":
            return self.table.get_row(target.obj_offset, target.name,
                                      target.pid)
        else:
            return text.Cell(u"%s %s (%d)" % (
                self.format_address(target.obj_offset),
                target.name, target.pid))


class EPROCESS_WideTextObjectRenderer(EPROCESS_TextObjectRenderer):
    renders_type = "_EPROCESS"
    renderers = ["WideTextRenderer"]

    def render_row(self, target, **_):
        return text.Cell(
            self.formatter.format(u"{0:s} Pid: {1:s} (@{2:#x})",
                                  target.name, target.pid, target))


class MMVAD_FLAGS_TextRenderer(text.TextObjectRenderer):
    renders_type = ("_MMVAD_FLAGS", "_MMVAD_FLAGS2", "_MMSECTION_FLAGS")
    renderers = ["TextRenderer", "TestRenderer"]

    def render_compact(self, target, **_):
        result = []
        for name in sorted(target.members):
            if name.endswith("Enum"):
                continue

            try:
                attribute = getattr(target, name)
                if attribute.v():
                    result.append(u"%s: %s" % (name, attribute))
            except AttributeError:
                pass

        return text.Cell(", ".join(result))
