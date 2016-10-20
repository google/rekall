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

from rekall.ui import json_renderer

from rekall.ui import text
from rekall.plugins.renderers import base_objects
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
                File_Name=task.p_comm))

        res = json_renderer.JsonObjectRenderer.EncodeToJsonSafe(self, result)
        return res

    def Summary(self, item, **_):
        return "%s (%s)" % (item.get("Cybox", {}).get("Name", ""),
                            item.get("Cybox", {}).get("PID", ""))


class Fileproc_TextObjectRenderer(base_objects.StructTextRenderer):
    renders_type = "fileproc"

    COLUMNS = [
        dict(name="human_type", width=15),
        dict(name="human_name", width=40)
    ]


class Vnode_TextObjectRenderer(base_objects.StructTextRenderer):
    renders_type = "vnode"

    COLUMNS = [
        dict(name="obj_offset", style="address"),
        dict(name="full_path", width=40, nowrap=True)
    ]


class Clist_TextObjectRenderer(base_objects.StructTextRenderer):
    renders_type = "clist"

    COLUMNS = [
        dict(name="obj_offset", style="address"),
        dict(name="recovered_contents", width=34)
    ]


class Tty_TextObjectRenderer(base_objects.StructTextRenderer):
    renders_type = "tty"

    COLUMNS = [
        dict(style="address", name="obj_offset"),
        dict(type="vnode", name="vnode"),
        dict(type="clist", name="input_buffer",
             columns=[dict(name="recovered_contents",
                           width=34)]),
        dict(type="clist", name="output_buffer",
             columns=[dict(name="recovered_contents",
                           width=34)])
    ]


class Session_TextObjectRenderer(base_objects.StructTextRenderer):
    renders_type = "session"

    COLUMNS = [
        dict(name="obj_offset", style="address"),
        dict(name="s_sid"),
        dict(name="s_leader", type="proc",
             columns=[dict(name="pid"),
                      dict(name="command", width=30)]),
        dict(name="s_login", width=20, nowrap=True)
    ]


class Socket_TextObjectRenderer(base_objects.StructTextRenderer):
    renders_type = "socket"

    COLUMNS = [
        dict(name="obj_offset", style="address"),
        dict(name="last_pid", width=10),
        dict(name="human_type", width=20),
        dict(name="human_name", width=60)
    ]


class Rtentry_TextObjectRenderer(base_objects.StructTextRenderer):
    renders_type = "rtentry"

    COLUMNS = [
        dict(name="source_ip", type="sockaddr", width=18),
        dict(name="dest_ip", type="sockaddr", width=18),
        dict(name="name", align="c"),
        dict(name="sent", width=8, align="r"),
        dict(name="rx", width=8, align="r"),
        dict(name="base_calendartime", width=30, align="c"),
        dict(name="rt_expire", align="r"),
        dict(name="delta", align="r")
    ]


class Sockaddr_TextObjectRenderer(text.TextObjectRenderer):
    renders_type = "sockaddr"

    def render_full(self, target, **_):
        return text.Cell(target.address)


class Zone_TextObjectRenderer(base_objects.StructTextRenderer):
    renders_type = "zone"
    COLUMNS = [
        dict(name="name", width=20),
        dict(name="count_active", width=12),
        dict(name="count_free", width=12),
        dict(name="elem_size", width=12),
        dict(name="tracks_pages", width=12),
        dict(name="allows_foreign", width=12)
    ]


class Ifnet_TextObjectRenderer(base_objects.StructTextRenderer):
    renders_type = "ifnet"
    COLUMNS = [
        dict(name="name", width=12),
        dict(name="l2_addr", width=18),
        dict(name="ipv4_addr", width=16),
        dict(name="ipv6_addr", width=40)
    ]


class Proc_TextObjectRenderer(base_objects.StructTextRenderer):
    renders_type = "proc"
    COLUMNS = [
        dict(style="address", name="obj_offset"),
        dict(width=20, align="l", name="name"),
        dict(width=5, align="r", name="pid")
    ]
