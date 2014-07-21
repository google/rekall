# Rekall Memory Forensics
# Copyright (C) 2014 Michael Cohen
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

"""This module implements the data export renderer.

The data export renderer is a way of exporting structured data from Rekall. The
renderer is based on the JsonRenderer but has a different goal - while the
JsonRenderer is designed to be able to exactly recreate the objects in the
future the data export renderer aims to include useful information about
exported objects.

For example, in order to decode the JsonRenderer output one must have access to
the original image, since the decoder will generate the exact BaseObject()
instances that the encoder used.

Not so with the data exporter - the exported data contains a lot of additional
information about the exported objects. The exported data also omits information
which is not relevant without access to the original image.
"""

from rekall.ui import json_renderer


class DataExportRenderer(json_renderer.JsonRenderer):
    """An exporter for data."""

    name = "data"

    def table_row(self, *args, **options):
        result = {}
        for i, arg in enumerate(args):
            column = self.columns[i]
            object_renderer = self.object_renderers[i]

            column_name = column.get("cname", column.get("name"))
            if column_name:
                result[column_name] = self.encoder.Encode(
                    arg, type=object_renderer, **options)

        self.SendMessage(["r", result])



class DataExportObjectRenderer(json_renderer.JsonObjectRenderer):
    renderers = ["DataExportRenderer"]

class DataExportBaseObjectRenderer(DataExportObjectRenderer):
    renders_type = "BaseObject"

    def EncodeToJsonSafe(self, item, **_):
        return dict(offset=item.obj_offset,
                    type_name=unicode(item.obj_type),
                    name=unicode(item.obj_name),
                    vm=unicode(item.obj_vm),
                    )


class DataExportPointerObjectRenderer(DataExportObjectRenderer):
    renders_type = "Pointer"

    def EncodeToJsonSafe(self, item, **_):
        return dict(offset=item.obj_offset,
                    type_name=unicode(item.obj_type),
                    name=unicode(item.obj_name),
                    vm=unicode(item.obj_vm),
                    target=item.v()
                    )


class DataExportNativeTypeRenderer(DataExportObjectRenderer):
    renders_type = "NativeType"

    def EncodeToJsonSafe(self, item, **_):
        return item.v()


class DataExportUnixTimestampObjectRenderer(DataExportObjectRenderer):
    renders_type = "UnixTimeStamp"

    def EncodeToJsonSafe(self, item, **_):
        return dict(type_name="UnixTimeStamp",
                    value=item.v(),
                    string_value=unicode(item))

