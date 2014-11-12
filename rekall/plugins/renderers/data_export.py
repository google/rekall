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
from rekall.plugins.renderers import json_storage


class DataExportRenderer(json_renderer.JsonRenderer):
    """An exporter for data."""

    name = "data"

    def table_row(self, *args, **options):
        # Encode the options and merge them with the table row. This allows
        # plugins to send additional data about the row in options.
        result = self.encoder.Encode(options)
        for i, arg in enumerate(args):
            column_spec = self.table.column_specs[i].copy()
            column_spec.update(options)

            object_renderer = self.object_renderers[i]
            if object_renderer is not None:
                column_spec["type"] = object_renderer

            column_name = column_spec.get("cname", column_spec.get("name"))
            if column_name:
                result[column_name] = self.encoder.Encode(
                    arg, **column_spec)

        self.SendMessage(["r", result])


class NativeDataExportObjectRenderer(json_renderer.JsonObjectRenderer):
    renderers = ["DataExportRenderer"]

    def Summary(self, item, formatstring=None, header=False, **options):
        """Returns a short summary of the object.

        The summary is a short human readable string, describing the object.
        """
        if formatstring == "[addrpad]" and not header:
            return "%#014x" % item

        return item


class DataExportObjectRenderer(json_renderer.StateBasedObjectRenderer):
    renderers = ["DataExportRenderer"]


class DataExportNoneObjectRenderer(json_storage.NoneObjectRenderer):
    renderers = ["DataExportRenderer"]


class DataExportInstructionRenderer(DataExportObjectRenderer):
    renders_type = "Instruction"

    def GetState(self, item, **_):
        return dict(value=unicode(item))


class DataExportBaseObjectRenderer(DataExportObjectRenderer):
    renders_type = "BaseObject"

    def EncodeToJsonSafe(self, item, **options):
        result = super(DataExportBaseObjectRenderer, self).EncodeToJsonSafe(
            item, **options)

        result.update(offset=item.obj_offset,
                      type_name=unicode(item.obj_type),
                      name=unicode(item.obj_name),
                      vm=unicode(item.obj_vm))

        return result


class DataExportPointerObjectRenderer(DataExportBaseObjectRenderer):
    renders_type = "Pointer"

    def Summary(self, item, **options):
        """Returns the object formatted according to the column_spec."""
        item = item["target"]
        return self.FromEncoded(item, "DataExportRenderer")(
            self.renderer).Summary(item, **options)

    def EncodeToJsonSafe(self, item, **options):
        result = super(DataExportPointerObjectRenderer, self).EncodeToJsonSafe(
            item, **options)

        result["target"] = item.v()

        # Also encode the target object.
        target_obj = item.deref()
        target_obj_renderer = self.DelegateObjectRenderer(target_obj)
        result["target_obj"] = target_obj_renderer.EncodeToJsonSafe(target_obj)

        return result


class DataExportNativeTypeRenderer(DataExportObjectRenderer):
    renders_type = "NativeType"

    def EncodeToJsonSafe(self, item, **_):
        return item.v()


class DataExportEnumerationRenderer(DataExportObjectRenderer):
    """For enumerations store both their value and the enum name."""
    renders_type = "Enumeration"

    def GetState(self, item, **_):
        return dict(enum=unicode(item),
                    value=int(item))

    def Summary(self, item, **_):
        return item.get("enum", "")


class DataExportUnixTimestampObjectRenderer(DataExportObjectRenderer):
    renders_type = "UnixTimeStamp"

    def Summary(self, item, **_):
        return item.get("string_value", "")

    def GetState(self, item, **_):
        return dict(type_name="UnixTimeStamp",
                    epoch=item.v(),
                    string_value=unicode(item))
