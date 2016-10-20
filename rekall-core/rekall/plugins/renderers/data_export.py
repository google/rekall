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

import datetime
import pytz

from rekall import utils

from rekall.ui import renderer
from rekall.ui import json_renderer

from rekall.plugins.renderers import json_storage


# Copy many of the normal json object renderers.
renderer.CopyObjectRenderers((
    json_renderer.StringRenderer,
    json_storage.ArrowObjectRenderer,
    json_storage.AttributeDictObjectRenderer,
    json_storage.BaseAddressSpaceObjectRenderer,
    json_storage.FileAddressSpaceObjectRenderer,
    json_storage.IA32PagedMemoryObjectRenderer,
    json_storage.JsonAttributedStringRenderer,
    json_storage.JsonEnumerationRenderer,
    json_storage.JsonFormattedAddress,
    json_storage.JsonHexdumpRenderer,
    json_storage.JsonInstructionRenderer,
    json_storage.NoneObjectRenderer,
    json_storage.ProfileObjectRenderer,
    json_storage.SessionObjectRenderer,
    json_storage.SetObjectRenderer,
    json_storage.SlottedObjectObjectRenderer,
    json_storage.UnixTimestampJsonObjectRenderer,
), renderer="DataExportRenderer")


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

            column_name = column_spec["name"]
            if column_name:
                result[column_name] = self.encoder.Encode(
                    arg, **column_spec)

        self.SendMessage(["r", result])


class NativeDataExportObjectRenderer(json_renderer.JsonObjectRenderer):
    """This is the fallback for all objects without a dedicated renderer."""
    renderers = ["DataExportRenderer"]

    def Summary(self, item, formatstring=None, header=False, **options):
        """Returns a short summary of the object.

        The summary is a short human readable string, describing the object.
        """
        try:
            if formatstring == "[addrpad]" and not header:
                return "%#014x" % item
        except TypeError:
            pass

        # Since we are the default renderer we must ensure this works.
        return utils.SmartStr(item)


class DataExportObjectRenderer(json_renderer.StateBasedObjectRenderer):
    renderers = ["DataExportRenderer"]


class DataExportTimestampObjectRenderer(DataExportObjectRenderer):
    renders_type = "datetime"
    renderers = ["DataExportRenderer"]

    EPOCH = datetime.datetime(1970, 1, 1, 0, 0, 0, 0, pytz.UTC)

    def GetState(self, item, **_):
        return dict(epoch=(item - self.EPOCH).total_seconds(),
                    string_value=item.strftime("%Y-%m-%d %H:%M:%S%z"))


class DataExportBaseObjectRenderer(DataExportObjectRenderer):
    renders_type = "BaseObject"

    def GetState(self, item, **options):
        result = super(DataExportBaseObjectRenderer, self).GetState(
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

    def GetState(self, item, **options):
        result = super(DataExportPointerObjectRenderer, self).GetState(
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


class DataExportRDFValueObjectRenderer(DataExportBaseObjectRenderer):
    renders_type = "RDFValue"

    def Summary(self, item, **_):
        return utils.SmartStr(item.get("str", ""))

    def GetState(self, item, **options):
        return dict(str=item.SerializeToString())


class DataExportPhysicalAddressContextObjectRenderer(
        DataExportRDFValueObjectRenderer):
    renders_type = "PhysicalAddressContext"

    def Summary(self, item, **_):
        return utils.SmartStr(item.get("str", ""))

    def GetState(self, item, **options):
        return item.summary()
