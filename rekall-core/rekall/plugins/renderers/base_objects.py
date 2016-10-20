# -*- coding: utf-8 -*-

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

"""This module implements base object renderers."""

from rekall import utils

from rekall.ui import renderer as renderer_module
from rekall.ui import text


class PluginObjectTextRenderer(text.TextObjectRenderer):
    renders_type = "Plugin"

    def render_full(self, target, **_):
        return text.Cell(repr(target))

    def render_compact(self, target, **_):
        return text.Cell(target.name)


class BaseObjectTextRenderer(text.TextObjectRenderer):
    renders_type = "BaseObject"

    def render_address(self, target, **options):
        return text.Cell(
            self.format_address(target.obj_offset, **options)
        )

    def render_full(self, target, **options):
        result = text.Cell(unicode(target.v()), **options)
        return result

    def render_value(self, target, **_):
        return text.Cell(unicode(target.v()))


class StringTextRenderer(BaseObjectTextRenderer):
    renders_type = "String"

    def render_full(self, target, **_):
        return text.Cell(
            utils.SmartUnicode(target).split("\x00")[0] or u"")

    render_value = render_full
    render_compact = render_full


class NoneObjectTextRenderer(BaseObjectTextRenderer):
    """NoneObjects will be rendered with a single dash '-'."""
    renders_type = "NoneObject"

    def render_row(self, target, **_):
        return text.Cell("-")


class NoneTextRenderer(NoneObjectTextRenderer):
    renders_type = "NoneType"


class UnixTimestampObjectRenderer(BaseObjectTextRenderer):
    renders_type = "UnixTimeStamp"

    def render_row(self, target, details=False, **options):
        if details:
            return text.Cell(repr(target))

        if target != None:
            return text.Cell(unicode(target))

        return text.Cell("-")


class ArrotTimestampObjectRenderer(BaseObjectTextRenderer):
    renders_type = "Arrow"

    timeformat = "YYYY-MM-DD HH:mm:ss"

    def render_row(self, target, details=False, **options):
        if details:
            return text.Cell(target.isoformat())

        if target != None:
            return text.Cell(target.format(self.timeformat))

        return text.Cell("-")


class PythonBoolTextRenderer(text.TextObjectRenderer):
    renders_type = "bool"

    def render_full(self, target, **_):
        color = "GREEN" if target else "RED"
        return text.Cell(
            value=unicode(target),
            highlights=[(0, -1, color, None)])

    render_value = render_full
    render_compact = render_full


class NativeTypeTextRenderer(BaseObjectTextRenderer):
    renders_type = "NativeType"

    def render_address(self, target, width=None, **options):
        return text.Cell(
            self.format_address(target.v(), **options),
            width=width)


class BaseBoolTextRenderer(PythonBoolTextRenderer):
    renders_type = "Bool"

    def render_row(self, target, **kwargs):
        return super(BaseBoolTextRenderer, self).render_row(bool(target),
                                                            **kwargs)


class FlagsTextRenderer(BaseObjectTextRenderer):
    renders_type = "Flags"

    def render_full(self, target, **_):
        flags = []
        value = target.v()
        for k, v in sorted(target.maskmap.items()):
            if value & v:
                flags.append(k)

        return text.Cell(u', '.join(flags))

    def render_value(self, target, **_):
        return text.Cell(unicode(self.v()))

    def render_compact(self, target, **_):
        lines = self.render_full(target).lines
        if not lines:
            return text.Cell("-")

        elided = lines[0]
        if len(elided) > 40:
            elided = elided[:39] + u"…"

        return text.Cell(elided)


class EnumerationTextRenderer(BaseObjectTextRenderer):
    renders_type = "Enumeration"

    def render_full(self, target, **_):
        value = target.v()
        name = target.choices.get(utils.SmartStr(value), target.default) or (
            u"UNKNOWN (%s)" % utils.SmartUnicode(value))

        return text.Cell(name)

    render_compact = render_full


class DatetimeTextRenderer(text.TextObjectRenderer):
    renders_type = "datetime"

    def render_row(self, target, **_):
        return text.Cell(target.strftime("%Y-%m-%d %H:%M:%S%z"))


class PointerTextRenderer(NativeTypeTextRenderer):
    renders_type = "Pointer"

    def render_value(self, *args, **kwargs):
        return self.render_address(*args, **kwargs)

    def render_full(self, target, **_):
        target_obj = target.deref()
        if target_obj == None:
            return text.Cell("-")

        delegate_cls = renderer_module.ObjectRenderer.ForTarget(
            target_obj, renderer=self.renderer)

        return delegate_cls(session=self.session,
                            renderer=self.renderer).render_full(target_obj)

    def render_compact(self, target, **options):
        return text.Cell(
            "(%s *) %s" % (
                target.target,
                self.format_address(target.v(), **options))
        )


class ListRenderer(text.TextObjectRenderer):
    """Renders a list of other objects."""
    renders_type = ("list", "tuple", "set", "frozenset")

    def render_row(self, target, **options):
        width = options.pop("width", None)
        result = []
        for item in target:
            object_renderer = self.ForTarget(item, self.renderer)(
                session=self.session, renderer=self.renderer)

            options["wrap"] = False
            cell = object_renderer.render_row(item, **options)
            result.append("\\n".join(cell.lines).strip())

        return text.Cell(", ".join(result), width=width)


class VoidTextRenderer(PointerTextRenderer):
    renders_type = "Void"

    def render_full(self, target, **options):
        return text.Cell(
            "(void *) %s" % self.format_address(target.v(), **options))

    render_compact = render_full


class FunctionTextRenderer(BaseObjectTextRenderer):
    renders_type = "Function"

    def render_full(self, target, width=None, **_):
        table = text.TextTable(
            columns=[
                dict(name="Address", style="address"),
                dict(name="OpCode", width=16),
                dict(name="Op", width=width)
            ],
            renderer=self.renderer,
            session=self.session)

        result = []
        for instruction in target.disassemble():
            result.append(unicode(table.get_row(
                instruction.address, instruction.hexbytes, instruction.text)))

        return text.Cell("\n".join(result))

    def render_compact(self, target, **options):
        return text.Cell(self.format_address(target.obj_offset, **options))

    render_value = render_compact


class StructTextRenderer(text.TextObjectRenderer):
    renders_type = "Struct"
    DEFAULT_STYLE = "compact"
    renderers = ["TextRenderer", "TestRenderer"]
    COLUMNS = None
    table = None

    def __init__(self, *args, **kwargs):
        self.columns = kwargs.pop("columns", self.COLUMNS)

        super(StructTextRenderer, self).__init__(*args, **kwargs)

        if self.columns:
            self.table = text.TextTable(
                columns=self.columns,
                renderer=self.renderer,
                session=self.session)

    def render_full(self, target, **_):
        """Full render of a struct outputs every field."""
        result = repr(target) + "\n"
        width_name = 0

        fields = []
        # Print all the fields sorted by offset within the struct.
        for k in target.members:
            width_name = max(width_name, len(k))
            obj = getattr(target, k)
            if obj == None:
                obj = target.m(k)

            fields.append(
                (getattr(obj, "obj_offset", target.obj_offset) -
                 target.obj_offset, k, utils.SmartUnicode(repr(obj))))

        fields.sort()

        result = result + u"\n".join(
            [u"  0x%02X %s%s %s" % (offset, k, " " * (width_name - len(k)), v)
             for offset, k, v in fields]) + "\n"

        return text.Cell(result)

    def render_header(self, **kwargs):
        style = kwargs.get("style", self.DEFAULT_STYLE)

        if style == "compact" and self.table:
            return self.table.render_header()
        else:
            return super(StructTextRenderer, self).render_header(**kwargs)

    def render_compact(self, target, **_):
        """Compact render outputs only a few select columns, or repr."""
        if not self.table:
            return self.render_repr(target)

        values = []
        for column in self.columns:
            name = column.get("name")
            if not name:
                raise ValueError(
                    "Column spec %r doesn't specify 'name'." % column)

            values.append(getattr(target, name))

        return self.table.get_row(*values)

    def render_repr(self, target, **_):
        """Explicitly just render the repr."""
        return text.Cell(repr(target))


class AttributeDictTextRenderer(text.TextObjectRenderer):
    renders_type = "dict"
    renderers = ["TextRenderer", "TestRenderer"]

    def __init__(self, *args, **kwargs):
        """We make a sub table for key, values."""
        super(AttributeDictTextRenderer, self).__init__(*args, **kwargs)
        self.table = text.TextTable(
            columns=[
                dict(name="Key"),
                dict(name="Value"),
            ],
            auto_widths=True,
            renderer=self.renderer,
            session=self.session)

    def render_row(self, item, **options):
        result = []
        for key, value in sorted(item.iteritems()):
            result.append(self.table.get_row(key, value))

        return text.StackedCell(*result)


class HexIntegerTextRenderer(text.TextObjectRenderer):
    renders_type = "HexInteger"
    renderers = ["TextRenderer", "TestRenderer"]

    def render_row(self, item, **options):
        return text.Cell(hex(item), align="r")


class TextHexdumpRenderer(text.TextObjectRenderer):
    renders_type = "HexDumpedString"
    renderers = ["TextRenderer", "TestRenderer"]

    def render_row(self, item, hex_width=None, **options):
        if hex_width is None:
            hex_width = (item.options.get("hex_width") or
                         self.session.GetParameter("hexdump_width", 8))

        data = item.value
        highlights = item.highlights or []
        hex_highlights = []
        for x, y, f, b in highlights:
            hex_highlights.append((3 * x, 3 * y, f, b))

        hexcell = text.Cell(
            width=hex_width * 3, highlights=hex_highlights,
            colorizer=self.renderer.colorizer)
        datacell = text.Cell(
            width=hex_width, highlights=highlights,
            colorizer=self.renderer.colorizer)

        for _, hexdata, translated_data in utils.Hexdump(data, width=hex_width):
            hexcell.append_line(hexdata)
            datacell.append_line("".join(translated_data))

        return text.JoinedCell(hexcell, datacell)
