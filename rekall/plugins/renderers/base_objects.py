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

from rekall.ui import text


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
    renderers = ["TextRenderer"]

    def render_row(self, target, details=False, **options):
        if details:
            return text.Cell(repr(target))

        if target:
            dt = target.as_datetime()
            if dt:
                return text.Cell(target.display_datetime(dt))

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
            width=width
        )


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
        renderer = target_obj.get_text_renderer()
        return renderer.render_full(target_obj)

    def render_compact(self, target, **options):
        return text.Cell(
            "(%s *) %s" % (
                target.target,
                self.format_address(target.v(), **options))
        )


class ListRenderer(text.TextObjectRenderer):
    """Renders a long as an address."""
    renders_type = ("list", "tuple")

    def render_row(self, target, **options):
        result = []
        for item in target:
            object_renderer = self.ForTarget(item, self.renderer)(
                session=self.session, renderer=self.renderer)
            result.append(object_renderer.render_row(item, **options))
            result.append(text.Cell(","))

        if result:
            result.pop(-1)

        return text.JoinedCell(*result)


class VoidTextRenderer(PointerTextRenderer):
    renders_type = "Void"

    def render_full(self, target, **options):
        return text.Cell(
            "(void) %s" % self.format_address(target.v(), **options)
        )

    render_compact = render_full


class FunctionTextRenderer(BaseObjectTextRenderer):
    renders_type = "Function"

    def render_full(self, target, **_):
        if target.mode == "AMD64":
            format_string = "%0#14x  %s"
        else:
            format_string = "%0#10x  %s"

        result = []
        for offset, _, instruction in target.Disassemble():
            result.append(format_string % (offset, instruction))

        return text.Cell("\n".join(result))

    def render_compact(self, target, **options):
        return text.Cell(self.format_address(target.obj_offset, **options))

    render_value = render_compact


class StructTextRenderer(text.TextObjectRenderer):
    renders_type = "Struct"
    DEFAULT_STYLE = "compact"

    def render_full(self, target, **_):
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

    def render_compact(self, target, **_):
        return text.Cell(repr(target))
