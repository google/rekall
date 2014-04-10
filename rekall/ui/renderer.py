# Rekall Memory Forensics
# Copyright (C) 2012 Michael Cohen
# Copyright 2013 Google Inc. All Rights Reserved.
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

"""This module implements a text based render.

A renderer is used by plugins to produce formatted output.
"""

import re
import os
import string
import sys

from rekall import config
from rekall import obj
from rekall import utils
from rekall import registry


config.DeclareOption(
    "--pager", default=os.environ.get("PAGER"), group="Interface",
    help="The pager to use when output is larger than a screen full.")

config.DeclareOption(
    "--paging_limit", default=None, group="Interface", type=int,
    help="The number of output lines before we invoke the pager.")

config.DeclareOption(
    "--renderer", default="TextRenderer", group="Interface",
    help="The renderer to use. e.g. (TextRenderer, "
    "JsonRenderer).")

config.DeclareOption(
    "--nocolors", default=False, action="store_true", group="Interface",
    help="If set suppress outputting colors.")

config.DeclareOption(
    "--logging", default="error", choices=[
        "debug", "info", "warning", "critical", "error"],
    help="Logging level to show messages.")

config.DeclareOption(
    "-v", "--verbose", default=False, action="store_true",
    help="Set logging to debug level.")

config.DeclareOption(
    "--debug", default=False, action="store_true",
    help="If set we break into the debugger on error conditions.")


class UnicodeWrapper(object):
    """A wrapper around a file like object which guarantees writes in utf8."""

    def __init__(self, fd, encoding='utf8'):
        self.fd = fd
        self.encoding = encoding

    def write(self, data):
        data = utils.SmartUnicode(data).encode(self.encoding, "replace")
        self.fd.write(data)

    def flush(self):
        self.fd.flush()

    def isatty(self):
        return self.fd.isatty()


class Formatter(string.Formatter):
    """A formatter which supports extended formating specs."""
    # This comes from http://docs.python.org/library/string.html
    # 7.1.3.1. Format Specification Mini-Language
    standard_format_specifier_re = re.compile(r"""
(?P<fill>[^{}<>=^bcdeEfFgGnLosxX])?   # The fill parameter. This can not be a
                                     # format string or it is ambiguous.
(?P<align>[<>=^])?     # The alignment.
(?P<sign>[+\- ])?      # Sign extension.
(?P<hash>\#)?          # Hash means to preceed the whole thing with 0x.
(?P<zerofill>0)?       # Should numbers be zero filled.
(?P<width>\d+)?        # The minimum width.
(?P<comma>,)?
(?P<precision>.\d+)?   # Precision
(?P<type>[bcdeEfFgGnosxXL%])?  # The format string (Not all are supported).
""", re.X)

    def format_field(self, value, format_spec):
        """Format the value using the format_spec.

        The aim of this function is to remove the delegation to __format__() on
        the object. For our needs we do not want the object to be responsible
        for its own formatting since it is not aware of the renderer itself.

        A rekall.obj.BaseObject instance must support the following
        formatting operations:

        __unicode__
        __str__
        __repr__
        and may also support __int__ (for formatting in hex).
        """
        m = self.standard_format_specifier_re.match(format_spec)
        if not m:
            raise re.error("Invalid regex")

        fields = m.groupdict()

        # Format the value according to the basic type.
        type = fields["type"] or "s"
        try:
            value = getattr(
                self, "format_type_%s" % type)(value, fields)
        except AttributeError:
            raise re.error("No formatter for type %s" % type)

        try:
            return format(value, format_spec)
        except ValueError:
            return str(value)

    def format_type_s(self, value, fields):
        try:
            # This is required to allow BaseObject to pass non unicode returns
            # from __unicode__ (e.g. NoneObject).
            result = value.__unicode__()
        except AttributeError:
            result = utils.SmartUnicode(value)

        # None objects get a -.
        if result is None or isinstance(result, obj.NoneObject):
            return "-" * int(fields['width'] or "1")

        return result

    def format_type_x(self, value, fields):
        _ = fields
        return int(value)

    def format_type_X(self, value, fields):
        _ = fields
        return int(value)

    def format_type_r(self, value, fields):
        _ = fields
        return repr(value)

    def format_type_f(self, value, fields):
        _ = fields
        if isinstance(value, (float, int, long)):
            return float(value)

        return value

    def format_type_L(self, value, fields):
        """Support extended list format."""
        _ = fields
        return ", ".join([utils.SmartUnicode(x) for x in value])


class BaseRenderer(object):
    """All renderers inherit from this."""

    __metaclass__ = registry.MetaclassRegistry

    isatty = False
    paging_limit = None

    def __init__(self, session=None, fd=None, paging_limit=None):
        self.session = session

        # Make sure that our output is unicode safe.
        self.fd = UnicodeWrapper(fd or sys.stdout)

        if self.fd.isatty():
            self.paging_limit = paging_limit
            self.isatty = True

        self.formatter = Formatter()

    def start(self, plugin_name=None, kwargs=None):
        """The method is called when new output is required.

        Metadata about the running plugin is provided so the renderer may log it
        if desired.

        Args:
           plugin_name: The name of the plugin which is running.
           kwargs: The args for this plugin.
        """
        pass

    def end(self):
        """Tells the renderer that we finished using it for a while."""
        pass

    def write(self, data):
        """Renderer should write some data."""
        pass

    def section(self, name=None, width=50):
        """Start a new section.

        Sections are used to separate distinct entries (e.g. reports of
        different files).
        """
        if name is None:
            self.write("*" * width + "\n")
            return

        pad_len = width - len(name) - 2  # 1 space on each side.
        padding = "*" * (pad_len / 2)  # Name is centered.

        self.write("{} {} {}\n".format(padding, name, padding))

    def format(self, formatstring, *data):
        """Write formatted data.

        For renderers that need access to the raw data (e.g. to check for
        NoneObjects), it is preferred to call this method directly rather than
        to format the string in the plugin itself.

        By default we just call the format string directly.
        """
        self.write(self.formatter.format(formatstring, *data))

    def flush(self):
        """Renderer should flush data."""

    def table_header(self, title_format_list=None, suppress_headers=False,
                     name=None):
        """Table header renders the title row of a table.

        This also stores the header types to ensure everything is formatted
        appropriately.  It must be a list of tuples rather than a dict for
        ordering purposes.

        Args:
           title_format_list: A list of (Name, formatstring) tuples describing
              the table headers.

           suppress_headers: If True table headers will not be written (still
              useful for formatting).

           name: The name of this table.
        """

    def table_row(self, *args, **kwargs):
        """Outputs a single row of a table."""
        self.table.render_row(row=args, **kwargs)

    def record(self, record_data):
        """Writes a single complete record.

        A record consists of one object of related fields.

        Args:
          data: A list of tuples (name, short_name, formatstring, data)
        """
        for name, _, formatstring, data in record_data:
            self.format("%s: %s\n" % (name, formatstring), data)

        self.format("\n")

    def color(self, target, **kwargs):
        return self.colorizer.Render(target, **kwargs)


class BaseColumn(object):
    """Things that all columnae have in common."""

    def __init__(self, name=None, cname=None, formatstring="s",
                 address_size=14, header_format=None, table=None):
        self.name = name or "-"
        self.cname = cname or "-"
        self.table = table
        self.wrap = None

        # How many places should addresses be padded?
        self.address_size = address_size
        self.parse_format(
            formatstring=formatstring,
            header_format=header_format,
        )

        # The format specifications are a dict.
        self.formatter = Formatter()
        self.header_width = 0

    def parse_format(self, formatstring=None, header_format=None):
        """Parse the format string into the format specification.

        We support some extended forms of format string which we process
        especially here:

        [addrpad] - This is a padded address to width self.address_size.
        [addr] - This is a non padded address.
        [wrap:width] - This wraps a stringified version of the target in the
           cell.
        """
        # Leading ! turns off eliding.
        if formatstring.startswith("!"):
            self.table.elide = True
            formatstring = formatstring[1:]

        # This means unlimited width.
        if formatstring == "":
            self.header_format = self.formatstring = ""

            # Eliding is not possible without column width limits.
            self.table.elide = False
            return

        m = re.search(r"\[addrpad\]", formatstring)
        if m:
            self.formatstring = "#0%sx" % self.address_size
            self.header_format = "^%ss" % self.address_size
            # Never elide addresses - makes them unreadable.
            self.table.elide = False
            return

        m = re.search(r"\[addr\]", formatstring)
        if m:
            self.formatstring = ">#%sx" % self.address_size
            self.header_format = "^%ss" % self.address_size
            self.table.elide = False
            return

        # Look for the wrap specifier.
        m = re.search(r"\[wrap:([^\]]+)\]", formatstring)
        if m:
            self.formatstring = "s"
            self.wrap = int(m.group(1))
            self.header_format = "<%ss" % self.wrap
            return

        # Fall through to a simple format specifier.
        self.formatstring = formatstring

        if header_format is None:
            self.header_format = re.sub("[Xx]", "s", formatstring)


class BaseTable(object):
    """Things that all tables have in common."""

    column_class = BaseColumn

    def __init__(self, columns=None, renderer=None, address_size=14,
                 suppress_headers=False):
        self.columns = [
            self.column_class(*args, address_size=address_size, table=self)
            for args in columns
        ]

        self.renderer = renderer
        self.suppress_headers = suppress_headers

    def render_header(self):
        pass

    def render_row(self, row=None):
        pass

