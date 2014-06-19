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
import gc
import logging
import time
import re
import string

from rekall import config
from rekall import obj
from rekall import utils
from rekall import registry


config.DeclareOption(
    "--renderer", default="TextRenderer", group="Interface",
    help="The renderer to use. e.g. (TextRenderer, "
    "JsonRenderer).")

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

    sort_key_func = None
    deferred_rows = None
    table_cls = None

    last_spin_time = 0
    last_gc_time = 0
    progress_interval = 0.2

    # This is used to ensure that renderers are always called as context
    # managers. This guarantees we call start() and end() automatically.
    _started = False

    def __init__(self, session=None):
        self.session = session

    def __enter__(self):
        self._started = True
        return self

    def __exit__(self, exc_type, exc_value, trace):
        self.end()

    def start(self, plugin_name=None, kwargs=None):
        """The method is called when new output is required.

        Metadata about the running plugin is provided so the renderer may log it
        if desired.

        Args:
           plugin_name: The name of the plugin which is running.
           kwargs: The args for this plugin.
        """
        _ = plugin_name
        _ = kwargs

        # This handles the progress messages from rekall for the duration of
        # the rendering.
        if self.session:
            self.session.progress.Register(id(self), self.RenderProgress)

        return self

    def end(self):
        """Tells the renderer that we finished using it for a while."""
        self._started = False
        if self.deferred_rows is not None:
            # Table was sorted. Render deferred rows now.
            self.flush_table()

        # Remove the progress handler from the session.
        if self.session:
            self.session.progress.UnRegister(id(self))

        self.flush()

    def write(self, data):
        """Renderer should write some data."""
        pass

    def section(self, name=None, width=50, keep_sort=False):
        """Start a new section.

        Sections are used to separate distinct entries (e.g. reports of
        different files).
        """

        if self.deferred_rows is not None:
            # Table is sorted. Print deferred rows from last section now.
            self.flush_table(keep_sort=keep_sort)

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
        if not self._started:
            raise RuntimeError("Writing to a renderer that is not started.")

        self.write(self.formatter.format(formatstring, *data))

    def flush(self):
        """Renderer should flush data."""
        pass

    def table_header(self, columns=None, suppress_headers=None, name=None,
                     sort=None, **kwargs):
        """Table header renders the title row of a table.

        This also stores the header types to ensure everything is formatted
        appropriately.  It must be a list of tuples rather than a dict for
        ordering purposes.

        Args:
          columns: A list of (name, cname, formatstring) tuples describing
            the table headers.

          suppress_headers: If True table headers will not be written (still
            useful for formatting).

          name: The name of this table.

          sort: Optional - tuple of cnames of columns to sort by. If sorting
          sorting is on, rendering of table rows will be deferred either
          until next call to table_header (or section) or until the plugin
          render function ends.
        """
        _ = name

        if not self._started:
            raise RuntimeError("Renderer is used without a context manager.")

        if self.deferred_rows is not None:
            # Previous table we rendered was sorted. Do deferred rendering now.
            self.flush_table()

        address_size = 14
        if (self.session and self.session.profile and
            self.session.profile.metadata("arch") == "I386"):
            address_size = 10

        self.table = self.table_cls(
            renderer=self, columns=columns, suppress_headers=suppress_headers,
            address_size=address_size, **kwargs
        )

        self.table.render_header()

        if sort:
            self.sort_key_func = self._build_sort_key_function(
                sort_cnames=sort,
                columns=columns,
            )
            self.deferred_rows = []

    @staticmethod
    def _build_sort_key_function(sort_cnames, columns):
        """Builds a function that takes a row and returns keys to sort on."""
        cnames_to_indices = {}
        for idx, (_, cname, _) in enumerate(columns):
            cnames_to_indices[cname] = idx

        sort_indices = [cnames_to_indices[x] for x in sort_cnames]

        # Row is a tuple of (values, kwargs) - hence row[0][index].
        return lambda row: [row[0][index] for index in sort_indices]

    def table_row(self, *args, **kwargs):
        """Outputs a single row of a table."""
        self.RenderProgress(message=None)

        if self.deferred_rows is not None:
            # Table rendering is being deferred for sorting.
            self.deferred_rows.append((args, kwargs))
        else:
            self.table.render_row(row=args, **kwargs)

    def flush_table(self, keep_sort=False):
        """If sorting is on, this will trigger deferred rendering."""
        self.deferred_rows.sort(key=self.sort_key_func)

        for row, kwargs in self.deferred_rows:
            self.table.render_row(
                row=row,
                **kwargs
            )

        if keep_sort:
            self.deferred_rows = []
        else:
            self.deferred_rows = None
            self.sort_key_func = None

    def record(self, record_data):
        """Writes a single complete record.

        A record consists of one object of related fields.

        Args:
          data: A list of tuples (name, short_name, formatstring, data)
        """
        for name, _, formatstring, data in record_data:
            self.format("%s: %s\n" % (name, formatstring), data)

        self.format("\n")

    def report_error(self, message):
        """Render the error in an appropriate way."""
        # By default just log the error. Visual renderers may choose to render
        # errors in a distinctive way.
        logging.error(message)

    def RenderProgress(self, *_, **kwargs):
        """Will be called to render a progress message to the user."""
        # Only write once per self.progress_interval.
        now = time.time()
        force = kwargs.get("force")

        # GC is expensive so we need to do it less frequently.
        if now > self.last_gc_time + 10:
            gc.collect()
            self.last_gc_time = now

        if force or now > self.last_spin_time + self.progress_interval:
            self.last_spin_time = now

            # Signal that progress must be written.
            return True

        return False

    def open(self, directory=None, filename=None, mode="rb"):
        """Opens a file for writing or reading."""
        _ = directory
        _ = filename
        _ = mode
        raise IOError("Renderer does not support writing to files.")


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

        m = re.match(r"\[addrpad\]", formatstring)
        if m:
            self.formatstring = "#0%sx" % self.address_size
            self.header_format = "^%ss" % self.address_size
            # Never elide addresses - makes them unreadable.
            self.table.elide = False
            return

        m = re.match(r"\[addr\]", formatstring)
        if m:
            self.formatstring = ">#%sx" % self.address_size
            self.header_format = "^%ss" % self.address_size
            self.table.elide = False
            return

        # Look for the wrap specifier.
        m = re.match(r"\[wrap:([^\]]+)\]", formatstring)
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
