# Volatility
# Copyright (C) 2012 Michael Cohen
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
import logging
import json
import re
import os
import string
import subprocess
import sys
import textwrap
import time

from volatility import obj
from volatility import utils
from volatility import registry
from volatility import constants


class Pager(object):
    """A wrapper around a pager.

    The pager can be specified by the session. (eg. session.pager = 'less') or
    in an PAGER environment var.
    """
    # Default encoding is utf8
    encoding = "utf8"

    def __init__(self, session=None, encoding=None):
        # More is the least common denominator of pagers :-(. Less is better,
        # but most is best!
        pager = session.pager or os.environ.get("PAGER")
        self.encoding = encoding or session.encoding or sys.stdout.encoding
        self.pager = subprocess.Popen(pager, shell=True, stdin=subprocess.PIPE,
                                      bufsize=10240)

    def write(self, data):
        # Encode the data according to the output encoding.
        data = utils.SmartUnicode(data).encode(self.encoding, "replace")
        try:
            self.pager.stdin.write(data)
            self.pager.stdin.flush()

        # This can happen if the pager disappears in the middle of the write.
        except IOError:
            self.flush()

    def flush(self):
        """Wait for the pager to be exited."""
        self.pager.communicate()


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




class Formatter(string.Formatter):
    """A formatter which supports extended formating specs."""
    # This comes from http://docs.python.org/library/string.html
    # 7.1.3.1. Format Specification Mini-Language
    standard_format_specifier_re = re.compile("""
(?P<fill>[^{}<>=^])?   # The fill parameter.
(?P<align>[<>=^])?     # The alignment.
(?P<sign>[+\- ])?      # Sign extension.
(?P<hash>\#)?          # Hash means to preceed the whole thing with 0x.
(?P<zerofill>0)?       # Should numbers be zero filled.
(?P<width>\d+)?        # The minimum width.
(?P<comma>,)?
(?P<precision>.\d+)?   # Precision
(?P<type>[bcdeEfFgGnosxX%])?  # The format string (Not all are supported).
""", re.X)

    def format_field(self, value, format_spec):
        """Format the value using the format_spec.

        The aim of this function is to remove the delegation to __format__() on
        the object. For our needs we do not want the object to be responsible
        for its own formatting since it is not aware of the renderer itself.

        A volatility.obj.BaseObject instance must support the following
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
            value = getattr(self, "format_type_%s" % type)(value, fields)
        except AttributeError:
            raise re.error("No formatter for type %s" % type)

        return format(value, format_spec)

    def format_type_s(self, value, fields):
        try:
            # This is required to allow BaseObject to pass non unicode returns
            # from __unicode__ (e.g. NoneObject).
            result = value.__unicode__()
        except AttributeError:
            result = unicode(value)

        # None objects get a -.
        if result is None or isinstance(result, obj.NoneObject):
            return "-" * int(fields['width'] or "1")

        return result

    def format_type_x(self, value, fields):
        return int(value)

    def format_type_X(self, value, fields):
        return int(value)

    def format_type_r(self, value, fields):
        return repr(value)


class TextColumn(object):
    """An implementation of a Column."""

    def __init__(self, name=None, cname=None, formatstring="s", address_size=14,
                 header_format=None, elide=False, **kwargs):
        self.name = name or "-"
        self.cname = cname or "-"
        self.elide = elide
        self.wrap = None

        # How many places should addresses be padded?
        self.address_size = address_size
        self.parse_format(formatstring=formatstring,
                          header_format=header_format)

        # The format specifications is a dict.
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
            self.elide = True
            formatstring = formatstring[1:]

        # This means unlimited width.
        if formatstring == "":
            self.header_format = self.formatstring = ""

            # Eliding is not possible without column width limits.
            self.elide = False
            return

        m = re.search("\[addrpad\]", formatstring)
        if m:
            self.formatstring = "#0%sx" % self.address_size
            self.header_format = "^%ss" % self.address_size
            # Never elide addresses - makes them unreadable.
            self.elide = False
            return

        m = re.search("\[addr\]", formatstring)
        if m:
            self.formatstring = ">#%sx" % self.address_size
            self.header_format = "^%ss" % self.address_size
            self.elide = False
            return

        # Look for the wrap specifier.
        m = re.search("\[wrap:([^\]]+)\]", formatstring)
        if m:
            self.formatstring = "s"
            self.wrap = int(m.group(1))
            self.header_format = "<%ss" % self.wrap
            return

        # Fall through to a simple format specifier.
        self.formatstring = formatstring

        if header_format is None:
            self.header_format = re.sub("[Xx]", "s", formatstring)

    def render_header(self):
        """Renders the cell header."""
        header_cell = self.render_cell(
            self.name, formatstring=self.header_format, elide=False)
        self.header_width = max([len(line) for line in header_cell])

        # Append a dashed line as a table header separator.
        header_cell.append("-" * self.header_width)

        return header_cell

    def elide_string(self, string, length):
        """Adds three dots in the middle of a string if it is longer than length"""
        if length == -1:
            return string

        if len(string) < length:
            return (" " * (length - len(string))) + string

        elif len(string) == length:
            return string

        else:
            if length < 5:
                logging.error("Cannot elide a string to length less than 5")

            even = ((length + 1) % 2)
            length = (length - 3) / 2
            return string[:length + even] + "..." + string[-length:]

    def render_cell(self, target, formatstring=None, elide=None):
        """Renders obj according to the format string."""
        if formatstring is None:
            formatstring = self.formatstring

        # For NoneObjects we just render dashes. (Other renderers might want to
        # actually record the error, we ignore it here.).
        if target is None or isinstance(target, obj.NoneObject):
            return ['-' * len(self.formatter.format_field(1, formatstring))]

        # Simple formatting.
        result = self.formatter.format_field(target, formatstring).splitlines()

        # Support line wrapping.
        if self.wrap:
            old_result = result
            result = []
            for line in old_result:
                result.extend(textwrap.wrap(line, self.wrap))

        elif elide is None:
            elide = self.elide

        if elide:
            # we take the header width as the maximum width of this column.
            result = [
                self.elide_string(line, self.header_width) for line in result]

        return result or [""]


class TextTable(object):
    """A table is a collection of columns.

    This table formats all its cells using proportional text font.
    """

    def __init__(self, columns=None, tablesep=" ", elide=False,
                 suppress_headers=False, address_size=10):
        self.columns = [TextColumn(*args, elide=elide, address_size=address_size)
                        for args in columns]
        self.tablesep = tablesep
        self.elide = elide
        self.suppress_headers = suppress_headers

    def write_row(self, renderer, cells):
        """Writes a row of the table.

        Args:
          renderer: The renderer we use to write on.
          cells: A list of cell contents. Each cell content is a list of lines
            in the cell.
        """
        # Ensure that all the cells are the same width.
        justified_cells = []
        cell_widths = []
        max_height = 0
        for cell in cells:
            max_width = max([len(line) for line in cell])
            max_height = max(max_height, len(cell))
            justified_cell = []
            for line in cell:
                justified_cell.append(line + (' ' * (max_width-len(line))))
            justified_cells.append(justified_cell)
            cell_widths.append(max_width)

        for line in range(max_height):
            line_components = []
            for i in range(len(justified_cells)):
                try:
                    line_components.append(justified_cells[i][line])
                except IndexError:
                    line_components.append(" " * cell_widths[i])

            renderer.write(self.tablesep.join(line_components) + "\n")

    def render_header(self, renderer):
        # The headers must always be calculated so we can work out the column
        # widths.
        headers = [c.render_header() for c in self.columns]

        if not self.suppress_headers:
            self.write_row(renderer, headers)

    def render_row(self, renderer, *args):
        self.write_row(
            renderer,
            [c.render_cell(obj) for c, obj in zip(self.columns, args)])



class RendererBaseClass(object):
    """All renderers inherit from this."""

    __metaclass__ = registry.MetaclassRegistry

    def __init__(self, session=None, fd=None):
        self.session = session
        self.fd = fd
        self.isatty = False
        self.formatter = Formatter()

    def start(self, plugin_name=None, kwargs=None):
        """The method is called when new output is required.

        Metadata about the running plugin is provided so the renderer may log it
        if desired.

        Args:
           plugin_name: The name of the plugin which is running.
           kwargs: The args for this plugin.
        """

    def end(self):
        """Tells the renderer that we finished using it for a while."""

    def write(self, data):
        """Renderer should write some data."""

    def section(self):
        """Start a new section.

        Sections are used to separate distinct entries (e.g. reports of different files).
        """
        self.write("*" * 50 + "\n")

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

    def table_header(self, title_format_list = None, suppress_headers=False,
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


class TextRenderer(RendererBaseClass):
    """Plugins can receive a renderer object to assist formatting of output."""

    tablesep = " "
    elide = False
    spinner = "/-\|"
    last_spin_time = 0
    last_spin = 0
    last_message_len = 0
    isatty = False

    def __init__(self, tablesep=" ", elide=False, max_data=1024*1024, **kwargs):
        super(TextRenderer, self).__init__(**kwargs)
        self.tablesep = tablesep
        self.elide = elide

        # We keep the data that we produce in memory for while.
        self.data = ''
        self.max_data = max_data

        # Make sure that our output is unicode safe.
        self.fd = UnicodeWrapper(self.fd or sys.stdout)

    def start(self, plugin_name=None, kwargs=None):
        """The method is called when new output is required.

        Args:
           plugin_name: The name of the plugin which is running.
           kwargs: The args for this plugin.
        """
        # This handles the progress messages from volatility for the duration of
        # the rendering.
        if self.session:
            self.session.progress = self.RenderProgress

    def end(self):
        """Tells the renderer that we finished using it for a while."""
        # Remove the progress handler from the session.
        if self.session:
            self.session.progress = None

    def write(self, data):
        self.data += data
        # Only keep some of the last data.
        self.data = self.data[-self.max_data:]

        self.fd.write(data)
        self.fd.flush()

    def flush(self):
        self.fd.flush()

    def table_header(self, columns = None, suppress_headers=False,
                     **kwargs):
        """Table header renders the title row of a table.

        This also stores the header types to ensure everything is formatted
        appropriately.  It must be a list of tuples rather than a dict for
        ordering purposes.

        Args:
           columns: A list of (Name, formatstring) tuples describing
              the table columns.

           suppress_headers: If True table headers will not be written (still
              useful for formatting).
        """
        # Determine the address size
        address_size = 14
        if (self.session and self.session.profile and
            self.session.profile.metadata("memory_model") == "32bit"):
            address_size = 10

        self.table = TextTable(columns=columns, tablesep=self.tablesep,
                               suppress_headers=suppress_headers,
                               elide=self.elide, address_size=address_size)
        self.table.render_header(self)

    def table_row(self, *args):
        """Outputs a single row of a table"""
        return self.table.render_row(self, *args)

    def RenderProgress(self, message="", force=False, **_):
        # Only write once per second.
        now = time.time()
        if force or now > self.last_spin_time + 0.2:
            self.last_spin_time = now
            self.last_spin += 1
            if not message:
                message = self.spinner[self.last_spin % len(self.spinner)]

            # Wipe the last message.
            sys.stdout.write("\r" + " " * self.last_message_len + "\r")
            self.last_message_len = len(message)
            sys.stdout.write(message + "\r")
            sys.stdout.flush()


class JsonFormatter(Formatter):
    """A formatter for json object."""

    def format_dict(self, value):
        result = []
        for k, v in value.items():
            result.append((k, self.format_field(v, "s")))

        return dict(result)

    def format_field(self, value, format_spec):
        """The json formatter aims to capture as many properties of the value as
        possible.
        """
        # We try to capture as much information about this object. Hopefully
        # this should be enough to reconstruct this object later.
        if isinstance(value, obj.BaseObject):
            result = dict(volatility_type=value.obj_type,
                          volatility_name=value.obj_name,
                          volatility_offset=value.obj_offset,
                          volatility_vm=str(value.obj_vm))

            for method in ["__unicode__", "__int__", "__str__"]:
                try:
                    result['value'] = self.format_field(
                        getattr(value, method)(), "s")['value']
                    break
                except (AttributeError, ValueError):
                    pass


            return result

        # If it is a simple type, just pass it as is.
        if isinstance(value, (int, long, basestring)):
            return dict(value=value)

        # If it is a NoneObject dump out the error
        if isinstance(value, obj.NoneObject):
            return dict(volatility_type=value.__class__.__name__,
                        volatility_reason=value.reason,
                        value=None)

        # Fall back to just formatting it.
        return super(JsonFormatter, self).format_field(value, format_spec)


class JsonColumn(TextColumn):
    """A column in a json table."""
    def __init__(self, name=None, cname=None, format_spec=None, **kwargs):
        self.formatter = JsonFormatter()
        self.name = name
        self.cname = cname

    def render_header(self):
        return self.cname

    def render_cell(self, target):
        return self.formatter.format_field(target, "s")


class JsonTable(TextTable):
    def __init__(self, columns=None, **kwargs):
        self.columns = [JsonColumn(*args) for args in columns]

    def render_header(self, renderer):
        renderer.table_data['headers'] = [c.render_header() for c in self.columns]

    def get_header(self, renderer):
        return [c.render_header() for c in self.columns]

    def render_row(self, renderer, *args):
        data = {}
        for c, obj in zip(self.columns, args):
            data[c.cname] = c.render_cell(obj)
        renderer.table_data.append(data)


class JsonRenderer(TextRenderer):
    """Render the output as a json object."""

    def start(self, plugin_name=None, kwargs=None):
        self.formatter = JsonFormatter()

        # We store the data here.
        self.data = dict(plugin_name=plugin_name,
                         tool_name="volatility-ng",
                         tool_version=constants.VERSION,
                         kwargs=self.formatter.format_dict(kwargs),
                         data=[])

        super(JsonRenderer, self).start(plugin_name=plugin_name,
                                        kwargs=kwargs)
        self.headers = []

    def end(self):
        # Just dump out the json object.
        self.fd.write(json.dumps(self.data, indent=4))

    def format(self, formatstring, *args):
        statement = [formatstring]
        for arg in args:
            # Just store the statement in the output.
            statement.append(self.formatter.format_field(arg, "s"))

        self.data['data'].append(statement)

    def table_header(self, columns = None, **kwargs):
        self.table = JsonTable(columns=columns)

        # This is the current table - the JsonTable object will write on it.
        self.table_data = []

        # Append it to the data.
        self.data['data'] = self.table_data

        # Write the headers.
        self.headers = self.table.get_header(self)

    def write(self, data):
        self.data['data'].append(data)
