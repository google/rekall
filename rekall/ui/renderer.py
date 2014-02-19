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
try:
    import curses
    curses.setupterm()
except ImportError:
    curses = None

import logging
import json
import re
import os
import string
import subprocess
import sys
import tempfile
import textwrap
import time

from rekall import config
from rekall import obj
from rekall import utils
from rekall import registry
from rekall import constants


config.DeclareOption(
    "--pager", default=os.environ.get("PAGER"), group="Interface",
    help="The pager to use when output is larger than a screen full.")

config.DeclareOption(
    "--paging_limit", default=50, group="Interface", type=int,
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


HIGHLIGHT_SCHEME = dict(
    important=("WHITE", "RED"),
    good=("GREEN", None),
    neutral=(None, None),
    )

class Pager(object):
    """A wrapper around a pager.

    The pager can be specified by the session. (eg.
    session.SetParameter("pager", 'less') or in an PAGER environment var.
    """
    # Default encoding is utf8
    encoding = "utf8"

    def __init__(self, session=None, encoding=None):
        # More is the least common denominator of pagers :-(. Less is better,
        # but most is best!
        self.pager_command = (session.GetParameter("pager") or
                              os.environ.get("PAGER"))

        self.encoding = (encoding or session.encoding or
                         sys.stdout.encoding or "utf8")

        # Make a temporary filename to store output in.
        self.fd, self.filename = tempfile.mkstemp(prefix="rekall")

    def __enter__(self):
        return self

    def __exit__(self, *args, **kwargs):
        # Delete the temp file.
        try:
            os.unlink(self.filename)
        except OSError:
            pass

    def write(self, data):
        # Encode the data according to the output encoding.
        data = utils.SmartUnicode(data).encode(self.encoding, "replace")
        try:
            if sys.platform in ["win32"]:
                data = data.replace("\n", "\r\n")

            os.write(self.fd, data)
        # This can happen if the pager disappears in the middle of the write.
        except IOError:
            pass

    def flush(self):
        """Wait for the pager to be exited."""
        os.close(self.fd)

        try:
            args = dict(filename=self.filename)
            # Allow the user to interpolate the filename in a special way,
            # otherwise just append to the end of the command.
            if "%" in self.pager_command:
                pager_command = self.pager_command % args
            else:
                pager_command = self.pager_command + " %s" % self.filename

            subprocess.call(pager_command, shell=True)

        # Allow the user to break out from waiting for the command.
        except KeyboardInterrupt:
            pass
        finally:
            try:
                os.unlink(self.filename)
            except OSError:
                pass


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
        return int(value)

    def format_type_X(self, value, fields):
        return int(value)

    def format_type_r(self, value, fields):
        return repr(value)

    def format_type_f(self, value, fields):
        if isinstance(value, (float, int, long)):
            return float(value)

        return value

    def format_type_L(self, value, fields):
        """Support extended list format."""
        return ", ".join([utils.SmartUnicode(x) for x in value])


class TextColumn(object):
    """An implementation of a Column."""

    def __init__(self, name=None, cname=None, formatstring="s", address_size=14,
                 header_format=None, table=None):
        self.name = name or "-"
        self.cname = cname or "-"
        self.table = table
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

    def render_header(self):
        """Renders the cell header."""
        header_cell = self.render_cell(
            self.name, formatstring=self.header_format, elide=False)
        self.header_width = max([len(line) for line in header_cell])

        # Append a dashed line as a table header separator.
        header_cell.append("-" * self.header_width)

        return header_cell

    def elide_string(self, string, length):
        """Elides the middle of a string if it is longer than length."""
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

        if isinstance(target, Colorizer):
            result = []
            for x in self.render_cell(target.target, formatstring=formatstring,
                                      elide=elide):
                result.append(target.Render(x))
            return result

        # For NoneObjects we just render dashes. (Other renderers might want to
        # actually record the error, we ignore it here.).
        elif target is None or isinstance(target, obj.NoneObject):
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
            elide = self.table.elide

        if elide:
            # we take the header width as the maximum width of this column.
            result = [
                self.elide_string(line, self.header_width) for line in result]

        if isinstance(target, bool):
            color = "GREEN" if target else "RED"
            result = [
                self.table.renderer.color(x, foreground=color) for x in result]

        return result or [""]


class TextTable(object):
    """A table is a collection of columns.

    This table formats all its cells using proportional text font.
    """

    def __init__(self, columns=None, tablesep=" ", elide=False,
                 suppress_headers=False, address_size=10, renderer=None):
        self.columns = [
            TextColumn(*args, address_size=address_size, table=self)
            for args in columns]

        self.renderer = renderer  # Our parent renderer.
        self.tablesep = tablesep
        self.elide = elide
        self.suppress_headers = suppress_headers

    def write_row(self, renderer, cells, highlight=False):
        """Writes a row of the table.

        Args:
          renderer: The renderer we use to write on.
          cells: A list of cell contents. Each cell content is a list of lines
            in the cell.
        """
        foreground, background = HIGHLIGHT_SCHEME.get(
            highlight, (None, None))

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

            renderer.write(
                renderer.color(
                    self.tablesep.join(line_components),
                    foreground=foreground, background=background) + "\n")

    def render_header(self, renderer):
        # The headers must always be calculated so we can work out the column
        # widths.
        headers = [c.render_header() for c in self.columns]

        if not self.suppress_headers:
            self.write_row(renderer, headers)

    def render_row(self, renderer, row=None, highlight=None):
        self.write_row(
            renderer,
            [c.render_cell(x) for c, x in zip(self.columns, row)],
            highlight=highlight)



class RendererBaseClass(object):
    """All renderers inherit from this."""

    __metaclass__ = registry.MetaclassRegistry

    def __init__(self, session=None, fd=None, paging_limit=50):
        self.session = session
        self.paging_limit = paging_limit
        self.fd = fd
        self.isatty = False
        self.formatter = Formatter()
        self.colorizer = Colorizer(
            fd, nocolor=session.GetParameter("nocolors") if session else False)

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

    def section(self, name=None):
        """Start a new section.

        Sections are used to separate distinct entries (e.g. reports of
        different files).
        """
        _ = name
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
        """Outputs a single row of a table.

        Supported kwargs:
          highlight: Highlight this raw according to the color scheme
            (e.g. important, good)
        """

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


class TextRenderer(RendererBaseClass):
    """Plugins can receive a renderer object to assist formatting of output."""

    tablesep = " "
    elide = False
    spinner = r"/-\|"
    last_spin_time = 0
    last_spin = 0
    last_message_len = 0
    isatty = False

    def __init__(self, tablesep=" ", elide=False, max_data=1024*1024,
                 paging_limit=None, **kwargs):
        super(TextRenderer, self).__init__(**kwargs)
        self.tablesep = tablesep
        self.elide = elide

        # We keep the data that we produce in memory for while.
        self.data = []
        self.max_data = max_data

        # Make sure that our output is unicode safe.
        self.fd = UnicodeWrapper(self.fd or sys.stdout)

        # The stream we write the progress on. Only write to stdout if it is a
        # tty.
        if sys.stdout.isatty():
            self.progress_fd = sys.stdout
            self.paging_limit = paging_limit
            self.isatty = True

        else:
            self.progress_fd = None
            self.paging_limit = None

    def start(self, plugin_name=None, kwargs=None):
        """The method is called when new output is required.

        Args:
           plugin_name: The name of the plugin which is running.
           kwargs: The args for this plugin.
        """
        # This handles the progress messages from rekall for the duration of
        # the rendering.
        if self.session:
            self.session.progress = self.RenderProgress

    def end(self):
        """Tells the renderer that we finished using it for a while."""
        # Remove the progress handler from the session.
        if self.session:
            self.session.progress = None

    def format(self, formatstring, *data):
        # Only clear the progress if we share the same output stream as the
        # progress.
        if self.fd is self.progress_fd:
            self.ClearProgress()

        super(TextRenderer, self).format(formatstring, *data)

    def write(self, data):
        self.data.append(data)

        # When not to use the pager.
        if (not self.isatty or  # Not attached to a tty.
            self.paging_limit is None or  # No paging limit specified.
            len(self.data) < self.paging_limit):  # Not enough output yet.
            self.fd.write(data)
            self.fd.flush()

        # Write a single message to the terminal.
        elif len(self.data) == self.paging_limit:
            self.fd.write(
                self.color("Please wait while the rest is paged...",
                           foreground="YELLOW") + "\r\n")
            self.fd.flush()

        # Suppress terminal output. Output is buffered in self.data and will be
        # sent to the pager.
        else:
            return

    def flush(self):
        self.data = []
        self.ClearProgress()
        self.fd.flush()

    def table_header(self, columns=None, suppress_headers=False,
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
            self.session.profile.metadata("arch") == "I386"):
            address_size = 10

        self.table = TextTable(columns=columns, tablesep=self.tablesep,
                               suppress_headers=suppress_headers,
                               address_size=address_size,
                               renderer=self)
        self.table.render_header(self)

    def table_row(self, *args, **kwargs):
        """Outputs a single row of a table"""
        return self.table.render_row(self, row=args, **kwargs)

    def ClearProgress(self):
        """Delete the last progress message."""
        if self.progress_fd is None:
            return

        # Wipe the last message.
        self.progress_fd.write("\r" + " " * self.last_message_len + "\r")
        self.progress_fd.flush()

    def _GetColumns(self):
        if curses:
            return curses.tigetnum('cols')

        return int(os.environ.get("COLUMNS", 80))

    def RenderProgress(self, message=" %(spinner)s", *args, **kwargs):
        if self.progress_fd is None:
            return

        # Only write once per second.
        now = time.time()
        force = kwargs.get("force")

        if force or now > self.last_spin_time + 0.2:
            self.last_spin_time = now
            self.last_spin += 1

            # Only expand variables when we need to.
            if "%(" in message:
                kwargs["spinner"] = self.spinner[
                    self.last_spin % len(self.spinner)]

                message = message % kwargs
            elif args:
                format_args = []
                for arg in args:
                    if callable(arg):
                        format_args.append(arg())
                    else:
                        format_args.append(arg)

                message = message % tuple(format_args)

            self.ClearProgress()

            message = " " + message + "\r"
            # Truncate the message to the terminal width to avoid wrapping.
            message = message[:self._GetColumns()]

            self.progress_fd.write(message)
            self.last_message_len = len(message)
            self.progress_fd.flush()


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
            result = dict(rekall_type=value.obj_type,
                          rekall_name=value.obj_name,
                          rekall_offset=value.obj_offset,
                          rekall_vm=str(value.obj_vm))

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
            return dict(rekall_type=value.__class__.__name__,
                        rekall_reason=value.reason,
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

    def render_row(self, renderer, row=None, **_):
        data = {}
        for c, obj in zip(self.columns, row):
            data[c.cname] = c.render_cell(obj)
        renderer.table_data.append(data)


class JsonRenderer(TextRenderer):
    """Render the output as a json object."""

    def start(self, plugin_name=None, kwargs=None):
        self.formatter = JsonFormatter()

        # We store the data here.
        self.data = dict(plugin_name=plugin_name,
                         tool_name="rekall-ng",
                         tool_version=constants.VERSION,
                         kwargs=self.formatter.format_dict(kwargs or {}),
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


class TestRenderer(TextRenderer):
    """A special renderer which makes parsing the output of tables easier."""

    def __init__(self, **kwargs):
        super(TestRenderer, self).__init__(tablesep="||", **kwargs)


class Colorizer(object):
    """An object which makes its target colorful."""

    COLORS = "BLACK BLUE GREEN CYAN RED MAGENTA YELLOW WHITE"
    COLOR_MAP = dict([(x, i) for i, x in enumerate(COLORS.split())])

    terminal_capable = False

    def __init__(self, stream, nocolor=False):
        """Initialize a colorizer.

        Args:
          stream: The stream to write to.

          nocolor: If True we suppress using colors, even if the output stream
             can support them.
        """
        if stream is None:
            stream = sys.stdout

        if nocolor:
            self.terminal_capable = False
            return

        try:
            if curses and stream.isatty():
                curses.setupterm()
                self.terminal_capable = True
        except AttributeError:
            pass

    def tparm(self, capabilities, *args):
        """A simplified version of tigetstr without terminal delays."""
        for capability in capabilities:
            term_string = curses.tigetstr(capability)
            if term_string is not None:
                term_string = re.sub("\$\<[^>]+>", "", term_string)
                break

        try:
            return curses.tparm(term_string, *args)
        except Exception, e:
            logging.debug("Unable to set tparm: %s" % e)
            return ""

    def Render(self, string, foreground=None, background=None):
        """Decorate the string with the ansii escapes for the color."""
        if (not self.terminal_capable or
            foreground not in self.COLOR_MAP or
            foreground not in self.COLOR_MAP):
            return utils.SmartUnicode(string)

        escape_seq = ""
        if background:
            escape_seq += self.tparm(
                ["setb", "setab"], self.COLOR_MAP[background])

        if foreground:
            escape_seq += self.tparm(
                ["setf", "setaf"], self.COLOR_MAP[foreground])

        return (escape_seq + utils.SmartUnicode(string) +
                self.tparm(["sgr0"]))
