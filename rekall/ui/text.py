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
except Exception:  # curses sometimes raises weird exceptions.
    curses = None

import logging
import re
import os
import string
import subprocess
import sys
import tempfile
import textwrap

from rekall import config
from rekall import registry
from rekall import utils

from rekall.ui import renderer


config.DeclareOption(
    "--pager", default=os.environ.get("PAGER"), group="Interface",
    help="The pager to use when output is larger than a screen full.")

config.DeclareOption(
    "--paging_limit", default=None, group="Interface", type=int,
    help="The number of output lines before we invoke the pager.")

config.DeclareOption(
    "--nocolors", default=False, action="store_true", group="Interface",
    help="If set suppress outputting colors.")


HIGHLIGHT_SCHEME = dict(
    important=("WHITE", "RED"),
    good=("GREEN", None),
    neutral=(None, None),
)


class Formatter(string.Formatter):
    """A formatter which supports extended formating specs."""
    # This comes from http://docs.python.org/library/string.html
    # 7.1.3.1. Format Specification Mini-Language
    standard_format_specifier_re = re.compile(r"""
(?P<fill>[^{}<>=^bcdeEfFgGnLosxX0-9])?  # The fill parameter. This can not be a
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

    def __init__(self, session=None):
        super(Formatter, self).__init__()
        self.session = session
        self._calculate_address_size()

    def _calculate_address_size(self):
        self.address_size = 14
        if self.session.profile.metadata("arch") == "I386":
            self.address_size = 10

    def parse_extended_format(self, value, formatstring="", header=False,
                              **options):
        """Parse the format string into the format specification.

        We support some extended forms of format string which we process
        especially here:

        [addrpad] - This is a padded address to width renderer.address_size.
        [addr] - This is a non padded address.
        [wrap:width] - This wraps a stringified version of the target in the
           cell.

        Args:
          formatstring: The formatstring we parse.
          options: An options dict. We may populate it with some options which
             are encoded in the extended format.

        Returns:
          A Cell instance.
        """
        extended_format = None

        # This means unlimited and uncontrolled width.
        if formatstring == "":
            extended_format = "s"

        if formatstring == "[addrpad]":
            if header:
                extended_format = "^%ss" % self.address_size
            else:
                extended_format = "#0%sx" % self.address_size

            if value == None:
                extended_format = "<%ss" % self.address_size

        elif formatstring == "[addr]":
            if header:
                extended_format = "^%ss" % self.address_size
            else:
                extended_format = ">#%sx" % self.address_size

        # Look for the wrap specifier.
        m = re.match(r"\[wrap:([^\]]+)\]", formatstring)
        if m:
            width = int(m.group(1))
            return Cell.wrap(utils.SmartUnicode(value), width)

        if extended_format is not None:
            return Cell.FromString(
                self.format_field(value, extended_format))

    def format_cell(self, value, formatstring="", header=False, **options):
        """Format the value into a Cell instance.

        This also support extended formatting directives.

        Returns:
          A Cell instance.
        """
        res = self.parse_extended_format(
            value, formatstring=formatstring, header=header, **options)

        if res:
            return res

        if header:
            formatstring = formatstring.replace("#", "")
            formatstring = formatstring.replace("<", "")
            formatstring = formatstring.replace(">", "")
            formatstring = formatstring.replace("x", "s")
            if not formatstring.startswith("^"):
                formatstring = "^" + formatstring

        return Cell.FromString(
            self.format_field(value, formatstring=formatstring))

    def format_field(self, value, formatstring="", header=False, **_):
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
        m = self.standard_format_specifier_re.match(formatstring)
        if not m:
            raise re.error("Invalid regex")

        fields = m.groupdict()

        if header:
            fields["align"] = "^"

        # Format the value according to the basic type.
        type = fields["type"] or "s"
        try:
            value = getattr(
                self, "format_type_%s" % type)(value, fields)
        except AttributeError:
            raise re.error("No formatter for type %s" % type)

        try:
            return format(value, formatstring)
        except ValueError:
            return str(value)

    def format_type_s(self, value, fields):
        try:
            # This is required to allow BaseObject to pass non unicode returns
            # from __unicode__ (e.g. NoneObject).
            result = value.__unicode__()
        except AttributeError:
            result = utils.SmartUnicode(value)

        formatstring = (u"{0:" + (fields.get("align") or "") +
                        (fields.get("width") or "") + "s}")
        return formatstring.format(result)

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


class Pager(object):
    """A wrapper around a pager.

    The pager can be specified by the session. (eg.
    session.SetParameter("pager", 'less') or in an PAGER environment var.
    """
    # Default encoding is utf8
    encoding = "utf8"

    def __init__(self, session=None, term_fd=None):
        self.session = session

        # More is the least common denominator of pagers :-(. Less is better,
        # but most is best!
        self.pager_command = (session.GetParameter("pager") or
                              os.environ.get("PAGER"))

        if self.pager_command in [None, "-"]:
            raise AttributeError("Pager command must be specified")

        self.encoding = session.GetParameter("encoding", "UTF-8")
        self.fd = None
        self.paging_limit = self.session.GetParameter("paging_limit")
        self.data = ""

        # Partial results will be directed to this until we hit the
        # paging_limit, and then we send them to the real pager. This means that
        # short results do not invoke the pager, but render directly to the
        # terminal. It probably does not make sense to have term_fd as anything
        # other than sys.stdout.
        self.term_fd = term_fd or sys.stdout
        if not self.term_fd.isatty():
            raise AttributeError("Pager can only work on a tty.")

        self.colorizer = Colorizer(
            self.term_fd,
            nocolor=self.session.GetParameter("nocolors"),
            )

    def __enter__(self):
        return self

    def __exit__(self, *args, **kwargs):
        # Delete the temp file.
        try:
            if self.fd:
                self.fd.close()
                os.unlink(self.fd.name)
        except OSError:
            pass

    def GetTempFile(self):
        if self.fd is not None:
            return self.fd

        # Make a temporary filename to store output in.
        self.fd = tempfile.NamedTemporaryFile(prefix="rekall")

        return self.fd

    def write(self, data):
        # Encode the data according to the output encoding.
        data = utils.SmartUnicode(data).encode(self.encoding, "replace")
        if sys.platform == "win32":
            data = data.replace("\n", "\r\n")

        if self.fd is not None:
            # Suppress terminal output. Output is buffered in self.fd and will
            # be sent to the pager.
            self.fd.write(data)

        # No paging limit specified - just dump to terminal.
        elif self.paging_limit is None:
            self.term_fd.write(data)
            self.term_fd.flush()

        # If there is not enough output yet, just write it to the terminal and
        # store it locally.
        elif len(self.data.splitlines()) < self.paging_limit:
            self.term_fd.write(data)
            self.term_fd.flush()
            self.data += data

        # Now create a tempfile and dump the rest of the output there.
        else:
            self.term_fd.write(
                self.colorizer.Render(
                    "Please wait while the rest is paged...",
                    foreground="YELLOW") + "\r\n")
            self.term_fd.flush()

            fd = self.GetTempFile()
            fd.write(self.data + data)

    def isatty(self):
        return self.term_fd.isatty()

    def flush(self):
        """Wait for the pager to be exited."""
        if self.fd is None:
            return

        self.fd.flush()

        try:
            args = dict(filename=self.fd.name)
            # Allow the user to interpolate the filename in a special way,
            # otherwise just append to the end of the command.
            if "%" in self.pager_command:
                pager_command = self.pager_command % args
            else:
                pager_command = self.pager_command + " %s" % self.fd.name

            subprocess.call(pager_command, shell=True)

        # Allow the user to break out from waiting for the command.
        except KeyboardInterrupt:
            pass

        finally:
            # This will delete the temp file.
            self.fd.close()


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
                term_string = re.sub(r"\$\<[^>]+>", "", term_string)
                break

        try:
            return curses.tparm(term_string, *args)
        except Exception, e:
            logging.debug("Unable to set tparm: %s" % e)
            return ""

    def Render(self, target, foreground=None, background=None):
        """Decorate the string with the ansii escapes for the color."""
        if (not self.terminal_capable or
            foreground not in self.COLOR_MAP or
            foreground not in self.COLOR_MAP):
            return utils.SmartUnicode(target)

        escape_seq = ""
        if background:
            escape_seq += self.tparm(
                ["setb", "setab"], self.COLOR_MAP[background])

        if foreground:
            escape_seq += self.tparm(
                ["setf", "setaf"], self.COLOR_MAP[foreground])

        return (escape_seq + utils.SmartUnicode(target) +
                self.tparm(["sgr0"]))


class ObjectRenderer(renderer.ObjectRenderer):
    """Baseclass for all TestRenderer object renderers."""

    # Fall back renderer for all objects.
    renders_type = "object"
    renderers = ["TextRenderer", "WideTextRenderer"]

    __metaclass__ = registry.MetaclassRegistry

    def __init__(self, *args, **kwargs):
        super(ObjectRenderer, self).__init__(*args, **kwargs)
        self.formatter = Formatter(session=self.session)

    def render_header(self, name=None, **options):
        """This should be overloaded to return the header Cell.

        Note that typically the same ObjectRenderer instance will be used to
        render all Cells in the same column.

        Args:
          name: The name of the Column.
          options: The options of the column (i.e. the dict which defines the
            column).

        Return:
          A Cell instance containing the formatted Column header.
        """
        formatstring = options.get("formatstring", "")
        header_cell = self.formatter.format_cell(
            name, formatstring, header=True)

        self.header_width = max([len(line) for line in header_cell])

        # Append a dashed line as a table header separator.
        header_cell.append("-" * self.header_width)

        return header_cell

    def render_row(self, target, **options):
        """Render the target suitably.

        Args:
          target: The object to be rendered.

          options: A dict containing rendering options. The options are created
            from the column options, overriden by the row options and finally
            the cell options.  It is ok for an instance to ignore some or all of
            the options. Some options only make sense in certain Renderer
            contexts.

        Returns:
          A Cell instance containing the rendering of target.
        """
        return self.formatter.format_cell(target, **options)


class CellRenderer(ObjectRenderer):
    """This renders a Cell object into a Cell object.

    i.e. it is just a passthrough object renderer for Cell objects. This is
    useful for rendering nested tables.
    """
    renders_type = "Cell"

    def render_row(self, target, **_):
        return Cell.Strip(target)


class Cell(object):
    """A Cell represents a single entry in a table.

    Cells always have a fixed number of characters in width and may have
    arbitrary number of characters (lines) for a height.

    The TextTable consists of an array of Cells:

    Cell Cell Cell Cell  <----- Headers.
    Cell Cell Cell Cell  <----- Table rows.

    The ObjectRenderer is responsible for turning an arbitrary object into a
    Cell object.
    """

    def __init__(self):
        self.lines = []

    def Justify(self, width=None):
        """Fix up the width of all lines so they are the same."""
        if width is None:
            width = self.width

        for i in range(len(self.lines)):
            line = self.lines[i]
            self.lines[i] = line + " " * (width - len(line))

        return self

    @property
    def width(self):
        """Return the maximum width of this Cell in characters."""
        return max(0, 0, *[len(x) for x in self.lines])

    @property
    def height(self):
        """The number of chars this Cell takes in height."""
        return len(self.lines)

    @classmethod
    def wrap(cls, value, width):
        """A constructor which creates a Cell by wrapping a long string."""
        result = cls()

        # Expand the line into a list of lines wrapped at the width.
        for wrapped_line in textwrap.wrap(value, width=width):
            # Pad the line to the required width.
            result.lines.append(
                wrapped_line + " " * (width - len(wrapped_line)))

        result.Justify()
        return result

    @classmethod
    def Strip(cls, cell):
        result = cls()
        for line in cell:
            result.append(line.strip())

        result.Justify()
        return result

    @classmethod
    def FromString(cls, value):
        result = cls()
        for line in value.splitlines():
            result.lines.append(line)

        return result

    @classmethod
    def Join(cls, *cells, **kwargs):
        """Construct a new Cell which is the result of combining Cells."""
        tablesep = kwargs.pop("tablesep", " ")
        if kwargs:
            raise AttributeError("Unsupported args %s" % kwargs)

        # Ensure that all the cells are the same width.
        cell_widths = []
        max_height = 0
        for cell in cells:
            cell.Justify()
            cell_widths.append(cell.width)
            max_height = max(max_height, cell.height)

        # Make a new cell to receive the output.
        result = cls()
        for line in range(max_height):
            line_components = []
            for i in range(len(cells)):
                try:
                    line_components.append(cells[i].lines[line])
                except IndexError:
                    line_components.append(" " * cell_widths[i])

            result.lines.append(tablesep.join(line_components))

        return result

    def __iter__(self):
        self.Justify()
        return iter(self.lines)

    def append(self, value):
        self.lines.append(value)
        return self


class TextColumn(object):
    """Implementation for text (mostly CLI) tables."""

    # The object renderer used for this column.
    object_renderer = None

    def __init__(self, table=None, renderer=None, session=None, type=None,
                 **options):
        self.session = session
        self.table = table
        self.wrap = None
        self.renderer = renderer
        # Arbitrary column options to be passed to ObjectRenderer() instances.
        # This allows a plugin to influence the output somewhat in different
        # output contexts.
        self.options = options

        # For columns which do not explicitly set their type, we can not
        # determine the type until the first row has been written. NOTE: It is
        # not supported to change the type of a column after the first row has
        # been written.
        if type:
            self.object_renderer = self.renderer.get_object_renderer(
                type=type, **options)

    def render_header(self):
        """Renders the cell header.

        Returns a Cell instance for this column header.
        """
        # If there is a customized object renderer for this column we use that.
        if self.object_renderer:
            header = self.object_renderer.render_header(**self.options)

        else:
            # Otherwise we just use the default.
            object_renderer = ObjectRenderer(self.renderer, self.session)

            header = object_renderer.render_header(**self.options)

        self.header_width = header.width
        return header

    def render_row(self, target, **options):
        """Renders the current row for the target.
        """
        # We merge the row options and the column options. This allows a call to
        # table_row() to override options.
        merged_opts = self.options.copy()
        merged_opts.update(options)

        if self.object_renderer is None:
            self.object_renderer = self.table.renderer.get_object_renderer(
                target, type=merged_opts.get("type"), **options)

        result = self.object_renderer.render_row(target, **merged_opts)
        if result.width < self.header_width:
            result.Justify(width=self.header_width)
        return result


class TextTable(object):
    """A table is a collection of columns.

    This table formats all its cells using proportional text font.
    """

    column_class = TextColumn

    def __init__(self, columns=None, renderer=None, suppress_headers=False,
                 session=None, tablesep=" ", **options):
        self.session = session
        self.tablesep = tablesep
        self.renderer = renderer
        self.options = options
        self.columns = []

        for args in columns:
            # Old style column specification are a tuple. The new way is a dict
            # which is more expressive but more verbose.
            if isinstance(args, (tuple, list)):
                args = dict(name=args[0],
                            cname=args[1],
                            formatstring=args[2])

            self.columns.append(self.column_class(
                session=self.session, table=self, renderer=self.renderer,
                **args))

        self.suppress_headers = suppress_headers

    def write_row(self, cells, highlight=False):
        """Writes a row of the table.

        Args:
          cells: A list of cell contents. Each cell content is a list of lines
            in the cell.
        """
        foreground, background = HIGHLIGHT_SCHEME.get(
            highlight, (None, None))

        # Iterate over all lines in the row and write it out.
        for line in Cell.Join(cells, tablesep=self.tablesep):
            self.renderer.write(
                self.renderer.colorizer.Render(
                    line, foreground=foreground, background=background) + "\n")

    def render_header(self):
        """Returns a Cell formed by joining all the column headers."""
        # Get each column to write its own header and then we join them all up.
        return Cell.Join(*[c.render_header() for c in self.columns],
                          tablesep=self.tablesep)

    def get_row(self, *row, **options):
        """Format the row into a single Cell spanning all output columns.

        Args:
          *row: A list of objects to render in the same order as columns are
             defined.

        Returns:
          A single Cell object spanning the entire row.
        """
        return Cell.Join(
            *[c.render_row(x, **options) for c, x in zip(self.columns, row)],
             tablesep=self.tablesep)

    def render_row(self, row=None, highlight=None, **options):
        """Write the row to the output."""
        return self.write_row(self.get_row(*row, **options),
                              highlight=highlight)


class UnicodeWrapper(object):
    """A wrapper around a file like object which guarantees writes in utf8."""

    _isatty = None

    def __init__(self, fd, encoding='utf8'):
        self.fd = fd
        self.encoding = encoding

    def write(self, data):
        data = utils.SmartUnicode(data).encode(self.encoding, "replace")
        self.fd.write(data)

    def flush(self):
        self.fd.flush()

    def isatty(self):
        if self._isatty is None:
            try:
                self._isatty = self.fd.isatty()
            except AttributeError:
                self._isatty = False

        return self._isatty


class TextRenderer(renderer.BaseRenderer):
    """Renderer for the command line that supports paging, colors and progress.
    """
    name = "text"

    tablesep = " "
    paging_limit = None
    table_cls = TextTable
    progress_fd = None

    # Render progress with a spinner.
    spinner = r"/-\|"
    last_spin = 0
    last_message_len = 0

    def __init__(self, tablesep=" ", output=None, mode="a+b", fd=None,
                 **kwargs):
        super(TextRenderer, self).__init__(**kwargs)

        # Allow the user to dump all output to a file.
        self.output = output or self.session.GetParameter("output")
        if self.output:
            # We append the text output for each command. This allows the user
            # to just set it once for the session and each new command is
            # recorded in the output file.
            fd = open(self.output, mode)

        if fd == None:
            fd = self.session.fd

        if fd == None:
            try:
                fd = Pager(session=self.session)
            except AttributeError:
                fd = sys.stdout

        # Make sure that our output is unicode safe.
        self.fd = UnicodeWrapper(fd)
        self.formatter = Formatter(session=self.session)

        self.tablesep = tablesep

        # We keep the data that we produce in memory for while.
        self.data = []

        # Write progress to stdout but only if it is a tty.
        self.progress_fd = UnicodeWrapper(sys.stdout)
        if not self.progress_fd.isatty():
            self.progress_fd = None

        self.colorizer = Colorizer(
            self.fd,
            nocolor=self.session.GetParameter("nocolors"),
        )

    def format(self, formatstring, *data):
        super(TextRenderer, self).format(formatstring, *data)

        # Only clear the progress if we share the same output stream as the
        # progress.
        if self.fd is self.progress_fd:
            self.ClearProgress()

        self.write(self.formatter.format(formatstring, *data))

    def write(self, data):
        self.fd.write(data)

    def flush(self):
        self.data = []
        self.ClearProgress()
        self.fd.flush()

    def table_header(self, *args, **options):
        self.options = options
        suppress_headers = options.pop("suppress_headers", False)
        super(TextRenderer, self).table_header(*args, **options)

        self.table = self.table_cls(
            renderer=self, session=self.session, tablesep=self.tablesep,
            *args, **options
            )

        for line in self.table.render_header():
            if not suppress_headers:
                self.write(line + "\n")

    def table_row(self, *args, **kwargs):
        """Outputs a single row of a table.

        Text tables support these additional kwargs:
          highlight: Highlights this raw according to the color scheme (e.g.
          important, good...)
        """
        super(TextRenderer, self).table_row(*args, **kwargs)
        self.RenderProgress(message=None)

        if self.deferred_rows is not None:
            # Table rendering is being deferred for sorting.
            self.deferred_rows.append((args, kwargs))
        else:
            self.table.render_row(row=args, **kwargs)

    def _GetColumns(self):
        if curses:
            return curses.tigetnum('cols')

        return int(os.environ.get("COLUMNS", 80))

    def RenderProgress(self, message=" %(spinner)s", *args, **kwargs):
        if super(TextRenderer, self).RenderProgress(**kwargs):
            self.last_spin += 1
            if not message:
                return

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

            self.last_message_len = len(message)

            self._RenderProgress(message)

            return True

    def _RenderProgress(self, message):
        """Actually write the progress message.

        This can be overwritten by renderers to deliver the progress messages
        elsewhere.
        """
        if self.progress_fd is not None:
            self.progress_fd.write(message)
            self.progress_fd.flush()

    def ClearProgress(self):
        """Delete the last progress message."""
        if self.progress_fd is None:
            return

        # Wipe the last message.
        self.progress_fd.write("\r" + " " * self.last_message_len + "\r")
        self.progress_fd.flush()

    def open(self, directory=None, filename=None, mode="rb"):
        if filename is None and directory is None:
            raise IOError("Must provide a filename")
        if directory:
            filename = os.path.join(directory, "./", filename)

        return open(filename, mode)


class TestRenderer(TextRenderer):
    """A special renderer which makes parsing the output of tables easier."""
    name = "test"

    def __init__(self, **kwargs):
        super(TestRenderer, self).__init__(tablesep="||", **kwargs)


class WideTextRenderer(TextRenderer):
    """A Renderer which explodes tables into wide formatted records."""

    name = "wide"

    def __init__(self, **kwargs):
        super(WideTextRenderer, self).__init__(**kwargs)

        self.delegate_renderer = TextRenderer(**kwargs)

    def __enter__(self):
        self.delegate_renderer.__enter__()
        self.delegate_renderer.table_header(
            [("Key", "key", "[wrap:15]"),
             ("Value", "Value", "[wrap:80]")],
            )

        return super(WideTextRenderer, self).__enter__()

    def __exit__(self, exc_type, exc_value, trace):
        self.delegate_renderer.__exit__(exc_type, exc_value, trace)
        return super(WideTextRenderer, self).__exit__(
            exc_type, exc_value, trace)

    def table_header(self, *args, **options):
        options["suppress_headers"] = True
        super(WideTextRenderer, self).table_header(*args, **options)

    def table_row(self, *row, **options):
        self.section()
        values = [c.render_row(x) for c, x in zip(self.table.columns, row)]

        for c, item in zip(self.table.columns, values):
            column_name = (getattr(c.object_renderer, "name", None) or
                           c.options.get("name"))
            self.delegate_renderer.table_row(column_name, item, **options)


class TreeNodeObjectRenderer(ObjectRenderer):
    renders_type = "TreeNode"


    def __init__(self, renderer=None, session=None, **options):
        self.max_depth = options.pop("max_depth", 10)
        child_spec = options.pop("child", None)
        if child_spec:
            child_type = child_spec.get("type")

            self.child = self.ByName(child_type, renderer)(
                renderer, session=session, **child_spec)

            if not self.child:
                raise AttributeError("Child %s of TreeNode was not found." %
                                     child_type)
        else:
            self.child = None

        super(TreeNodeObjectRenderer, self).__init__(
            renderer, session=session, **options)

    def render_header(self, **options):
        if self.child:
            padding = Cell.FromString(" " * self.max_depth)
            heading = Cell.Join(self.child.render_header(**options), padding)
        else:
            heading = super(TreeNodeObjectRenderer, self).render_header(
                **options)

        self.heading_width = heading.width
        return heading

    def render_row(self, target, depth=0, **options):
        if self.child:
            child_cell = self.child.render_row(target, **options)
        else:
            child_cell = super(TreeNodeObjectRenderer, self).render_row(
                target, **options)

        padding = Cell.FromString("." * depth)
        result = Cell.Join(padding, child_cell)
        result.Justify(width=self.heading_width)

        return result
