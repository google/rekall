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
import subprocess
import sys
import tempfile
import textwrap

from rekall import config
from rekall import obj
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


class TextColumn(renderer.BaseColumn):
    """Implementation for text (mostly CLI) tables."""

    def __init__(self, *args, **kwargs):
        super(TextColumn, self).__init__(*args, **kwargs)

        self.name = self.name or "-"
        self.cname = self.cname or "-"

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
                self.table.renderer.colorizer.Render(
                    x, foreground=color) for x in result]

        return result or [""]


class TextTable(renderer.BaseTable):
    """A table is a collection of columns.

    This table formats all its cells using proportional text font.
    """

    column_class = TextColumn

    def __init__(self, tablesep=" ", elide=False, **kwargs):
        super(TextTable, self).__init__(**kwargs)

        self.tablesep = tablesep
        self.elide = elide

    def write_row(self, cells, highlight=False):
        """Writes a row of the table.

        Args:
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

            self.renderer.write(
                self.renderer.colorizer.Render(
                    self.tablesep.join(line_components),
                    foreground=foreground, background=background) + "\n")

    def render_header(self):
        # The headers must always be calculated so we can work out the column
        # widths.
        headers = [c.render_header() for c in self.columns]

        if not self.suppress_headers:
            self.write_row(headers)

    def render_row(self, row=None, highlight=None):
        # pylint: disable=arguments-differ
        self.write_row(
            [c.render_cell(x) for c, x in zip(self.columns, row)],
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

    Args:
      elide: Causes words to be shortened in the middle if they're longer than
        format spec.
    """
    tablesep = " "
    elide = False
    paging_limit = None
    table_cls = TextTable
    progress_fd = None

    # Render progress with a spinner.
    spinner = r"/-\|"
    last_spin = 0
    last_message_len = 0

    def __init__(self, tablesep=" ", elide=False, output=None, mode="a+b",
                 fd=None, **kwargs):
        super(TextRenderer, self).__init__(**kwargs)

        # Allow the user to dump all output to a file.
        self.output = output or self.session.GetParameter("output")
        if self.output:
            # We append the text output for each command. This allows the user
            # to just set it once for the session and each new command is
            # recorded in the output file.
            fd = open(self.output, mode)

        if fd is None:
            fd = self.session.fd

        if fd is None:
            try:
                fd = Pager(session=self.session)
            except AttributeError:
                fd = sys.stdout

        # Make sure that our output is unicode safe.
        self.fd = UnicodeWrapper(fd)
        self.formatter = renderer.Formatter()

        self.tablesep = tablesep
        self.elide = elide

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
        # Only clear the progress if we share the same output stream as the
        # progress.
        if self.fd is self.progress_fd:
            self.ClearProgress()

        super(TextRenderer, self).format(formatstring, *data)

    def write(self, data):
        self.fd.write(data)

    def flush(self):
        self.data = []
        self.ClearProgress()
        self.fd.flush()

    def table_header(self, *args, **kwargs):
        """Text table header also takes elide and tablesep arguments.

        The rest of this is the same as BaseRenderer.table_header."""
        return super(TextRenderer, self).table_header(
            *args,
            elide=self.elide,
            tablesep=self.tablesep,
            **kwargs
        )

    def table_row(self, *args, **kwargs):
        """Outputs a single row of a table.

        Text tables support these additional kwargs:
          highlight: Highlights this raw according to the color scheme (e.g.
          important, good...)
        """
        return super(TextRenderer, self).table_row(*args, **kwargs)

    def _GetColumns(self):
        if curses:
            return curses.tigetnum('cols')

        return int(os.environ.get("COLUMNS", 80))


    def start(self, plugin_name=None, kwargs=None):
        super(TextRenderer, self).start(plugin_name=plugin_name, kwargs=kwargs)
        if self.output:
            # Remove values which are None.
            if kwargs:
                for k, v in kwargs.items():
                    if v is None:
                        kwargs.pop(k)

            if plugin_name:
                self.section("%s %s" % (plugin_name, kwargs or ""))

        return self

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

    def __init__(self, **kwargs):
        super(TestRenderer, self).__init__(tablesep="||", **kwargs)
