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
import time

from rekall import obj
from rekall import utils

from rekall.ui import renderer


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
                self.table.renderer.color(x, foreground=color) for x in result]

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
                self.renderer.color(
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


class TextRenderer(renderer.BaseRenderer):
    """Renderer for the command line that supports paging, colors and progress.

    Args:
      elide: Causes words to be shortened in the middle if they're longer than
        format spec.
    """
    tablesep = " "
    elide = False
    isatty = False
    paging_limit = None
    table_cls = TextTable

    def __init__(self, tablesep=" ", elide=False, max_data=1024*1024,
                 **kwargs):
        super(TextRenderer, self).__init__(**kwargs)

        self.tablesep = tablesep
        self.elide = elide

        # We keep the data that we produce in memory for while.
        self.data = []
        self.max_data = max_data

        # Write progress to stdout but only if it is a tty.
        if sys.stdout.isatty():
            self.progress_fd = sys.stdout

        self.colorizer = Colorizer(
            self.fd,
            nocolor=(self.session and self.session.GetParameter("nocolors")),
        )

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


class TestRenderer(TextRenderer):
    """A special renderer which makes parsing the output of tables easier."""

    def __init__(self, **kwargs):
        super(TestRenderer, self).__init__(tablesep="||", **kwargs)
