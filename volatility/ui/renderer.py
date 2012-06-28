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
import os
import subprocess
import sys
import textwrap
import time

from volatility import fmtspec
from volatility import utils


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
        self.pager = subprocess.Popen(pager, shell=True, stdin=subprocess.PIPE, bufsize=10240)

    def write(self, data):
        # Encode the data according to the output encoding.
        data = utils.SmartUnicode(data).encode(self.encoding, "replace")
        try:
            self.pager.stdin.write(data)
            self.pager.stdin.flush()
        except IOError:
            raise KeyboardInterrupt("Pipe Error")

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


class TextRenderer(object):
    """Plugins can receive a renderer object to assist formatting of output."""

    tablesep = " "
    elide = True
    spinner = "/-\|"
    last_spin_time = 0
    last_spin = 0
    last_message_len = 0

    def __init__(self, session=None, fd=None):
        self.session = session
        self.fd = fd
        self.isatty = False

    def start(self):
        """The method is called when new output is required."""
        # When piping to a pager do not draw progress - this confuses the pager.
        if self.fd is None and self.session.pager:
            self.pager = Pager(session=self.session)
            self.isatty = False

        elif self.fd:
            # When outputting to file we can draw progress.
            self.pager = UnicodeWrapper(self.fd)
            if self.fd != sys.stdout:
                self.isatty = True
                self.session.progress = self.RenderProgress

        else:
            # When outputting to the terminal we can draw progress.
            self.pager = UnicodeWrapper(sys.stdout)
            self.isatty = sys.stdout.isatty()
            self.session.progress = self.RenderProgress

    def end(self):
        """Tells the renderer that we finished using it for a while."""
        sys.stdout.write("\r")
        self.pager.flush()
        self.session.progress = None

    def write(self, data):
        if self.isatty:
            sys.stdout.flush()
            sys.stdout.write("\r")
            sys.stdout.flush()

        self.pager.write(data)

    def flush(self):
        self.pager.flush()

    def _elide(self, string, length):
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

    def _formatlookup(self, code):
        """Code to turn profile specific values into format specifications"""
        # Allow the format code to be provided as dict for directly initializing
        # a FormatSpec object.
        if isinstance(code, dict):
            return fmtspec.FormatSpec(**code)

        code = code or ""
        # Allow extended format specifiers (e.g. [addr] or [addrpad])
        if not code.startswith('['):
            return fmtspec.FormatSpec(code)

        # Strip off the square brackets
        code = code[1:-1].lower()
        if code.startswith('addr'):
            spec = fmtspec.FormatSpec("#10x")
            if self.session.profile.metadata('memory_model') == '64bit':
                spec.minwidth += 8

            if 'pad' in code:
                spec.fill = "0"
                spec.align = spec.align if spec.align else "="

            else:
                # Non-padded addresses will come out as numbers,
                # so titles should align >
                spec.align = ">"
            return spec

        # Something went wrong
        debug.warning("Unknown table format specification: " + code)
        return ""

    def table_header(self, title_format_list = None, suppress_headers=False):
        """Table header renders the title row of a table.

        This also stores the header types to ensure everything is formatted
        appropriately.  It must be a list of tuples rather than a dict for
        ordering purposes.

        Args:

           title_format_list: A list of (Name, formatstring) tuples describing
              the table headers.

           suppress_headers: If True table headers will not be written (still
              useful for formatting).
        """
        titles = []
        rules = []
        self._formatlist = []

        for (k, v) in title_format_list:
            spec = self._formatlookup(v)

            # If spec.minwidth = -1, this field is unbounded length
            if spec.minwidth != -1:
                spec.minwidth = max(spec.minwidth, len(k))

            # Get the title specification to follow the alignment of the field
            titlespec = fmtspec.FormatSpec(formtype='s',
                                           minwidth=max(spec.minwidth, len(k)))

            titlespec.align = spec.align if spec.align in "<>^" else "<"

            # Add this to the titles, rules, and formatspecs lists
            titles.append((u"{0:" + titlespec.to_string() + "}").format(k))
            rules.append("-" * titlespec.minwidth)
            self._formatlist.append(spec)

        # Write out the titles and line rules
        if not suppress_headers:
            self.write(self.tablesep.join(titles) + "\n")
            self.write(self.tablesep.join(rules) + "\n")

    def table_row(self, *args):
        """Outputs a single row of a table"""
        reslist = []
        cell_widths = []
        if len(args) > len(self._formatlist):
            logging.error("Too many values for the table")

        number_of_lines = 0

        for index in range(len(args)):
            spec = self._formatlist[index]
            formatted_output = (u"{0:" + spec.to_string() + "}").format(args[index])
            if spec.elide:
                result = [self._elide(formatted_output, spec.minwidth)]
            elif spec.wrap:
                result = []

                for line in formatted_output.split("\n"):
                    result.extend(textwrap.wrap(
                            line, spec.width, replace_whitespace=False))
            else:
                result = [formatted_output]

            reslist.append(result)
            number_of_lines = max(number_of_lines, len(result))
            cell_widths.append(len(result[0]))

        # Allow table rows to span multiple text lines.
        for i in range(number_of_lines):
            row = []
            for j, cell_content in enumerate(reslist):
                try:
                    row.append(cell_content[i])
                except IndexError:
                    row.append(" " * cell_widths[j])

            self.write(self.tablesep.join(row))
            self.write("\n")

    def RenderProgress(self, message="", force=False, **_):
        if self.isatty:
            # Only write once per second.
            now = time.time()
            if force or now > self.last_spin_time + 0.2:
                self.last_spin_time = now
                self.last_spin += 1
                if not message:
                    message = self.spinner[self.last_spin % len(self.spinner)]

                sys.stdout.write("\r" + " " * self.last_message_len + "\r")
                self.last_message_len = len(message)
                sys.stdout.write(message)
                sys.stdout.flush()
