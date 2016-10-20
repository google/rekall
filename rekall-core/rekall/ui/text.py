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

import re
import os
import subprocess
import sys
import tempfile
import textwrap

from rekall import config
from rekall import registry
from rekall import utils

from rekall.ui import renderer as renderer_module


config.DeclareOption(
    "--pager", default=os.environ.get("PAGER"), group="Interface",
    help="The pager to use when output is larger than a screen full.")

config.DeclareOption(
    "--paging_limit", default=None, group="Interface", type="IntParser",
    help="The number of output lines before we invoke the pager.")

config.DeclareOption(
    "--colors", default="auto", type="Choices",
    choices=["auto", "yes", "no"],
    group="Interface", help="Color control. If set to auto only output "
    "colors when connected to a terminal.")


HIGHLIGHT_SCHEME = dict(
    important=(u"WHITE", u"RED"),
    good=(u"GREEN", None),
    neutral=(None, None))


StyleEnum = utils.AttributeDict(
    address="address",
    value="value",
    compact="compact",
    typed="typed",  # Also show type information.
    full="full",
    cow="cow")


# This comes from http://docs.python.org/library/string.html
# 7.1.3.1. Format Specification Mini-Language
FORMAT_SPECIFIER_RE = re.compile(r"""
(?P<fill>[^{}<>=^#bcdeEfFgGnLorsxX0-9])?  # The fill parameter. This can not be
                                          # a format string or it is ambiguous.
(?P<align>[<>=^])?     # The alignment.
(?P<sign>[+\- ])?      # Sign extension.
(?P<hash>\#)?          # Hash means to preceed the whole thing with 0x.
(?P<zerofill>0)?       # Should numbers be zero filled.
(?P<width>\d+)?        # The minimum width.
(?P<comma>,)?
(?P<precision>.\d+)?   # Precision
(?P<type>[bcdeEfFgGnorsxXL%])?  # The format string (Not all are supported).
""", re.X)


def ParseFormatSpec(formatstring):
    if formatstring == "[addrpad]":
        return dict(
            style="address",
            padding="0"
        )

    elif formatstring == "[addr]":
        return {"style": "address"}

    match = FORMAT_SPECIFIER_RE.match(formatstring)
    result = {}

    width = match.group("width")
    if width:
        result["width"] = int(width)

    align = match.group("align")
    if align == "<":
        result["align"] = "l"
    elif align == ">":
        result["align"] = "r"
    elif align == "^":
        result["align"] = "c"

    return result


class Pager(object):
    """A wrapper around a pager.

    The pager can be specified by the session. (eg.
    session.SetParameter("pager", 'less') or in an PAGER environment var.
    """
    # Default encoding is utf8
    encoding = "utf8"

    def __init__(self, session=None, term_fd=None):
        if session == None:
            raise RuntimeError("Session must be set")

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
            color=self.session.GetParameter("colors"),
            session=session
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
        self.fd = tempfile.NamedTemporaryFile(prefix="rekall", delete=False)

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

        try:
            self.fd.flush()
        except ValueError:
            pass

        try:
            args = dict(filename=self.fd.name)
            # Allow the user to interpolate the filename in a special way,
            # otherwise just append to the end of the command.
            if "%" in self.pager_command:
                pager_command = self.pager_command % args
            else:
                pager_command = self.pager_command + " %s" % self.fd.name

            # On windows the file must be closed before the subprocess
            # can open it.
            self.fd.close()

            subprocess.call(pager_command, shell=True)

        # Allow the user to break out from waiting for the command.
        except KeyboardInterrupt:
            pass

        finally:
            try:
                # This will delete the temp file.
                os.unlink(self.fd.name)
            except Exception:
                pass


class Colorizer(object):
    """An object which makes its target colorful."""

    COLORS = u"BLACK RED GREEN YELLOW BLUE MAGENTA CYAN WHITE"
    COLOR_MAP = dict([(x, i) for i, x in enumerate(COLORS.split())])

    terminal_capable = False

    def __init__(self, stream, color="auto", session=None):
        """Initialize a colorizer.

        Args:
          stream: The stream to write to.

          color: If "no" we suppress using colors, even if the output stream
             can support them.
        """
        if session == None:
            raise RuntimeError("Session must be set")

        self.session = session
        self.logging = self.session.logging.getChild("colorizer")

        if stream is None:
            stream = sys.stdout

        # We currently do not support Win32 colors.
        if curses is None or color == "no":
            self.terminal_capable = False

        elif color == "yes":
            self.terminal_capable = True

        elif color == "auto":
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
        except Exception as e:
            self.logging.debug("Unable to set tparm: %s" % e)
            return ""

    def Render(self, target, foreground=None, background=None):
        """Decorate the string with the ansii escapes for the color."""
        if (not self.terminal_capable or
                foreground not in self.COLOR_MAP or
                background not in self.COLOR_MAP):
            return utils.SmartUnicode(target)

        escape_seq = ""
        if background:
            escape_seq += self.tparm(
                ["setab", "setb"], self.COLOR_MAP[background])

        if foreground:
            escape_seq += self.tparm(
                ["setaf", "setf"], self.COLOR_MAP[foreground])

        return (escape_seq + utils.SmartUnicode(target) +
                self.tparm(["sgr0"]))


class TextObjectRenderer(renderer_module.ObjectRenderer):
    """Baseclass for all TextRenderer object renderers."""

    # Fall back renderer for all objects.
    renders_type = "object"
    renderers = ["TextRenderer", "WideTextRenderer", "TestRenderer"]

    __metaclass__ = registry.MetaclassRegistry
    DEFAULT_STYLE = "full"

    @utils.safe_property
    def address_size(self):
        address_size = 14

        # We get the value of the profile via the session state because doing
        # self.session.profile will trigger profile autodetection even when
        # it's not needed.
        if (self.session.HasParameter("profile_obj") and
                self.session.profile.metadata("arch") == "I386"):
            address_size = 10

        return address_size

    def format_address(self, address, **options):
        result = "%x" % address
        padding = options.get("padding", " ")
        if padding == "0":
            return ("0x" + "0" * max(0, self.address_size - 2 - len(result)) +
                    result)

        return padding * max(
            0, self.address_size - 2 - len(result)) + "0x" + result

    def render_header(self, name="", style=StyleEnum.full, hex_width=0,
                      **options):
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
        header_cell = Cell(unicode(name), width=options.get("width", None))

        if style == "address" and header_cell.width < self.address_size:
            header_cell.rewrap(width=self.address_size, align="c")

        self.header_width = max(header_cell.width, len(name))
        header_cell.rewrap(align="c", width=self.header_width)

        # Append a dashed line as a table header separator.
        header_cell.append_line("-" * self.header_width)

        return header_cell

    def render_typed(self, target, **options):
        return Cell(repr(target), **options)

    def render_full(self, target, **options):
        return Cell(utils.SmartUnicode(target), **options)

    def render_address(self, target, width=None, **options):
        if target is None:
            return Cell(width=width)

        return Cell(
            self.format_address(int(target), **options),
            width=width)

    def render_compact(self, *args, **kwargs):
        return self.render_full(*args, **kwargs)

    def render_value(self, *args, **kwargs):
        return self.render_full(*args, **kwargs)

    def render_row(self, target, style=None, **options):
        """Render the target suitably.

        The default implementation calls a render_STYLE method based on the
        style keyword arg.

        Args:
          target: The object to be rendered.

          style: A value from StyleEnum, specifying how the object should
              be renderered.

          options: A dict containing rendering options. The options are created
            from the column options, overriden by the row options and finally
            the cell options.  It is ok for an instance to ignore some or all of
            the options. Some options only make sense in certain Renderer
            contexts.

        Returns:
          A Cell instance containing the rendering of target.
        """
        if not style:
            style = self.DEFAULT_STYLE

        method = getattr(self, "render_%s" % style, None)
        if not callable(method):
            raise NotImplementedError(
                "%s doesn't know how to render style %s." % (
                    type(self).__name__, style))

        cell = method(target, **options)
        if not isinstance(cell, BaseCell):
            raise RuntimeError("Invalid cell renderer.")

        return cell

    def render_cow(self, *_, **__):
        """Renders Bessy the cow."""
        cow = (
            "                                |############          \n"
            "                                |#####  #####          \n"
            "                                |##        ##          \n"
            "              _                 |#####  #####          \n"
            "             / \\_               |############          \n"
            "            /    \\              |                      \n"
            "           /\\/\\  /\\  _          |       /;    ;\\       \n"
            "          /    \\/  \\/ \\         |   __  \\____//        \n"
            "        /\\  .-   `. \\  \\        |  /{_\\_/   `'\\____    \n"
            "       /  `-.__ ^   /\\  \\       |  \\___ (o)  (o)   }   \n"
            "      / _____________________________/          :--'   \n"
            "    ,-,'`@@@@@@@@       @@@@@@         \\_    `__\\      \n"
            "   ;:(  @@@@@@@@@        @@@             \\___(o'o)     \n"
            "   :: )  @@@@          @@@@@@        ,'@@(  `===='     \n"
            "   :: : @@@@@:          @@@@         `@@@:             \n"
            "   :: \\  @@@@@:       @@@@@@@)    (  '@@@'             \n"
            "   :; /\\      /      @@@@@@@@@\\   :@@@@@)              \n"
            "   ::/  )    {_----------------:  :~`,~~;              \n"
            "  ;; `; :   )                  :  / `; ;               \n"
            " ;;;  : :   ;                  :  ;  ; :               \n"
            " `'`  / :  :                   :  :  : :               \n"
            "     )_ \\__;                   :_ ;  \\_\\               \n"
            "     :__\\  \\                   \\  \\  :  \\              \n"
            "         `^'                    `^'  `-^-'             \n")

        cell = Cell(value=cow,
                    highlights=[(33, 45, u"RED", u"RED"),
                                (88, 93, u"RED", u"RED"),
                                (93, 95, u"WHITE", u"WHITE"),
                                (95, 100, u"RED", u"RED"),
                                (143, 145, u"RED", u"RED"),
                                (145, 153, u"WHITE", u"WHITE"),
                                (153, 155, u"RED", u"RED"),
                                (198, 203, u"RED", u"RED"),
                                (203, 205, u"WHITE", u"WHITE"),
                                (205, 210, u"RED", u"RED"),
                                (253, 265, u"RED", u"RED")])
        return cell


class AttributedStringRenderer(TextObjectRenderer):
    renders_type = "AttributedString"

    def render_address(self, *_, **__):
        raise NotImplementedError("This doesn't make any sense.")

    def render_full(self, target, **_):
        return Cell(value=target.value, highlights=target.highlights,
                    colorizer=self.renderer.colorizer)

    def render_value(self, target, **_):
        return Cell(value=target.value)


class CellRenderer(TextObjectRenderer):
    """This renders a Cell object into a Cell object.

    i.e. it is just a passthrough object renderer for Cell objects. This is
    useful for rendering nested tables.
    """
    renders_type = "Cell"

    def render_row(self, target, **_):
        return target


class BaseCell(object):
    """A Cell represents a single entry in a table.

    Cells always have a fixed number of characters in width and may have
    arbitrary number of characters (lines) for a height.

    The TextTable consists of an array of Cells:

    Cell Cell Cell Cell  <----- Headers.
    Cell Cell Cell Cell  <----- Table rows.

    The ObjectRenderer is responsible for turning an arbitrary object into a
    Cell object.
    """

    _width = None
    _height = None
    _align = None
    _lines = None

    # This flag means we have to respect the value of self._width when
    # rebuilding because it was specified explicitly, either through the
    # constructor, or through a call to rewrap.
    width_explicit = False

    # Stretch ("stretch") or push out ("margin", similar to CSS) to desired
    # width?
    mode = "stretch"

    __abstract = True

    def __init__(self, align="l", width=None, **_):
        self._align = align or "l"
        self._width = width
        if self._width:
            self.width_explicit = True

    def __iter__(self):
        return iter(self.lines)

    def __unicode__(self):
        return u"\n".join(self.lines)

    @utils.safe_property
    def lines(self):
        if not self._lines:
            self.rebuild()

        return self._lines

    @utils.safe_property
    def width(self):
        return self._width

    @utils.safe_property
    def height(self):
        return self._height

    @utils.safe_property
    def align(self):
        return self._align

    def dirty(self):
        self._lines = None
        if not self.width_explicit:
            self._width = None

    def rebuild(self):
        raise NotImplementedError("Subclasses must override.")

    def rewrap(self, width=None, align="l", mode="stretch"):
        if width is not None:
            self.width_explicit = True

        if self.width == width and align == self.align and mode == self.mode:
            return

        self._width = width
        self._align = align
        self.mode = mode
        self.dirty()


class JoinedCell(BaseCell):
    """Joins child cells sideways (left to right).

    This is not a replacement for table output! Joined cells are for use when
    an object renderer needs to display a subtable, or when one needs to pass
    on wrapping information onto the table, and string concatenation in the
    Cell class is insufficient.
    """

    def __init__(self, *cells, **kwargs):
        super(JoinedCell, self).__init__(**kwargs)
        self.tablesep = kwargs.pop("tablesep", " ")

        if not cells:
            cells = [Cell("")]

        self.cells = []
        for cell in cells:
            if (isinstance(cell, JoinedCell)
                    and cell.align == self.align
                    and self.mode == self.mode):
                # As optimization, JoinedCells are not nested if we can just
                # consume their contents. However, we have to give the child
                # cell a chance to recalculate and can only do this if the
                # configurations are compatible.
                cell.rebuild()
                self.cells.extend(cell.cells)
            elif isinstance(cell, BaseCell):
                self.cells.append(cell)

            elif not isinstance(cell, basestring):
                raise RuntimeError(
                    "Something went wrong! Cell should be a string.")

        self.rebuild()

    def rebuild(self):
        self._height = 0
        self._lines = []

        # Figure out how wide the contents are going to be and adjust as
        # needed.
        contents_width = 0
        for cell in self.cells:
            contents_width += cell.width + len(self.tablesep)

        contents_width = max(0, contents_width - len(self.tablesep))

        if self.width_explicit or self.width is None:
            self._width = max(self.width, contents_width)
        else:
            self._width = self.width

        adjustment = self._width - contents_width

        # Wrap or pad children.
        if adjustment and self.mode == "stretch" and self.cells:
            align = self.align

            if align == "l":
                child_cell = self.cells[-1]
                child_cell.rewrap(width=adjustment + child_cell.width)
            elif align == "r":
                child_cell = self.cells[0]
                child_cell.rewrap(width=adjustment + child_cell.width)
            elif align == "c":
                self.cells[-1].rewrap(
                    width=(adjustment / 2) + self.cells[-1].width +
                    adjustment % 2)
                self.cells[0].rewrap(
                    width=(adjustment / 2) + self.cells[0].width)
            else:
                raise ValueError(
                    "Invalid alignment %s for JoinedCell." % align)

        # Build up lines from child cell lines.
        for cell in self.cells:
            self._height = max(self.height, cell.height)

        for line_no in xrange(self.height):
            parts = []
            for cell in self.cells:
                try:
                    parts.append(cell.lines[line_no])
                except IndexError:
                    parts.append(" " * cell.width)

            line = self.tablesep.join(parts)
            if self.mode == "margin":
                if self.align == "l":
                    line += adjustment * " "
                elif self.align == "r":
                    line = adjustment * " " + line
                elif self.align == "c":
                    p, r = divmod(adjustment, 2)
                    line = " " * p + line + " " * (p + r)
            self._lines.append(line)

    def __repr__(self):
        return "<JoinedCell align=%s, width=%s, cells=%s>" % (
            repr(self.align), repr(self.width), repr(self.cells))


class StackedCell(BaseCell):
    """Vertically stack child cells on top of each other.

    This is not a replacement for table output! Stacked cells should be used
    when one needs to display multiple lines in a single cell, and the text
    paragraph logic in the Cell class is insufficient. (E.g. rendering faux
    graphics, such as QR codes and heatmaps.)

    Arguments:
    table_align: If True (default) will align child cells as columns.
                 NOTE: With this option, child cells must all be JoinedCell
                 instanes and have exactly the same number of children each.
    """

    def __init__(self, *cells, **kwargs):
        self.table_align = kwargs.pop("table_align", True)
        super(StackedCell, self).__init__(**kwargs)

        self.cells = []
        for cell in cells:
            if isinstance(cell, StackedCell):
                self.cells.extend(cell.cells)
            else:
                self.cells.append(cell)

    @utils.safe_property
    def width(self):
        if not self._lines:
            self.rebuild()

        return self._width

    @utils.safe_property
    def column_count(self):
        if not self.table_align:
            raise AttributeError(
                "Only works for StackedCells with table_align set to True.")
        first_row = self.cells[0]
        if not isinstance(first_row, JoinedCell):
            raise AttributeError(
                ("With table_align is set to True, first cell must be a "
                 "JoinedCell"))
        return len(self.cells[0].cells)

    def rebuild(self):
        target_width = 0
        if self.width_explicit:
            target_width = self._width

        self._width = 0
        self._height = 0
        self._lines = []

        column_widths = []
        if self.table_align:
            for row in self.cells:
                if len(row.cells) > len(column_widths):
                    column_widths.extend([0] * (
                        len(row.cells) - len(column_widths)))

                for column, cell in enumerate(row.cells):
                    w = column_widths[column]
                    if cell.width > w:
                        column_widths[column] = cell.width

        lines = []
        for cell in self.cells:
            for column, width in enumerate(column_widths):
                try:
                    cell.cells[column].rewrap(width=width)
                except IndexError:
                    # Turns out, this row doens't have as many cells as we
                    # have columns (common with last rows).
                    break

            if target_width:
                # Rewrap to fit the target width.
                cell.rewrap(align="l", width=target_width, mode="margin")
            else:
                cell.dirty()  # Gotta update them child cells.

            lines.extend(cell.lines)
            self._height += cell.height
            self._width = max(self._width, cell.width)

        self._lines = lines

    def __repr__(self):
        return "<StackedCell align=%s, _width=%s, cells=%s>" % (
            repr(self.align), repr(self._width), repr(self.cells))


class Cell(BaseCell):
    """A cell for text, knows how to wrap, preserve paragraphs and colorize."""
    _lines = None

    def __init__(self, value="", highlights=None, colorizer=None,
                 padding=0, **kwargs):
        super(Cell, self).__init__(**kwargs)
        self.paragraphs = value.splitlines()
        self.colorizer = colorizer
        self.highlights = highlights or []
        self.padding = padding or 0

        if not self._width:
            if self.paragraphs:
                self._width = max([len(x) for x in self.paragraphs])
            else:
                self._width = 1

        self._width += self.padding

    def justify_line(self, line):
        adjust = self.width - len(line) - self.padding

        if self.align == "l":
            return " " * self.padding + line + " " * adjust, 0
        elif self.align == "r":
            return " " * adjust + line + " " * self.padding, adjust
        elif self.align == "c":
            radjust, r = divmod(adjust, 2)
            ladjust = radjust
            radjust += r

            padding, r = divmod(self.padding, 2)
            radjust += padding
            ladjust += padding
            ladjust += r

            lpad = " " * ladjust
            rpad = " " * radjust
            return lpad + line + rpad, 0
        else:
            raise ValueError("Invalid cell alignment: %s." % self.align)

    def highlight_line(self, line, offset, last_highlight):
        if not self.colorizer.terminal_capable:
            return line

        if last_highlight:
            line = last_highlight + line

        limit = offset + len(line)
        adjust = 0

        for rule in self.highlights:
            start = rule.get("start")
            end = rule.get("end")
            fg = rule.get("fg")
            bg = rule.get("bg")
            bold = rule.get("bold")

            if offset <= start <= limit + adjust:
                escape_seq = ""
                if fg is not None:
                    if isinstance(fg, basestring):
                        fg = self.colorizer.COLOR_MAP[fg]

                    escape_seq += self.colorizer.tparm(
                        ["setaf", "setf"], fg)

                if bg is not None:
                    if isinstance(bg, basestring):
                        bg = self.colorizer.COLOR_MAP[bg]

                    escape_seq += self.colorizer.tparm(
                        ["setab", "setb"], bg)

                if bold:
                    escape_seq += self.colorizer.tparm(["bold"])

                insert_at = start - offset + adjust
                line = line[:insert_at] + escape_seq + line[insert_at:]

                adjust += len(escape_seq)
                last_highlight = escape_seq

            if offset <= end <= limit + adjust:
                escape_seq = self.colorizer.tparm(["sgr0"])

                insert_at = end - offset + adjust
                line = line[:insert_at] + escape_seq + line[insert_at:]

                adjust += len(escape_seq)
                last_highlight = None

        # Always terminate active highlight at the linebreak because we don't
        # know what's being rendered to our right. We will resume
        # last_highlight on next line.
        if last_highlight:
            line += self.colorizer.tparm(["sgr0"])
        return line, last_highlight

    def rebuild(self):
        self._lines = []
        last_highlight = None

        normalized_highlights = []
        for highlight in self.highlights:
            if isinstance(highlight, dict):
                normalized_highlights.append(highlight)
            else:
                normalized_highlights.append(dict(
                    start=highlight[0], end=highlight[1],
                    fg=highlight[2], bg=highlight[3]))

        self.highlights = sorted(normalized_highlights,
                                 key=lambda x: x["start"])

        offset = 0
        for paragraph in self.paragraphs:
            for line in textwrap.wrap(paragraph, self.width):
                line, adjust = self.justify_line(line)
                offset += adjust

                if self.colorizer and self.colorizer.terminal_capable:
                    line, last_highlight = self.highlight_line(
                        line=line, offset=offset, last_highlight=last_highlight)

                self._lines.append(line)

            offset += len(paragraph)

    def dirty(self):
        self._lines = None

    def rewrap(self, width=None, align=None, **_):
        width = width or self.width or max(0, 0, *[len(line)
                                                   for line in self.lines])
        align = align or self.align or "l"

        if (width, align) == (self.width, self.align):
            return self

        self._width = width
        self._align = align
        self.dirty()

        return self

    def append_line(self, line):
        self.paragraphs.append(line)
        self.dirty()

    @utils.safe_property
    def height(self):
        """The number of chars this Cell takes in height."""
        return len(self.lines)

    def __repr__(self):
        if not self.paragraphs:
            contents = "None"
        elif len(self.paragraphs) == 1:
            contents = repr(self.paragraphs[0])
        else:
            contents = repr("%s..." % self.paragraphs[0])

        return "<Cell value=%s, align=%s, width=%s>" % (
            contents, repr(self.align), repr(self.width))


class TextColumn(object):
    """Implementation for text (mostly CLI) tables."""

    # The object renderer used for this column.
    object_renderer = None

    def __init__(self, table=None, renderer=None, session=None, type=None,
                 formatstring=None, **options):
        if session is None:
            raise RuntimeError("A session must be provided.")

        self.session = session
        self.table = table
        self.renderer = renderer
        self.header_width = 0

        # Arbitrary column options to be passed to ObjectRenderer() instances.
        # This allows a plugin to influence the output somewhat in different
        # output contexts.
        self.options = ParseFormatSpec(formatstring) if formatstring else {}
        # Explicit keyword arguments override formatstring.
        self.options.update(options)

        # For columns which do not explicitly set their type, we can not
        # determine the type until the first row has been written. NOTE: It is
        # not supported to change the type of a column after the first row has
        # been written.
        if type:
            self.object_renderer = self.renderer.get_object_renderer(
                type=type, target_renderer="TextRenderer", **options)

    def render_header(self):
        """Renders the cell header.

        Returns a Cell instance for this column header."""
        # If there is a customized object renderer for this column we use that.
        if self.object_renderer:
            header = self.object_renderer.render_header(**self.options)
        else:
            # Otherwise we just use the default.
            object_renderer = TextObjectRenderer(self.renderer, self.session)
            header = object_renderer.render_header(**self.options)

        self.header_width = header.width

        return header

    def render_row(self, target, **options):
        """Renders the current row for the target."""
        # We merge the row options and the column options. This allows a call to
        # table_row() to override options.
        merged_opts = self.options.copy()
        merged_opts.update(options)

        if merged_opts.get("nowrap"):
            merged_opts.pop("width", None)

        if self.object_renderer is not None:
            object_renderer = self.object_renderer
        else:
            object_renderer = self.table.renderer.get_object_renderer(
                target=target, type=merged_opts.get("type"),
                target_renderer="TextRenderer", **options)

        if target is None:
            result = Cell(width=merged_opts.get("width"))
        else:
            result = object_renderer.render_row(target, **merged_opts)
            result.colorizer = self.renderer.colorizer

        # If we should not wrap we are done.
        if merged_opts.get("nowrap"):
            return result

        if "width" in self.options or self.header_width > result.width:
            # Rewrap if we have an explicit width (and wrap wasn't turned off).
            # Also wrap to pad if the result is actually narrower than the
            # header, otherwise it messes up the columns to the right.
            result.rewrap(width=self.header_width,
                          align=merged_opts.get("align", result.align))

        return result

    @utils.safe_property
    def name(self):
        return self.options.get("name") or self.options.get("cname", "")


class TextTable(renderer_module.BaseTable):
    """A table is a collection of columns.

    This table formats all its cells using proportional text font.
    """

    column_class = TextColumn
    deferred_rows = None

    def __init__(self, auto_widths=False, **options):
        super(TextTable, self).__init__(**options)

        # Respect the renderer's table separator preference.
        self.options.setdefault("tablesep", self.renderer.tablesep)

        # Parse the column specs into column class implementations.
        self.columns = []

        for column_specs in self.column_specs:
            column = self.column_class(session=self.session, table=self,
                                       renderer=self.renderer, **column_specs)
            self.columns.append(column)

        # Auto-widths mean we calculate the optimal width for each column.
        self.auto_widths = auto_widths

        # If we want to autoscale each column we must defer rendering.
        if auto_widths:
            self.deferred_rows = []

    def write_row(self, *cells, **kwargs):
        """Writes a row of the table.

        Args:
          cells: A list of cell contents. Each cell content is a list of lines
            in the cell.
        """
        highlight = kwargs.pop("highlight", None)
        foreground, background = HIGHLIGHT_SCHEME.get(
            highlight, (None, None))

        # Iterate over all lines in the row and write it out.
        for line in JoinedCell(tablesep=self.options.get("tablesep"), *cells):
            self.renderer.write(
                self.renderer.colorizer.Render(
                    line, foreground=foreground, background=background) + "\n")

    def render_header(self, **options):
        """Returns a Cell formed by joining all the column headers."""
        # Get each column to write its own header and then we join them all up.
        result = []
        for c in self.columns:
            merged_opts = c.options.copy()
            merged_opts.update(options)
            if not merged_opts.get("hidden"):
                result.append(c.render_header())

        return JoinedCell(
            *result, tablesep=self.options.get("tablesep", " "))

    def get_row(self, *row, **options):
        """Format the row into a single Cell spanning all output columns.

        Args:
          *row: A list of objects to render in the same order as columns are
             defined.

        Returns:
          A single Cell object spanning the entire row.
        """
        result = []
        for c, x in zip(self.columns, row):
            merged_opts = c.options.copy()
            merged_opts.update(options)
            if not merged_opts.get("hidden"):
                result.append(c.render_row(x, **options))

        return JoinedCell(
            *result, tablesep=self.options.get("tablesep", " "))

    def render_row(self, row=None, highlight=None, annotation=False, **options):
        """Write the row to the output."""
        if annotation:
            self.renderer.format(*row)
        elif self.deferred_rows is None:
            return self.write_row(self.get_row(*row, **options),
                                  highlight=highlight)
        else:
            self.deferred_rows.append((row, options))

    def flush(self):
        if self.deferred_rows is not None:
            # Calculate the optimal widths.
            if self.auto_widths:
                total_width = self.renderer.GetColumns() - 10

                max_widths = []
                for i, column in enumerate(self.columns):
                    length = 1
                    for row in self.deferred_rows:
                        try:
                            # Render everything on the same line
                            rendered_lines = column.render_row(
                                row[0][i], nowrap=1).lines


                            if rendered_lines:
                                rendered_line = rendered_lines[0]
                            else:
                                rendered_line = ""

                            length = max(length, len(rendered_line))

                        except IndexError:
                            pass

                    max_widths.append(length)

                # Now we have the maximum widths of each column. The problem is
                # about dividing the total_width into the best width so as much
                # fits.
                sum_of_widths = sum(max_widths)
                for column, max_width in zip(self.columns, max_widths):
                    width = min(
                        max_width * total_width / sum_of_widths,
                        max_width + 1)

                    width = max(width, len(unicode(column.name)))
                    column.options["width"] = width

            # Render the headers now.
            if not self.options.get("suppress_headers"):
                for line in self.render_header():
                    self.renderer.write(line + "\n")

            self.session.report_progress("TextRenderer: sorting %(spinner)s")
            for row, options in self.deferred_rows:
                self.write_row(self.get_row(*row, **options))


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


class TextRenderer(renderer_module.BaseRenderer):
    """Renderer for the command line that supports paging, colors and progress.
    """
    name = "text"

    tablesep = " "
    paging_limit = None
    progress_fd = None

    deferred_rows = None

    # Render progress with a spinner.
    spinner = r"/-\|"
    last_spin = 0
    last_message_len = 0

    table_class = TextTable

    def __init__(self, tablesep=" ", output=None, mode="a+b", fd=None,
                 **kwargs):
        super(TextRenderer, self).__init__(**kwargs)

        # Allow the user to dump all output to a file.
        self.output = output
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
        self.tablesep = tablesep

        # We keep the data that we produce in memory for while.
        self.data = []

        # Write progress to stdout but only if it is a tty.
        self.progress_fd = UnicodeWrapper(sys.stdout)
        if not self.progress_fd.isatty():
            self.progress_fd = None

        self.colorizer = Colorizer(
            self.fd,
            color=self.session.GetParameter("colors"),
            session=self.session)
        self.logging = self.session.logging.getChild("renderer.text")

    def section(self, name=None, width=50):
        if name is None:
            self.write("*" * width + "\n")
        else:
            pad_len = width - len(name) - 2  # 1 space on each side.
            padding = "*" * (pad_len / 2)  # Name is centered.

            self.write("\n{0} {1} {2}\n".format(padding, name, padding))

    def format(self, formatstring, *data):
        """Parse and interpolate the format string.

        A format string consists of a string with interpolation markers
        embedded. The syntax for an interpolation marker is
        {pos:opt1=value,opt2=value}, where pos is the position of the data
        element to interpolate, and opt1, opt2 are the options to provide the
        object renderer.

        For example:

        renderer.format("Process {0:style=compact}", task)

        For backwards compatibility we support the following syntaxes:
        {0:#x} equivalent to {0:style=address}
        {1:d} equivalent to {1}


        """
        super(TextRenderer, self).format(formatstring, *data)

        # Only clear the progress if we share the same output stream as the
        # progress.
        if self.fd is self.progress_fd:
            self.ClearProgress()

        default_pos = 0
        # Currently use a very simple regex to format - we dont support
        # outputting {} chars.
        for part in re.split("({.*?})", formatstring):
            # Literal.
            if not part.startswith("{"):
                self.write(part)
                continue

            # By default use compact style unless specified otherwise.
            options = dict(style="compact")
            position = None

            # Parse the format string - we do not support anything too complex
            # now.
            m = re.match(r"{(\d+):(.+)}", part)
            if m:
                position = int(m.group(1))
                option_string = m.group(2)

            m = re.match(r"{(\d*)}", part)
            if m:
                option_string = ""
                if not m.group(1):
                    position = default_pos
                    default_pos += 1
                else:
                    position = int(m.group(1))

            if position is None:
                self.logging.error("Unknown format specifier: %s", part)
                continue

            # These are backwards compatible hacks. Newer syntax is
            # preferred.
            if option_string in ["#x", "08x", "8x", "addr"]:
                options["style"] = "address"
                options["padding"] = ""

            elif option_string == "addrpad":
                options["style"] = "address"
                options["padding"] = "0"

            elif "=" in option_string:
                for option_part in option_string.split(","):
                    if "=" in option_part:
                        key, value = option_part.split("=", 1)
                        options[key.strip()] = value.strip()
                    else:
                        options[option_part] = True
            else:
                options.update(ParseFormatSpec(option_string))

            # Get the item to be interpolated.
            item = data[position]

            # Now find the correct object renderer.
            obj_renderer = TextObjectRenderer.ForTarget(item, self)(
                renderer=self, session=self.session)

            self.write(obj_renderer.render_row(item, **options))

    def write(self, data):
        self.fd.write(data)

    def flush(self):
        super(TextRenderer, self).flush()
        self.data = []
        self.ClearProgress()
        self.fd.flush()

    def table_header(self, *args, **options):
        options["tablesep"] = self.tablesep
        super(TextRenderer, self).table_header(*args, **options)

        # Skip the headers if there are deferred_rows.
        if (self.table.deferred_rows is not None or
                self.table.options.get("suppress_headers") or
                self.table.auto_widths):
            return

        for line in self.table.render_header(**options):
            self.write(line + "\n")

    def table_row(self, *args, **kwargs):
        """Outputs a single row of a table.

        Text tables support these additional kwargs:
          highlight: Highlights this raw according to the color scheme (e.g.
                     important, good...)
        """
        super(TextRenderer, self).table_row(*args, **kwargs)
        self.RenderProgress(message=None)

    def GetColumns(self):
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
            message = message[:self.GetColumns()]

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

        if directory is None:
            directory, filename = os.path.split(filename)

        filename = utils.SmartStr(filename) or "Unknown%s" % self._object_id

        # Filter the filename for illegal chars.
        filename = re.sub(
            r"[^a-zA-Z0-9_.@{}\[\]\- ]",
            lambda x: "%" + x.group(0).encode("hex"),
            filename)

        if directory:
            filename = os.path.join(directory, "./", filename)

        if "w" in mode:
            try:
                os.makedirs(directory)
            except (OSError, IOError):
                pass

        return open(filename, mode)


class TestRenderer(TextRenderer):
    """A special renderer which makes parsing the output of tables easier."""
    name = "test"

    def __init__(self, **kwargs):
        super(TestRenderer, self).__init__(tablesep="||", **kwargs)

    def GetColumns(self):
        # Return a predictable and stable width.
        return 138


class WideTextRenderer(TextRenderer):
    """A Renderer which explodes tables into wide formatted records."""

    name = "wide"

    def __init__(self, **kwargs):
        super(WideTextRenderer, self).__init__(**kwargs)

        self.delegate_renderer = TextRenderer(**kwargs)

    def __enter__(self):
        self.delegate_renderer.__enter__()
        self.delegate_renderer.table_header([
            dict(name="Key", width=15),
            dict(name="Value")
        ], suppress_headers=True)

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

        for c, cell in zip(self.table.columns, values):
            column_name = (getattr(c.object_renderer, "name", None) or
                           c.options.get("name"))

            # Skip empty columns.
            if not cell.lines:
                continue

            self.delegate_renderer.table_row(column_name, cell, **options)


class TreeNodeObjectRenderer(TextObjectRenderer):
    renders_type = "TreeNode"

    def __init__(self, renderer=None, session=None, **options):
        self.max_depth = options.pop("max_depth", 10)
        child_spec = options.pop("child", None)
        if child_spec:
            child_type = child_spec.get("type", "object")
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
            heading = JoinedCell(self.child.render_header(**options))
        else:
            heading = super(TreeNodeObjectRenderer, self).render_header(
                **options)

        self.heading_width = heading.width
        return heading

    def render_row(self, target, depth=0, child=None, **options):
        if not child:
            child = {}

        if self.child:
            child_renderer = self.child
        else:
            child_renderer = self.ForTarget(target, renderer=self.renderer)(
                session=self.session, renderer=self.renderer)

        child_cell = child_renderer.render_row(target, **child)
        child_cell.colorizer = self.renderer.colorizer

        padding = Cell("." * depth)
        result = JoinedCell(padding, child_cell)

        return result


class DividerObjectRenderer(TextObjectRenderer):
    renders_type = "Divider"

    def __init__(self, renderer=None, session=None, **options):
        child_spec = options.pop("child", None)
        if child_spec:
            child_type = child_spec.get("type", "object")
            self.child = self.ByName(child_type, renderer)(
                renderer, session=session, **child_spec)

            if not self.child:
                raise AttributeError("Child %s of Divider was not found." %
                                     child_type)
        else:
            self.child = None

        super(DividerObjectRenderer, self).__init__(
            renderer, session=session, **options)

    def render_header(self, **options):
        self.header_width = 0
        return Cell("")

    def render_row(self, target, child=None, **options):
        last_row = self.renderer.table.options.get("last_row")
        if last_row == target:
            return Cell("")

        self.renderer.table.options["last_row"] = target

        if not child:
            child = dict(wrap=False)

        if self.child:
            child_renderer = self.child
        else:
            child_renderer = self.ForTarget(target, renderer=self.renderer)(
                session=self.session, renderer=self.renderer)

        child_cell = child_renderer.render_row(target, **child)
        child_cell.colorizer = self.renderer.colorizer

        return StackedCell(
            Cell("-" * child_cell.width),
            child_cell,
            Cell("-" * child_cell.width),
            table_align=False)
