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

"""This module implements various visual aides and their renderers."""

from rekall.ui import colors
from rekall.ui import text
from rekall import utils


class DepthIndicator(int):
    pass


class DepthIndicatorRenderer(text.TextObjectRenderer):
    renders_type = "DepthIndicator"

    def render_row(self, target, **_):
        return text.Cell("." * int(target))


class MemoryMap(object):
    """Represents a map of memory regions with various highlighting.

    Memory maps are divided into rows with constant number of cells, each
    with individual highlighting rules (mostly coloring).

    Attributes:
    ==========
    column_headers: As table headers.
    row_headers: (Optional) First column with row headers.
    caption: (Optional) Should describe relationship between headers
             and row headers. Rendering is up to the renderer.
    greyscale: If False (default) heatmap intensity values will be translated
               into colors with increasing hue. If True, shades of grey will
               be used instead with varying luminosity.

               Some subclasses may enforce this to be True or False.
    legend: Instance of MapLegend explaining the map.
    rows: Rows of constant number of cells each.
    cells (read-only): All the cells.

    Cell format:
    ============
    Each cell is a dict with the following public keys:

    heat (optional): Number between 0 and 1.0 signifying the relative heat.
                     Will be converted to color at rendering.
                     If not given, rgb must be given.
    bg (optional): The actual desired color of the cell, given as tuple of
                   (red, green, blue) with values of each in the 0-255 range.
                   If not given, heat must be given.
    fg (optional): Foreground color. Better not specified, will be derived
                   from background.
    value (optional): String contents of the cell. Usually something like
                      a number of hits in that part of the heatmap.

    Cells may also end up containing non-public keys that are implementation
    specific; they'll always be prefixed with an underscore, in the great
    Pythonic tradition.
    """

    rows = None
    legend = None
    row_headers = None
    column_headers = None
    caption = "Offset"
    greyscale = False

    def __init__(self, session=None, *_, **__):
        self.session = session

    @staticmethod
    def _make_memorymap_headers(offset, limit, column_count, resolution):
        """Will make row and column headers suitable for maps of memory.

        The mapped region starts at 'offset' and ends at 'limit'. Each row
        represents a region of memory subdivided into columns, so that rows
        are labeled with the absolute offset from 0, and columns are labeled
        with relative offsets to the row they're in.

        Returns tuple of (row_headers, column_headers).
        """
        size = limit - offset

        # Template for column headers. We pad to the length that's necessary
        # to format on the order of resolution as a hexadecimal number.
        column_tpl = "+%%0.%dx" % len("%x" % resolution)
        columns = [column_tpl % c for c
                   in xrange(offset, resolution * column_count, resolution)]

        row_count, r = divmod(size, column_count * resolution)
        if r:
            row_count += 1

        row_tpl = "0x%x"
        rows = [row_tpl % (r * resolution * column_count)
                for r in xrange(row_count)]

        return rows, columns

    @utils.safe_property
    def cells(self):
        for row in self.rows:
            for cell in row:
                yield cell


class RunBasedMap(MemoryMap):
    """MemoryMap representing discrete ranges in memory.

    Colors, names and sigils representing the ranges will be read from the
    legend.

    Arguments:
    ==========
    runs: dict of "start" (int), "end" (int) and "value" (str).
          The value will be used to look up colors and sigils in the legend, so
          it has to match an entry in the legend.
    legend: Instance of MapLegend - see doc there.
    limit: The highest address in the map. Optional - if not supplied,
           the map will show up to the end of the highest range.
    offset: The lowest address in the map. Optional - if not supplied, map
            will start at zero.
    caption: Explanation of what the map is showing. Default is 'Offset'
             and is typically overriden to something like 'Offset (v)'.
    resolution: How many bytes one cell in the map represents.
    cell_width: How long of a string is permitted in the cells themselves.
                This value is important because the cells show sigils
                (see MapLegend) in order of representation.
    blend: Should the map attempt to blend the color of overlapping ranges?
           If False the map basically becomes a painter's algorithm.
    column_count: How many columns wide should the map be? Lowering this
                  value will result in more rows.
    cell_count: Alternative to providing resolution, caller may request a map
                of constant size, with variable resolution.
    """

    def __init__(self, runs, legend, offset=None, limit=None, caption="Offset",
                 resolution=0x100000, cell_width=6, blend=True,
                 cell_count=None, column_count=8, *args, **kwargs):
        # This is a monster of a constructor, but it wouldn't actually be
        # more readable as separate functions. In short, this will:
        # 1. Figure out how big the map needs to be.
        # 2. Chunk up the runs into preallocated cells and blend the colors.
        # 3. Do another pass to decide what sigils to display, based on
        #    relative weights of runs represented in each cell.
        super(RunBasedMap, self).__init__(*args, **kwargs)

        if cell_count and resolution or not (cell_count or resolution):
            raise ValueError(
                ("Must specify EITHER resolution (got %s) OR cell count "
                 "(got %s).") % (repr(cell_count), repr(resolution)))

        if not runs:
            raise ValueError("Must provide runs.")

        # Determine how many cells we need and preallocate them.
        # Sort the runs by start.
        runs = sorted(runs, key=lambda run: run["start"])

        if not offset:
            offset = runs[0]["start"]

        if not limit:
            limit = runs[-1]["end"]

        # How many cells are we going to need to represent this thing?
        if cell_count:
            resolution = (limit - offset) / cell_count
        else:
            cell_count, r = divmod(limit - offset, resolution)
            if r:
                cell_count += 1

        # Prefabricate the required cells. They contain mutable members, hence
        # this, somewhat awkward, construct.
        cells = [self._make_cell() for _ in xrange(cell_count)]

        # Chunk up the runs and populate cells, blending RGB as needed.
        for run in runs:
            start = run["start"]
            if start < offset:
                start = offset

            end = run["end"]
            if end > limit:
                end = limit

            value = run["value"]
            rgb = legend.colors.get(value, (0, 0, 0))
            sigil = legend.sigils.get(value)
            if not sigil:
                sigil = "?"
                self.session.logging.warning("Unknown memory region %s!", value)

            # Chunks need to align to resolution increments.
            mod = start % resolution
            for chunk in xrange(start - mod, end, resolution):
                cell_idx = chunk / resolution
                chunk_start = max(chunk, start)
                chunk_end = min(chunk + resolution, end)
                chunk_size = chunk_end - chunk_start
                chunk_weight = resolution / float(chunk_size)
                chunk_rgb = rgb

                cell = cells[cell_idx]
                prev_weight = cell["_weight"]

                if blend and prev_weight:
                    chunk_rgb = colors.BlendRGB(x=cell["bg"],
                                                y=rgb,
                                                wx=prev_weight,
                                                wy=chunk_weight)

                prev_sigils = cell["_sigils"]
                prev_sigils.setdefault(sigil, 0.0)
                prev_sigils[sigil] += chunk_weight

                cell["_weight"] = chunk_weight + prev_weight
                cell["bg"] = chunk_rgb
                cell["_idx"] = cell_idx

        # Loop over cells and set up their string contents with sigils.
        rows = []
        row = None
        for i, cell in enumerate(cells):
            if i % column_count == 0:
                row = []
                rows.append(row)

            room = cell_width
            string = ""
            for sigil, _ in sorted(cell["_sigils"].iteritems(),
                                   key=lambda x: x[1], reverse=True):
                if len(sigil) < room:
                    string += sigil
                    room -= len(sigil)

                if not room:
                    break

            cell["value"] = string or "-"
            row.append(cell)

        self.runs = runs
        self.rows = rows
        self.legend = legend
        self.caption = caption
        self.row_headers, self.column_headers = self._make_memorymap_headers(
            limit=limit, offset=offset, resolution=resolution,
            column_count=column_count)
        self.greyscale = False

    @staticmethod
    def _make_cell():
        """Prefab cell with some default values already set."""
        return dict(_weight=0.0,
                    _sigils=dict(),
                    bg=(0, 0, 0),
                    value="-")


class Heatmap(MemoryMap):
    """MemoryMap with colors assigned based on heat."""

    def __init__(self, cells, caption=None, row_headers=None,
                 column_headers=None, legend=None, greyscale=False, *args,
                 **kwargs):
        super(Heatmap, self).__init__(*args, **kwargs)

        rows = []
        column_count = len(column_headers)
        for i, cell in enumerate(cells):
            if i % column_count == 0:
                row = []
                rows.append(row)
            row.append(cell)

        self.rows = rows
        self.row_headers = row_headers
        self.column_headers = column_headers
        self.caption = caption
        self.legend = legend or HeatmapLegend()
        self.greyscale = greyscale

    @classmethod
    def from_hitcount(cls, hits, bucket_size, ceiling=None):
        """Build a heatmap from a collection of hits falling into buckets.

        Returns instance of HeatMap with only rows set. Caller should set
        row_headers, column_headers, caption, legend and greyscale as desired.

        Arguments:
        ==========
        hits: List of addresses where something hit.
        bucket_size: Size of each bucket to divide hits up between.
        ceiling (optional): Max number of hits per bucket. If not given
                            will be determined. The ceiling isn't enforced -
                            exceeding cells will appear as such.
        """
        buckets = []
        for hit in hits:
            bucket_idx = hit / bucket_size

            # Do we need to allocate more buckets?
            for _ in xrange(bucket_idx - len(buckets) + 1):
                buckets.append(0)

            buckets[bucket_idx] += 1

        ceiling = ceiling or max(*buckets)
        tpl = "%%d/%d" % ceiling
        cells = [dict(heat=float(x) / ceiling, value=tpl % x)
                 for x in buckets]

        return cls(cells=cells)


class MapLegend(object):
    """Describes a (heat) map using colors, sigils and optional description.

    Attributes:
    notes: Optional text to display next to the legend (depends on renderer.)
    legend: List of tuples of ((str) sigil, (str) name, (r,g,b) color).

    Sigils, names and colors:
    A name is a long, descriptive title of each range. E.g. "ACPI Memory"
    A sigil is a short (len 1-2) symbol which will be displayed within each
    cell for more clarity (by some renderers). E.g. "Ac"
    A color is a tuple of (red, green, blue) and is exactly what it sounds
    like.
    """

    def __init__(self, legend, notes=None):
        self.notes = notes
        self.legend = legend
        self.colors = {}
        self.sigils = {}
        for sigil, title, rgb in legend:
            self.colors[title] = rgb
            self.sigils[title] = sigil


def HeatmapLegend():
    return MapLegend(
        [(None, "%.1f" % (heat / 10.0), colors.HeatToRGB(heat / 10.0))
         for heat in xrange(11)])


class MemoryMapTextRenderer(text.TextObjectRenderer):
    renders_type = "MemoryMap"

    def render_address(self, *_, **__):
        raise NotImplementedError()

    def render_full(self, target, **options):
        column_headers = []
        row_headers = []

        for row_header in target.row_headers or ():
            row_headers.append(text.Cell(
                row_header, align="r", padding=1))

        # If we're prepending row headers we need an extra column on the left.
        if row_headers:
            column_headers.append(text.Cell(
                target.caption or "-", padding=1))
        for column_header in target.column_headers:
            column_headers.append(text.Cell(
                column_header, align="c", padding=1))

        rows = [text.JoinedCell(*column_headers, tablesep="")]
        for idx, row in enumerate(target.rows):
            cells = []
            if row_headers:
                cells.append(row_headers[idx])

            for cell in row:
                fg = cell.get("fg")
                bg = cell.get("bg")
                heat = cell.get("heat")
                if heat and not bg:
                    bg = colors.HeatToRGB(heat, greyscale=target.greyscale)

                bg = colors.RGBToXTerm(*bg) if bg else None

                if bg and not fg:
                    fg = colors.XTermTextForBackground(bg)

                cells.append(text.Cell(
                    value=unicode(cell.get("value", "-")),
                    highlights=[dict(
                        bg=bg, fg=fg, start=0, end=-1, bold=True)],
                    colorizer=self.renderer.colorizer,
                    padding=1))

            rows.append(text.JoinedCell(*cells, tablesep="", align="l"))

        return text.StackedCell(*rows, align="l")

    def render_value(self, *_, **__):
        raise NotImplementedError

    def render_compact(self, target, **_):
        return text.Cell(repr(target))


class MapLegendRenderer(text.TextObjectRenderer):
    renders_type = "MapLegend"

    def render_full(self, target, **options):
        orientation = options.pop("orientation", "vertical")

        cells = []
        for sigil, description, bg in target.legend:
            bg = colors.RGBToXTerm(*bg)
            fg = colors.XTermTextForBackground(bg)
            if sigil:
                title = "%s (%s)" % (description, sigil)
            else:
                title = description
            cell = text.Cell(
                value=title,
                highlights=[dict(bg=bg, fg=fg, start=0, end=-1)],
                colorizer=self.renderer.colorizer,
                padding=2,
                align="c")
            cells.append(cell)

        if orientation == "vertical":
            legend = text.StackedCell(*cells, table_align=False)
        elif orientation == "horizontal":
            legend = text.JoinedCell(*cells)
        else:
            raise ValueError("Invalid orientation %s." % orientation)

        if target.notes:
            cell = text.Cell(target.notes)
            legend = text.StackedCell(cell, legend, table_align=False)

        return legend

    def render_address(self, *_, **__):
        raise NotImplementedError()

    def render_value(self, *_, **__):
        raise NotImplementedError()

    def render_compact(self, target, **_):
        return text.Cell(repr(target))
