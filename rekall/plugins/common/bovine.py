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

"""The plugins in this module are mainly used to visually test renderers."""

__author__ = "Adam Sindelar <adamsh@google.com>"

import itertools

from rekall import plugin
from rekall import algo
from rekall import utils

from rekall.plugins.renderers import visual_aides


class RekallBovineExperience3000(plugin.Command):
    """Renders Bessy the cow and some beer.

    This is a text renderer stress-test. It uses multiple features at the
    same time:

    - Multiple coloring rules per line (this was a doozy).
    - Two columns with colors next to each other.
    - Text with its own newlines isn't rewrapped.
    - It still wraps if it overflows the cell.
    - Bovine readiness and international spirit.
    """
    __name = "moo"

    def render(self, renderer):
        renderer.table_header([
            dict(name="Dogma", width=35, style="full"),
            dict(name="Bessy", width=65, type="bool", style="cow"),
            dict(name="Pilsner", width=50, style="full"),
            dict(name="Nowrap", width=10, nowrap=True)])

        fixtures = self.session.LoadProfile("tests/fixtures")
        beer = fixtures.data["ascii_art"]["beer"]
        phys_map = fixtures.data["fixtures"]["phys_map"]

        renderer.table_row(
            ("This is a renderer stress-test. The flags should have correct"
             " colors, the beer should be yellow and the cell on the left"
             " should not bleed into the cell on the right.\n"
             "This is a really "
             "long column of text with its own newlines in it!\n"
             "This bovine experience has been brought to you by Rekall."),
            True,
            utils.AttributedString("\n".join(beer["ascii"]),
                                   beer["highlights"]),
            ("This is a fairly long line that shouldn't get wrapped.\n"
             "The same row has another line that shouldn't get wrapped."))

        renderer.section("Heatmap test:")
        cells = []
        for digit in itertools.islice(algo.EulersDecimals(), 0xff):
            cells.append(dict(heat=float(digit + 1) * .1, value=digit))

        randomized = visual_aides.Heatmap(
            caption="Offset (p)",
            # Some of the below xs stand for eXtreme. The other ones just
            # look cool.
            column_headers=["%0.2x" % x for x in xrange(0, 0xff, 0x10)],
            row_headers=["0x%0.6x" % x for x
                         in xrange(0x0, 0xfffff, 0x10000)],
            cells=cells,
            greyscale=False)

        gradual = visual_aides.Heatmap(
            caption="Offset (v)",
            column_headers=["%0.2x" % x for x in xrange(0, 0xff, 0x10)],
            row_headers=["0x%0.6x" % x for x
                         in xrange(0x0, 0xfffff, 0x10000)],
            cells=[dict(value="%x" % x, heat=x / 255.0) for x in xrange(256)],
            greyscale=False)

        ranges_legend = visual_aides.MapLegend(phys_map["ranges_legend"])

        ranges = visual_aides.RunBasedMap(
            caption="Offset (p)",
            legend=ranges_legend,
            runs=phys_map["runs"])

        renderer.table_header([dict(name="Random Heatmap", style="full",
                                    width=60, align="c"),
                               dict(name="Gradual Heatmap", style="full",
                                    width=60, align="c"),
                               dict(name="Legend", style="full",
                                    orientation="horizontal")])
        renderer.table_row(randomized, gradual, visual_aides.HeatmapLegend())

        renderer.table_header([dict(name="Greyscale Random", style="full",
                                    width=60, align="c"),
                               dict(name="Memory Ranges", style="full",
                                    width=80, align="c"),
                               dict(name="Ranges Legend", style="full",
                                    width=30, orientation="vertical")])

        randomized.greyscale = True
        renderer.table_row(randomized, ranges, ranges_legend)
