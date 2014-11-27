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

from rekall import plugin
from rekall import utils


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

        beer = (
            "                /\                      \n"
            "               / |\                     \n"
            "              /  | \                    \n"
            "             /   |  \                   \n"
            "            /____|   \                  \n"
            "           / \    \   \                 \n"
            "          /   \    \  /                 \n"
            "         /     \    \/                  \n"
            "        /       \   /                   \n"
            "       /         \ /                    \n"
            "      /           v                     \n"
            "     /               ( o )o)            \n"
            "    /               ( o )o )o)          \n"
            "                  (o( ~~~~~~~~o         \n"
            "                  ( )' ~~~~~~~' _       \n"                  
            "                    o|   o    |-. \\     \n"                  
            "                    o|     o  |  \\ \\    \n"                  
            "                     | .      |  | |    \n"                  
            "                    o|   .    |  / /    \n"          
            "                     |  .  .  |._ /     \n"          
            "                     .========.         \n")          

        beer_highlights = [(16, 18, "CYAN", None),
                           (55, 58, "CYAN", None),
                           (94, 98, "CYAN", None),
                           (133, 139, "CYAN", None),
                           (172, 179, "CYAN", None),
                           (213, 220, "RED", None),
                           (254, 261, "RED", None),
                           (295, 301, "RED", None),
                           (336, 341, "RED", None),
                           (377, 380, "RED", None),
                           (418, 419, "RED", None),
                           
                           (461, 468, "BLACK", "WHITE"),
                           (500, 510, "BLACK", "WHITE"),
                           (538, 551, "BLACK", "WHITE"),
                           (578, 591, "BLACK", "WHITE"),
                           
                           (620, 621, "BLACK", "WHITE"),
                           (660, 661, "BLACK", "WHITE"),
                           (740, 741, "BLACK", "WHITE"),
                           
                           (621, 631, "WHITE", "YELLOW"),
                           (661, 671, "WHITE", "YELLOW"),
                           (701, 711, "WHITE", "YELLOW"),
                           (741, 751, "WHITE", "YELLOW"),
                           (781, 791, "WHITE", "YELLOW"),
                           (822, 830, "WHITE", "YELLOW")]

        renderer.table_row(
            ("This is a renderer stress-test. The flags should have correct"
             " colors, the beer should be yellow and the cell on the left"
             " should not bleed into the cell on the right.\n"
             "This is a really "
             "long column of text with its own newlines in it!\n"
             "This bovine experience has been brought to you by Rekall."),
            True,
            utils.AttributedString(beer, beer_highlights),
            ("This is a fairly long line that shouldn't get wrapped.\n"
             "The same row has another line that shouldn't get wrapped."))
