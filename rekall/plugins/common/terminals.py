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

"""OS-independent plugins for working with terminals."""

__author__ = "Adam Sindelar <adamsh@google.com>"

import re

from rekall import plugin
from rekall.entities.query import expression


class ListTerminals(plugin.Command):
    __name = "list_terminals"
    SHORTENER = re.compile(r"[\s\x00]{6,}")

    def render(self, renderer):
        renderer.table_header([
            ("User", "user", "15"),
            ("Session", "session", "15"),
            ("Terminal vnode", "vnode", "30"),
            ("Recovered input", "input", "75"),
            ("Recovered output", "output", "75")])

        for terminal in self.session.entities.find("has component Terminal"):

            buffer_in = self.session.entities.find_first(
                expression.Intersection(
                    expression.Equivalence(
                        expression.Binding("Buffer/purpose"),
                        expression.Literal("terminal_input")),
                    expression.Equivalence(
                        expression.Binding("Buffer/context"),
                        expression.Literal(terminal.identity))))

            buffer_out = self.session.entities.find_first(
                expression.Intersection(
                    expression.Equivalence(
                        expression.Binding("Buffer/purpose"),
                        expression.Literal("terminal_output")),
                    expression.Equivalence(
                        expression.Binding("Buffer/context"),
                        expression.Literal(terminal.identity))))

            renderer.table_row(
                terminal["Terminal/session"]["Session/user"]["User/username"],
                terminal["Terminal/session"]["Session/sid"],
                terminal.get("Terminal/file", complete=True)["File/path"],
                repr(self.SHORTENER.sub("<whitespace>",
                                        buffer_in["Buffer/contents"])),
                repr(self.SHORTENER.sub("<whitespace>",
                                        buffer_out["Buffer/contents"])))
