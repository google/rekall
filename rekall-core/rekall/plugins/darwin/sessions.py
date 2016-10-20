# Rekall Memory Forensics
#
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

"""
Darwin Session collectors and plugins.
"""
__author__ = "Adam Sindelar <adamsh@google.com>"

from rekall import plugin

from rekall.plugins.darwin import common


class DarwinSessions(common.AbstractDarwinProducer):
    """Finds sessions by walking their global hashtable."""

    name = "sessions"
    type_name = "session"

    def collect(self):
        session_hash_table_size = self.profile.get_constant_object(
            "_sesshash", "unsigned long")

        # The hashtable is an array to session list heads.
        session_hash_table = self.profile.get_constant_object(
            "_sesshashtbl",
            target="Pointer",
            target_args=dict(
                target="Array",
                target_args=dict(
                    target="sesshashhead",
                    count=session_hash_table_size.v())))

        # We iterate over the table and then over each list.
        for sesshashhead in session_hash_table:
            for session in sesshashhead.lh_first.walk_list("s_hash.le_next"):
                yield [session]


class DarwinTerminals(common.AbstractDarwinCommand):
    """Lists open ttys."""

    name = "terminals"

    table_header = [
        dict(type="session", name="session",
             columns=[dict(name="s_sid")]),
        dict(type="tty", name="tty")
    ]

    def collect(self):
        for session in self.session.plugins.sessions().produce():
            if session.s_ttyp:
                yield dict(session=session,
                           tty=session.s_ttyp)
