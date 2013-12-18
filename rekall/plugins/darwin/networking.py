# Rekall Memory Forensics
#
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

__author__ = "Michael Cohen <scudette@google.com>"

from rekall.plugins.darwin import common


class DarwinArp(common.DarwinPlugin):
    """Show information about arp tables."""

    __name = "arp"

    def render(self, renderer):
        renderer.table_header(
            [("IP Addr", "ip_addr", "20"),
             ("MAC Addr", "mac", "18"),
             ("Interface", "interface", "9"),
             ("Sent", "sent", "8"),
             ("Recv", "recv", "8"),
             ("Time", "timestamp", "24"),
             ("Expires", "expires", "8"),
             ("Delta", "delta", "8"),
             ])

        arp_cache = self.profile.get_constant_object(
            "_llinfo_arp",
            target="Pointer",
            target_args=dict(
                target="llinfo_arp"
                )
            )

        while arp_cache:
            entry = arp_cache.la_rt

            renderer.table_row(
                entry.source_ip,
                entry.dest_ip,
                entry.name,
                entry.sent,
                entry.rx,
                entry.base_calendartime,
                entry.rt_expire,
                entry.delta
                )

            arp_cache = arp_cache.la_le.le_next
