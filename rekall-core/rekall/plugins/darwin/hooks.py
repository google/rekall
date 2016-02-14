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


class DarwinNotifiers(common.AbstractDarwinCommand):
    """Detects hooks in I/O Kit IONotify objects."""

    __name = "notifiers"

    def render(self, renderer):
        renderer.table_header([
            ("Notify Type", "notify_type", "25"),
            ("Handler", "handler", "[addrpad]"),
            ("Match Key", "match_key", "20"),
            ("Match Value", "match_value", "30"),
            ("Symbol", "symbol", ""),
        ])

        gnotifications = self.profile.get_constant_cpp_object(
            "gNotifications",
            target="Pointer",
            target_args=dict(
                target="OSDictionary"
            )
        )

        if not gnotifications:
            self.session.logging.error("Could not find the gNotifications "
                                       "object. The profile %r could be "
                                       "incomplete." % self.profile)
            return

        resolver = self.session.address_resolver
        # The notification dictionary contains sets of _IOServiceNotifier
        # handlers.
        for key, value in gnotifications.items("OSOrderedSet"):
            for notifier in value.list_of_type("_IOServiceNotifier"):
                symbol = resolver.format_address(notifier.handler)

                for match_key, match_value in notifier.matching.items(
                        "OSString"):
                    renderer.table_row(
                        key, notifier.handler,
                        match_key, match_value.value,
                        symbol)
