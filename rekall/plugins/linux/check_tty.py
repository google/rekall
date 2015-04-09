# Rekall Memory Forensics
#
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Rekall Memory Forensics is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General Public
# License.
#
# Rekall Memory Forensics is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# Rekall Memory Forensics.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@author:       Joe Sylve
@license:      GNU General Public License 2.0
@contact:      joe.sylve@gmail.com
@organization: 504ENSICS Labs
"""

from rekall.plugins.linux import common


class CheckTTY(common.LinuxPlugin):
    """Checks tty devices for hooks.

    Some malware insert a hook into the ops struct of the tty driver. This
    plugin enumerates all tty_struct objects and checks if their ops handlers
    have been subverted.
    """
    __name = "check_ttys"


    @classmethod
    def is_active(cls, session):
        # Older versions of linux do not have the ldisc.ops member.
        return (super(CheckTTY, cls).is_active(session) and
                session.profile.Object("tty_ldisc").m("ops"))

    def CheckTTYs(self):
        drivers_list = self.profile.get_constant_object(
            "tty_drivers", target="list_head", vm=self.kernel_address_space)

        resolver = self.session.address_resolver
        for driver in drivers_list.list_of_type("tty_driver", "tty_drivers"):
            for tty in driver.ttys:
                if not tty:
                    continue

                # This is the method which receives input. It should be present
                # inside the tty driver.
                recv_buf = tty.ldisc.ops.receive_buf

                yield tty.name, recv_buf, resolver.format_address(recv_buf)

    def render(self, renderer):
        renderer.table_header([
            ("Name", "name", "<16"),
            ("Address", "address", "[addrpad]"),
            ("Symbol", "symbol", "<30")])

        for name, call_addr, sym_name in self.CheckTTYs():
            renderer.table_row(name, call_addr, sym_name or "Unknown",
                               highlight=None if sym_name else "important")
