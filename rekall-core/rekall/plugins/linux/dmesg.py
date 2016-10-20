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

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0 or later
@contact:      atcuno@gmail.com
@organization: Digital Forensics Solutions
"""

from rekall.plugins.linux import common


class LinuxDmesg(common.LinuxPlugin):
    '''Gathers dmesg buffer.'''

    __name = "dmesg"

    table_header = [
        dict(name="timestamp", width=16),
        dict(name="facility", width=2),
        dict(name="level", width=2),
        dict(name="message", width=80)
    ]

    def collect(self):
        if self.profile.get_obj_size("log"):
            # Linux 3.x uses a log struct to keep log messages. In this case the
            # log is a pointer to a variable length array of log messages.
            dmesg = self.profile.get_constant_object(
                "log_buf",
                vm=self.kernel_address_space,
                target="Pointer",
                target_args=dict(
                    target="ListArray",
                    target_args=dict(
                        target="log",
                        maximum_size=self.profile.get_constant("log_buf_len")
                        )
                    )
                )

            for message in dmesg:
                yield (message.ts_nsec / 1e9, message.facility, message.level,
                       message.message)

        else:
            # Older kernels just use the area as a single unicode string.
            dmesg = self.profile.get_constant_object(
                "log_buf",
                vm=self.kernel_address_space,
                target="Pointer",
                target_args=dict(
                    target="UnicodeString",
                    target_args=dict(
                        length=int(self.profile.get_constant_object(
                            "log_buf_len", target="unsigned int"))
                        )
                    )
                )

            yield dict(message=dmesg.deref())
