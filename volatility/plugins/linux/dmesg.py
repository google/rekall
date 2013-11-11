# Volatility
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

from volatility.plugins.linux import common

class LinuxDmesg(common.AbstractLinuxCommandPlugin):
    '''Gathers dmesg buffer.'''

    __name = "dmesg"

    def render(self, renderer):
        renderer.format("{0}", self.profile.Object(
            "Pointer",
            vm=self.kernel_address_space,
            offset=self.profile.get_constant("log_buf"),
            target='UnicodeString',
            target_args=dict(length=self.profile.get_constant("log_buf_len"))))
