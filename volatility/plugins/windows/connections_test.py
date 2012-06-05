# Volatility
#
# Authors:
# Michael Cohen <scudette@gmail.com>
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

"""Tests for the connections plugins."""

from volatility import testlib


class TestConnections(testlib.VolatilityBaseUnitTestCase):
    """Test the connections module."""

    trunk_launch_args = [['connections'],
                         ['sockets']]
    ng_launch_args = [['connections', {}],
                      ['sockets', {}]]

    def testConnectionss(self):
        previous_meta, current_meta = self.ReRunVolatilityTest('connections')
        previous = previous_meta['output']
        current = current_meta['output']

        # Compare the entire table
        for i in range(4):
            self.assertListEqual(
                sorted(self.ExtractColumn(current, i, 2)),
                sorted(self.ExtractColumn(previous, i, 2)))

    def testSockets(self):
        previous_meta, current_meta = self.ReRunVolatilityTest('sockets')
        previous = previous_meta['output']
        current = current_meta['output']

        # Compare the entire table
        for i in range(6):
            self.assertListEqual(
                sorted(self.ExtractColumn(current, i, 2)),
                sorted(self.ExtractColumn(previous, i, 2)))
