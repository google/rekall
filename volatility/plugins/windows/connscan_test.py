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

"""Tests for the ConnScan plugins."""

from volatility import testlib


class TestConnectionScanners(testlib.VolatilityBaseUnitTestCase):
    """Test the ConnScan module."""

    trunk_launch_args = [['connscan']]
    ng_launch_args = [['connscan', {}]]

    def testConnectionss(self):
        previous_meta, current_meta = self.ReRunVolatilityTest('connscan')
        previous = previous_meta['output']
        current = current_meta['output']

        if previous_meta['mode'] == 'trunk':
            sep = " +"
        else:
            sep = r"\|\|"

        # Compare the entire table
        for i in range(4):
            self.assertListEqual(
                sorted(self.ExtractColumn(current, i, 2)),
                sorted(self.ExtractColumn(previous, i, 2, seperator=sep)))
