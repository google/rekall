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

"""Tests for the vadinfo plugins."""

from volatility import testlib


class TestVadInfo(testlib.VolatilityBaseUnitTestCase):
    """Test the vadinfo module."""

    PARAMETERS = dict(commandline="vadinfo --pid 2624")

    def testVadInfo(self):
        previous = self.baseline['output']
        current = self.current['output']

        self.assertListEqual(
            self.FilterOutput(previous, "VAD node"),
            self.FilterOutput(current, "VAD node"))

        file_objects = list(self.MatchOutput(previous, "FileObject @[0-9a-z]+"))
        self.assertEqual(len(file_objects), 27)
        self.assertListEqual(file_objects,
                             self.MatchOutput(current, "FileObject @[0-9a-z]+"))


class TestVad(testlib.VolatilityBaseUnitTestCase):
    """Test the vad module."""

    # This command only exists in technology preview.
    PARAMETERS = dict(ng_commandline="vad --pid 2624")

    def testVad(self):
        for x, y in zip(self.baseline['output'], self.current['output']):
            self.assertTableRowsEqual(x, y)
