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

from rekall import testlib


class TestInfo(testlib.SimpleTestCase):
    """Test the Info plugin.

    The Info module changes all the time as new plugins are added. We therefore
    only check that some of the usual plugins are present.
    """

    PARAMETERS = dict(
        commandline="info"
        )

    def testCase(self):
        previous = set(
            self.ExtractColumn(
                list(self.SplitLines(self.baseline['output']))[1], 0))

        current = set(
            self.ExtractColumn(
                list(self.SplitLines(self.current['output']))[1], 0))

        # Its ok if the current result is a superset of the previous result.
        self.assertEqual(previous - current, set())



class TestGrep(testlib.SimpleTestCase):
    PARAMETERS = dict(
        commandline="grep %(keyword)s --offset %(offset)s"
        )
