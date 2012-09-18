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

"""Tests for the session plugin."""

from volatility import testlib


class TestSessions(testlib.VolatilityBaseUnitTestCase):
    PARAMETERS = dict(commandline="sessions")

    def testSession(self):
        previous = self.baseline['output']
        current = self.current['output']

        if self.baseline_mode == "trunk":
            # Trunk may miss some processes here - we allow the config file to
            # tell us which processes trunk typically misses.
            for pid in self.baseline['options'].get(
                "trunk_misses_processes", "").split(","):
                if pid:
                    current = self.FilterOutput(current, "@ %s" % pid,
                                                exclude=True)

            # Trunk does not print the offsets of the _EPROCESS.
            current = self.ReplaceOutput(" @ 0x.+", "", current)

            # If processes were missed we do not compare the total process
            # count.
            if pid:
                current = self.ReplaceOutput("Processes: .+", "", current)
                previous = self.ReplaceOutput("Processes: .+", "", previous)

        self.assertListEqual(previous, current)
