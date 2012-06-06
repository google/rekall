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

"""Tests for the procexecdump plugins."""
import os
import hashlib
import tempfile
import StringIO

from volatility import testlib


class TestProcdump(testlib.VolatilityBaseUnitTestCase):
    """Test the Procdump module."""

    trunk_launch_args = [['procexedump', '--pid', '2536', '--dump-dir']]
    ng_launch_args = [['procdump', dict(pid=1700)]]

    def LaunchTrunkVolatility(self, args=None, **kwargs):
        # Get a temp directory
        directory = tempfile.mkdtemp()
        args.append(directory)

        result = super(TestProcdump, self).LaunchTrunkVolatility(args=args, **kwargs)

        with open(os.path.join(directory, "executable.%s.exe" % args[2])) as fd:
            md5 = hashlib.md5(fd.read())
            result['hash'] = md5.hexdigest()

        return result

    def RunVolatilityModule(self, pid=None, **kwargs):
        fd = StringIO.StringIO()
        result = super(TestProcdump, self).RunVolatilityModule(outfd=fd, pid=pid, **kwargs)

        del result['kwargs']

        md5 = hashlib.md5(fd.getvalue())
        result['hash'] = md5.hexdigest()

        return result

    def testProcDump(self):
        try:
            previous_run_data = self.LoadPreviousRunData('procdump')
        except IOError:
            previous_run_data = self.LoadPreviousRunData('procexedump')

        result = self.RunVolatilityModule(profile=previous_run_data['profile'],
                                          image=previous_run_data['filename'],
                                          module='procdump', pid=1700)

        self.assertEqual(previous_run_data['hash'], result['hash'])
