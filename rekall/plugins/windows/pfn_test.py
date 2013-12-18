# Rekall Memory Forensics
#
# Copyright 2013 Google Inc. All Rights Reserved.
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

"""Tests for the pfn plugins."""
import json

from rekall import testlib


class TestPFN(testlib.RekallBaseUnitTestCase):
    """Test the pfn module."""

    # This is the test data in json format. Keys are _EPROCESS and values is a
    # list of private addresses.
    PARAMETERS = dict(test_data="""{ "0x81faf280": ["0x320010", "0x7ffdf043"],
                  "0x81ed84e8":  ["0x240200", "0x360012"]
                }""")

    def BuildBaseLineData(self, config_options):
        return {}

    def testPFN(self):
        """Test the vtop function."""
        config_options = self.baseline['options']

        session = self.MakeUserSession(config_options)

        # Instantiate the pfn plugin.
        vtop = session.vol("vtop")
        ptov = session.vol("ptov")

        # Get the image metadata.
        for task_offset, virtual_addresses in json.loads(
            config_options['test_data']).items():

            task = session.profile._EPROCESS(
                vm=session.kernel_address_space,
                offset=int(task_offset, 16))

            process_space = task.get_process_address_space()

            for virtual_address in virtual_addresses:
                virtual_address = int(virtual_address, 16)
                for level, value, address in vtop.vtop(
                    virtual_address, process_space):
                    if "mapped" in level:
                        self.assertEqual(value, process_space.vtop(
                                virtual_address))

                        # Check that ptov works. This only works with private
                        # process pages (process mapped pages will not
                        # work). When adding numbers to the pfn json file, check
                        # with the plugins.vad module that the address is a
                        # private page:
                        vaddr, metadata = ptov.ptov(value)
                        metadata = dict(metadata)

                        self.assertEqual(vaddr, virtual_address)
                        self.assertEqual(metadata['DTB'], process_space.dtb)
