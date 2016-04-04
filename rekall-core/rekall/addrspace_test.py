import logging
import unittest

from rekall import addrspace
from rekall import testlib
from rekall import session


class CustomRunsAddressSpace(addrspace.RunBasedAddressSpace):
    def __init__(self, runs=None, data=None, **kwargs):
        super(CustomRunsAddressSpace, self).__init__(**kwargs)
        self.base = addrspace.BufferAddressSpace(data=data,
                                                 session=self.session)
        for i in runs:
            self.add_run(*i)


class RunBasedTest(testlib.RekallBaseUnitTestCase):
    """Test the RunBasedAddressSpace implementation."""

    def setUp(self):
        self.session = session.Session()
        self.test_as = CustomRunsAddressSpace(
            session=self.session,
            #        Voff, Poff, length
            runs=[(1000, 0, 10),    # This contains data.
                  (1020, 40, 10),
                  (1030, 50, 10),   # Contiguous runs.
                  (1050, 0, 2),
                  (1052, 5, 2)],
            data="0123456789")

    def testRunsRead(self):
        # Read from an address without data
        self.assertEqual(self.test_as.read(0, 20), "\x00" * 20)

        # Address translation.
        self.assertEqual(self.test_as.vtop(0), None)
        self.assertEqual(self.test_as.vtop(1005), 5)

        # Read spanning two runs
        self.assertEqual(self.test_as.read(1050, 4), "0156")

        # Read in the middle of a run
        self.assertEqual(self.test_as.read(1005, 10),
                         "56789" + "\x00" * 5)
        # Read past the end
        self.assertEqual(self.test_as.read(2000, 10),
                         "\x00" * 10)

    def testDiscontiguousRunsGetRanges(self):
        """Test the range merging."""
        runs = []
        # The pure mapping is not merged.
        for run in self.test_as.get_mappings():
            self.assertTrue(isinstance(run, addrspace.Run))
            self.assertEqual(run.address_space, self.test_as.base)
            runs.append([run.start, run.end, run.file_offset])

        self.assertEqual(runs,
                         [[1000, 1010, 0],
                          [1020, 1030, 40],
                          [1030, 1040, 50],
                          [1050, 1052, 0],
                          [1052, 1054, 5]])

        runs = []
        for run in self.test_as.merge_base_ranges():
            runs.append([run.start, run.end, run.file_offset])

        # merge_base_ranges is supposed to merge contiguous runs but still
        # maintain contiguous ranges in the base address space.
        self.assertEqual(runs,
                         [[1000, 1010, 0],
                          [1020, 1040, 40],
                          [1050, 1052, 0],
                          [1052, 1054, 5]])

        runs = []
        for run in self.test_as.get_address_ranges():
            # No valid physical mapping given here.
            self.assertTrue(run.file_offset is None)
            self.assertTrue(run.address_space is None)
            runs.append([run.start, run.end])

        # get_address_ranges is supposed to merge contiguous runs in the virtual
        # AS.
        self.assertEqual(runs,
                         [[1000, 1010],
                          [1020, 1040],
                          [1050, 1054]])


        # Check that get_address_ranges honors the start and end parameters.
        run = None
        for run in self.test_as.get_address_ranges(start=1022, end=1024):
            self.assertEqual(run.start, 1022)
            self.assertEqual(run.end, 1024)

            # get_address_ranges does not have a file_offset member.
            self.assertEqual(run.file_offset, None)

        self.assertTrue(run)


        # Check that merge_base_ranges honors the start and end parameters.
        run = None
        for run in self.test_as.merge_base_ranges(start=1022, end=1024):
            self.assertEqual(run.start, 1022)
            self.assertEqual(run.end, 1024)

            # The file_offset must be properly adjusted too.
            self.assertEqual(run.file_offset, 40 + 2)

        self.assertTrue(run)

        # Check that get_mappings honors the start parameter.
        run = None
        for run in self.test_as.get_mappings(start=1022):
            # get_mappings does not clip ranges so we may get a range which
            # starts below the specified limit.
            self.assertEqual(run.start, 1020)
            self.assertEqual(run.end, 1030)

            # The file_offset is unchanged.
            self.assertEqual(run.file_offset, 40)
            break

        self.assertTrue(run)

        # Check that get_mappings honors the end parameter.
        run = None
        for run in self.test_as.get_mappings(end=1022):
            pass

        # Check the last run. Note get_mappings may not clip the last run so it
        # may extend past the end but should never start past the specified end
        # point.
        self.assertEqual(run.start, 1020)
        self.assertEqual(run.end, 1030)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
