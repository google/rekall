import logging

from rekall import addrspace
from rekall import obj
from rekall import testlib
from rekall import session


class CustomRunsAddressSpace(addrspace.RunBasedAddressSpace):
    def __init__(self, runs=None, data=None, **kwargs):
        super(CustomRunsAddressSpace, self).__init__(**kwargs)
        self.base = addrspace.BufferAddressSpace(data=data,
                                                 session=self.session)
        for i in runs:
            self.runs.insert(i)


class RunBasedTest(testlib.RekallBaseUnitTestCase):
    """Test the RunBasedAddressSpace implementation."""

    def setUp(self):
        self.session = session.Session()
        self.contiguous_as = CustomRunsAddressSpace(session=self.session,
            runs = [(1000, 0, 1), (1001, 1, 9)],
            data="0123456789")
        self.discontiguous_as = CustomRunsAddressSpace(session=self.session,
            runs=[(1000, 0, 1), (1020, 1, 9)],
            data="0123456789")

    def testDiscontiguousRunsRead(self):
        # Read from an address without data
        self.assertEqual(self.discontiguous_as.read(0, 20),
                         "\x00" * 20)
        # Read spanning two runs
        self.assertEqual(self.discontiguous_as.read(1000, 30),
                         "0" + "\x00"*19 + "123456789" +  "\x00")
        # Read in the middle of a run
        self.assertEqual(self.discontiguous_as.read(1025, 10),
                         "6789" + "\x00" * 6)
        # Read past the end
        self.assertEqual(self.discontiguous_as.read(2000, 10),
                         "\x00" * 10)

    def testContiguousRunsRead(self):
        # Read from an address without data
        self.assertEqual(self.contiguous_as.read(0, 20),
                         "\x00" * 20)
        # Read spanning two runs
        self.assertEqual(self.contiguous_as.read(1000, 30),
                         "0123456789" + "\x00"*20)
        # Read in the middle of a run
        self.assertEqual(self.contiguous_as.read(1005, 10),
                         "56789" + "\x00" * 5)
        # Read past the end
        self.assertEqual(self.contiguous_as.read(2000, 10),
                         "\x00" * 10)

if __name__ == "__main__":
    unittest.main()
