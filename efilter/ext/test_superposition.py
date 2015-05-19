import unittest

from efilter.ext import superposition


class SuperpositionTest(unittest.TestCase):
    """This file only tests the specifities of ext.superpositions.

    efilter.protocols.test_superpositon has additional tests, based on the
    generic protocol.
    """

    def testMutability(self):
        """Test adding states."""
        s = superposition.HashedSuperposition(1, 2, 3)
        s.add_state(4)
        self.assertEqual(sorted(s.getstates()), [1, 2, 3, 4])

        # Adding another superposition should leave us flat.
        s.add_state(superposition.HashedSuperposition(4, 5))
        self.assertEqual(sorted(s.getstates()), [1, 2, 3, 4, 5])
