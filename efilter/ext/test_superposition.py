import unittest

from efilter.types import hashable
from efilter.types import superposition as isuperposition


# Do not try any of this in real code - this is just for sake of tests.
class frozendict(dict):
    def __hash__(self):
        return hash(frozenset(self.items()))


def _hashed_frozendict(x):
    return hash(frozenset(x.items()))

hashable.IHashable.implement(
    for_type=frozendict,
    implementations={hashable.hashed: _hashed_frozendict})


class TypesTest(unittest.TestCase):
    def testMutables(self):
        x = dict(name="Alice")
        y = dict(name="Bob")

        # Can't put dicts in a superposition.
        with self.assertRaises(NotImplementedError):
            isuperposition.superposition(x, y)

        # Frozendicts work.
        x = frozendict(name="Alice")
        y = frozendict(name="Bob")
        isuperposition.superposition(x, y)

    def testTypes(self):
        with self.assertRaises(TypeError):
            isuperposition.superposition(1, "foo")

        self.assertEqual(isuperposition.superposition(1, 2).state_type(), int)

    def testInterface(self):
        s = isuperposition.superposition(1, 2)
        s_ = isuperposition.superposition(2, 3)

        self.assertSetEqual(set([1, 2, 3]),
                            isuperposition.getstates(s.union(s_)))

        self.assertSetEqual(set([2]),
                            isuperposition.getstates(s.intersection(s_)))
