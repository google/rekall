import unittest

from efilter.protocols import hashable
from efilter.protocols import superposition


# Do not try any of this in real code - this is just for sake of tests.
class frozendict(dict):
    def __hash__(self):
        return hash(frozenset(self.items()))


def _hashed_frozendict(x):
    return hash(frozenset(x.items()))

hashable.IHashable.implement(
    for_type=frozendict,
    implementations={hashable.hashed: _hashed_frozendict})


class SuperpositionTest(unittest.TestCase):
    def assertStateEq(self, s1, s2):
        return self.assertTrue(superposition.state_eq(s1, s2))

    def testMutables(self):
        """Test that mutable types cannot be put in a superposition."""
        x = dict(name="Alice")
        y = dict(name="Bob")

        # Can't put dicts in a superposition.
        with self.assertRaises(NotImplementedError):
            superposition.superposition(x, y)

        # Frozendicts work, because they are hashable.
        x = frozendict(name="Alice")
        y = frozendict(name="Bob")
        superposition.superposition(x, y)

    def testCreation(self):
        """Test that creation is reasonable."""
        
        # Providing the same object twice will still build a superposition.
        s = superposition.superposition("foo", "foo")
        # This object is a superposition type...
        self.assertIsInstance(s, superposition.ISuperposition)

        # ...but it is not IN superposition.
        self.assertFalse(superposition.insuperposition(s))

        # Using meld is sometimes more convenient for this.
        s = superposition.meld("foo", "foo")
        # This object is actually a string.
        self.assertIsInstance(s, basestring)
        # It can still be manipulated with the superposition-aware protocol,
        # as can any scalar.
        self.assertEqual(s, superposition.getstate(s))

    def testTypes(self):
        """Test that types are correctly derived and enforced."""

        # Cannot have a superposition with two different state types.
        with self.assertRaises(TypeError):
            superposition.superposition(1, "foo")

        self.assertEqual(superposition.superposition(1, 2).state_type(), int)

    def testStates(self):
        """Test that states are inspectable and comparable."""
        s1 = superposition.superposition("foo", "bar")
        s2 = superposition.superposition("bar", "foo")
        s3 = superposition.superposition(1, 2)
        s4 = 1
        s5 = superposition.superposition(1)

        self.assertItemsEqual(superposition.getstates(s1),
                              superposition.getstates(s2))

        self.assertTrue(superposition.state_eq(s1, s2))
        self.assertFalse(superposition.state_eq(s1, s3))

        # Superposition is obviously not equal to a scalar.
        self.assertFalse(s5 == s4)

        # But their states CAN be equal:
        self.assertTrue(superposition.state_eq(s4, s5))
        self.assertTrue(superposition.state_eq(s5, s4))

        # We can also compare two scalars this way (if we really have nothing
        # better to do).
        self.assertTrue(superposition.state_eq("foo", "foo"))

    def testSetOps(self):
        """Test set operations on states."""
        s1 = 1
        s2 = superposition.superposition(1, 2, 3)
        s3 = superposition.superposition(2, 3, 4)
        s4 = 2

        # Test intersections:
        s_ = superposition.state_intersection(s1, s2)
        self.assertStateEq(s_, 1)

        s_ = superposition.state_intersection(s1, s3)
        self.assertStateEq(s_, None)

        s_ = superposition.state_intersection(s2, s3)
        self.assertStateEq(superposition.superposition(2, 3), s_)

        # Test unions:
        s_ = superposition.state_union(s1, s4)
        self.assertStateEq(superposition.superposition(1, 2), s_)

    def testNesting(self):
        """Test that superpositions remain flat."""
        s = superposition.superposition("foo", "bar")
        s = superposition.superposition(s, "baz")
        self.assertStateEq(superposition.superposition("foo", "bar", "baz"), s)

        s = superposition.superposition("zoo", s)
        self.assertStateEq(
            superposition.superposition("foo", "bar", "baz", "zoo"), s)

        self.assertEqual(superposition.state_type(s), type("foo"))

    def testApplication(self):
        """Test function application across states."""
        self.assertEqual(
            superposition.superposition(2, 4),
            superposition.state_apply(
                superposition.superposition(1, 2),
                lambda x: x * 2))

        # As everything working on states, this should also work on scalars.
        applied = superposition.state_apply(5, lambda x: x * 2)
        self.assertTrue(superposition.state_eq(10, applied))

    def testHasState(self):
        """Test superposition operations on scalars."""
        # hasstate should work same as equivalance on scalars.
        self.assertTrue(superposition.hasstate(1, 1))
        self.assertFalse(superposition.hasstate(2, 1))

        with self.assertRaises(TypeError):
            # The 'state' argument to hasstate is not allowed to be in
            # superposition.
            superposition.hasstate(1, superposition.superposition(1, 2))

        # It should work as expected in the base case:
        self.assertTrue(superposition.hasstate(
            superposition.superposition("foo", "bar"),
            state="foo"))
        self.assertFalse(superposition.hasstate(
            superposition.superposition("foo", "bar"),
            state="baz"))
