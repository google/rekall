from rekall import testlib

from rekall.entities import superposition
from rekall.entities import types

from rekall.entities.ext import indexset_test as it


class SuperpositionTest(testlib.RekallBaseUnitTestCase):
    def testFactories(self):
        impl = superposition.BaseSuperposition.impl_for_type(
            typedesc=types.TypeFactory(str))
        self.assertEqual(impl, superposition.HashableSuperposition)

        self.assertIsInstance(
            impl.merge_values(("foo", "bar"), types.TypeFactory(str)),
            superposition.HashableSuperposition)

    def testContains(self):
        """Superpositions should compare with scalars."""
        s = superposition.HashableSuperposition(
            variants={"foo", "bar"},
            typedesc=str)

        self.assertTrue(s in ["foo", "bar", "fuzz"])
        self.assertTrue(s not in ["fuzz"])

        # TODO: This will fail right now! Turns out, achieving this sort of
        # behavior is kind of difficult. Maybe the magic behavior of
        # superpositions should be revisited - it's causing lots of unexpected
        # issues.
        # self.assertFalse(s in ["bar"])

    def testHashable(self):
        impl = superposition.HashableSuperposition
        s1 = impl.merge_values(variants=("foo", "bar", "foo"),
                               typedesc=types.TypeFactory(str))
        self.assertEqual(sorted(s1), ["bar", "foo"])
        self.assertEqual(len(s1), 2)
        self.assertTrue("foo" in s1)
        self.assertFalse("FOO" in s1)
        self.assertFalse(5 in s1)

        s1.add(5)
        s1.add(5)
        self.assertTrue("5" in s1)
        self.assertEqual(sorted(s1), ["5", "bar", "foo"])

        s2 = impl(variants=("foo",), typedesc=types.TypeFactory(str))
        self.assertTrue(s1.issuperset(s2))
        s2.add("baz")
        self.assertFalse(s1.issuperset(s2))

    def testList(self):
        impl = superposition.ListSuperposition
        s1 = impl.merge_values(variants=(["foo"], ["bar"], ["bar"]),
                               typedesc=types.TypeFactory(list))

        self.assertTrue(["bar"] in s1)
        self.assertEqual(len(s1), 2)
        self.assertEqual(sorted(s1), [["bar"], ["foo"]])

    def testIndexed(self):
        impl = superposition.IndexedSuperposition
        e1 = it.FakeIndexable(["_foo", 1], "foo")
        e2 = it.FakeIndexable(["_bar", 2], "bar")
        e3 = it.FakeIndexable(["_baz", 3], "baz")

        s1 = impl.merge_values(variants=(e1, e2), typedesc=(it.FakeIndexable))
        self.assertTrue(e1 in s1)
        self.assertFalse(e3 in s1)

        self.assertEqual(len(s1), 2)
        s1.add(e1)
        self.assertEqual(len(s1), 2)
