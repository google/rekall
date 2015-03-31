from rekall import testlib

from rekall.entities import identity


class IdentityTest(testlib.RekallBaseUnitTestCase):

    def testInvalidCompare(self):
        # This will raise because the two processes are equal on one index
        # (the PID) but differ on the other (the offset). This is a logic error
        # because the system can't decide what to do.
        x = identity.Identity.from_dict(
            "LOCALHOST",
            {"Process/pid": 1,
             "Struct/base": 0xf00ba4})

        y = identity.Identity.from_dict(
            "LOCALHOST",
            {"Process/pid": 1,
             "Struct/base": 0xc001d00d})

        self.assertRaises(RuntimeError, x.__eq__, y)

        # The correct way to establish a unique process identity is by using
        # a tuple of the PID and the creation timestamp. That'll ensure that
        # both indices are either equal or unequal.
        x = identity.Identity.from_dict(
            "LOCALHOST",
            {("Process/pid", "Timestamps/created_at"): (1, 1337),
             "Struct/base": 0xf00ba4})

        y = identity.Identity.from_dict(
            "LOCALHOST",
            {("Process/pid", "Timestamps/created_at"): (1, 1234),
             "Struct/base": 0xc001d00d})

        self.assertNotEqual(x, y)
