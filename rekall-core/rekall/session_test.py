from rekall import addrspace
from rekall import testlib
from rekall import session


class CustomAddressSpace(addrspace.BaseAddressSpace):

    def ConfigureSession(self, session_obj):
        session_obj.SetCache("foo", "bar", volatile=False)


class SessionTest(testlib.RekallBaseUnitTestCase):
    """Test the RunBasedAddressSpace implementation."""

    def setUp(self):
        self.session = session.Session()
        self.physical_AS = CustomAddressSpace(session=self.session)

    def testSessionCache(self):
        """Make sure session gets the correct cache."""
        with self.session:
            self.session.SetParameter("cache", "memory")

            # Set something in the session cache.
            self.session.SetCache("a", "b")

        # Make sure it is set.
        self.assertEqual(self.session.GetParameter("a"), "b")

        self.physical_AS.volatile = False
        self.session.physical_address_space = self.physical_AS

        # None volatile physical address space should use the user specified
        # cache type.
        self.assertEqual(self.session.cache.__class__.__name__, "Cache")

        # Assigning the physical address space causes the cache to be
        # purged. The cache is allowed to be purged at any time (it is only a
        # cache).
        self.assertEqual(self.session.GetParameter("a"), None)

        # Volatile physical address space forces a TimedCache
        self.physical_AS.volatile = True
        self.session.physical_address_space = self.physical_AS

        self.assertEqual(self.session.cache.__class__.__name__, "TimedCache")

        # Any parameters set by the address space should be present in the
        # session cache.
        self.assertEqual(self.session.GetParameter("foo"), "bar")
