import logging
import unittest

from volatility import addrspace
from volatility import obj
from volatility.plugins.overlays import basic
from volatility.plugins.overlays.windows import xp


class ProfileTest(unittest.TestCase):
    """Test the profile implementation."""

    def setUp(self):
        # Create an address space from a buffer for testing
        self.address_space = addrspace.BufferAddressSpace(
            config=None, data="hello world" * 100)

    def testNativeTypes(self):
        # We build a simple profile with just the native types here.
        profile = obj.Profile.classes['Profile32Bits']()

        # Check that simple types work
        self.assertEqual(profile.Object("long", offset=0, vm=self.address_space),
                         0x6c6c6568)

        self.assertEqual(profile.Object("long long", offset=0, vm=self.address_space),
                         0x6f77206f6c6c6568)

    def testWindowsXPProfile(self):
        # We build a simple profile with just the native types here.
        profile = obj.Profile.classes['WinXPSP2x86']()

        # Check that simple types work
        self.assertEqual(profile.Object("long", offset=0, vm=self.address_space),
                         0x6c6c6568)

        self.assertEqual(profile.Object("long long", offset=0, vm=self.address_space),
                         0x6f77206f6c6c6568)

        

        
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
