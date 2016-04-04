import logging
import unittest

from rekall import addrspace
from rekall import obj

# Import and register all the plugins.
from rekall import plugins # pylint: disable=unused-import
from rekall import session
from rekall import testlib


class ProfileTest(testlib.RekallBaseUnitTestCase):
    """Test the profile implementation."""

    def setUp(self):
        self.session = session.Session()
        # Create an address space from a buffer for testing
        self.address_space = addrspace.BufferAddressSpace(
            data="hello world" * 100, session=self.session)

    def testNativeTypes(self):
        # We build a simple profile with just the native types here.
        profile = obj.Profile.classes['Profile32Bits'](session=self.session)

        # Check that simple types work
        self.assertEqual(
            profile.Object("long", offset=0, vm=self.address_space),
            0x6c6c6568)

        self.assertEqual(
            profile.Object("long long", offset=0, vm=self.address_space),
            0x6f77206f6c6c6568)

    def testBitField(self):
        # We build a simple profile with just the native types here.
        profile = obj.Profile.classes['Profile32Bits'](session=self.session)
        profile.add_types({
            'Test': [0x10, {
                'Field1': [0x00, ['BitField', dict(start_bit=0, end_bit=4)]],
                'Field2': [0x00, ['BitField', dict(start_bit=4, end_bit=8)]],
                }]})

        test = profile.Object("Test", offset=0, vm=self.address_space)

        bf1 = test.Field1
        bf2 = test.Field2

        self.assertEqual(bf1, 8)
        self.assertEqual(bf2, 6)

        # Check for overloaded numeric methods.
        self.assertEqual(bf1 + 1, 9)
        self.assertEqual(bf1 - 1, 7)
        self.assertEqual(bf1 + bf2, 8 + 6)
        self.assertEqual(bf1 < bf2, 8 < 6)
        self.assertEqual(bf1 > bf2, 8 > 6)
        self.assertEqual(bf1 & bf2, 8 & 6)
        self.assertEqual(bf1 ^ bf2, 8 ^ 6)
        self.assertEqual(bf1 + 6, 8 + bf2)
        self.assertEqual(bf1 < 6, 8 < bf2)
        self.assertEqual(bf1 > 6, 8 > bf2)
        self.assertEqual(bf1 & 6, 8 & bf2)
        self.assertEqual(bf1 ^ 6, 8 ^ bf2)

    def testPointer(self):
        # Create an address space from a buffer for testing
        address_space = addrspace.BufferAddressSpace(
            data="\x08\x00\x00\x00\x00\x00\x00\x00"
            "\x66\x55\x44\x33\x00\x00\x00\x00"
            "\x99\x88\x77\x66\x55\x44\x33\x22", session=self.session)

        vtype = {'Test': [0x10, {
            # Check simple type dereferencing
            'ptr32': [0x00, ['Pointer', dict(
                target='unsigned long'
                )]],
            'ptr64': [0x00, ['Pointer', dict(
                target='long long'
                )]],

            # Check struct dereferencing
            'next': [0x00, ['Pointer', dict(
                target='Test'
                )]],

            # A pointer to an invalid location
            'invalid': [0x08, ['Pointer', dict(
                target='long'
                )]],

            # A void pointer
            'void': [0x00, ['Pointer', dict(
                target='Void'
                )]],
            }]}

        # We build a simple profile with just the native types here.
        profile = obj.Profile.classes['Profile32Bits'](session=self.session)
        profile.add_types(vtype)

        test = profile.Object("Test", offset=0, vm=address_space)

        ptr = test.ptr32

        # Can we check the offset of members?
        self.assertEqual(profile.get_obj_offset("Test", "invalid"), 8)

        # 32 bit pointers.
        self.assertEqual(ptr.obj_size, 4)

        # The pointer itself is at location 0.
        self.assertEqual(ptr.obj_offset, 0)

        # But is pointing to location 8.
        self.assertEqual(ptr.v(), 8)
        self.assertEqual(int(ptr), 8)
        self.assertEqual(ptr, 8)

        # The long is the next 8 bytes.
        self.assertEqual(ptr.dereference(), 0x33445566)

        # Pointer comparison
        self.assertEqual(test.ptr32, test.ptr64)

        # We could do pointer arithmetic.
        ptr2 = ptr + 2

        # The new pointer is at location 8 (its 32 bits).
        self.assertEqual(ptr2.obj_offset, 8)

        # The pointer to long long is moving twice as fast
        self.assertEqual(test.ptr64 + 1, 0x33445566)
        self.assertEqual(test.ptr32 + 1, 0)

        # And its pointing to.
        self.assertEqual(ptr2.v(), 0x33445566)

        # The above makes the pointer invalid, so dereferencing it returns a 0.
        # (This is because there is no good way to validate pages except at
        # system runtime.)
        self.assertEqual(ptr2.dereference(), 0)

        # This is also invalid and will return a zero.
        self.assertEqual(test.invalid.dereference(), 0)

        # Test nonzero.
        self.assert_(test.ptr32)

        # Now dereference a struct.
        ptr3 = test.next

        # This struct starts at offset 8.
        self.assertEqual(test.next.v(), 8)

        next = ptr3.dereference()

        # We get another struct from this.
        self.assertEqual(next.obj_type, "Test")

        # This new struct's ptr32 is pointing at this address now.
        self.assertEqual(next.ptr32, 0x33445566)

        # Now test 64 bit pointers.
        profile = obj.Profile.classes['ProfileLLP64'](session=self.session)
        profile.add_types(vtype)

        test = profile.Object("Test", offset=0, vm=address_space)

        ptr = test.ptr32

        # 64 bit pointers.
        self.assertEqual(ptr.obj_size, 8)

        # The pointer itself is at location 0.
        self.assertEqual(ptr.obj_offset, 0)

        # But is pointing to location 8.
        self.assertEqual(ptr.v(), 8)

        # The long is the next 8 bytes.
        self.assertEqual(ptr.dereference(), 0x33445566)

        # We could do pointer arithmetic.
        ptr2 = ptr + 2

        # This will advance the pointer by 8 bytes (still pointer to long).
        self.assertEqual(ptr2.obj_offset, 8)
        self.assertEqual(ptr2, 0x33445566)

        # NOTE: We assume that long is 32 bits wide in both 64 bits and 32 bits
        # mode - which is the way windows does it. This is not the same as linux
        # which has long being the bit size in both cases.

        # Test the void pointer
        self.assertEqual(test.void, 8)

        # A Void object can not be compared to anything!
        self.assertNotEqual(test.void.dereference(), 0x33445566)

    def testArray(self):
        # Create an address space from a buffer for testing
        address_space = addrspace.BufferAddressSpace(
            data="abcdefghijklmnopqrstuvwxyz", session=self.session)

        profile = obj.Profile.classes['Profile32Bits'](session=self.session)
        test = profile.Object("Array", vm=address_space, offset=0,
                              target="int", count=0)

        self.assertEqual(test[0], 0x64636261)
        self.assertEqual(test[1], 0x68676665)

        # Can read past the end of the array but this returns all zeros.
        self.assertEqual(test[100], 0)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
