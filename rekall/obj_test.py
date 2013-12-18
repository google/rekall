import logging
import unittest

from rekall import addrspace
from rekall import conf
from rekall import obj

# Import and register all the plugins.
from rekall import plugins


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

    def testBitField(self):
        # We build a simple profile with just the native types here.
        profile = obj.Profile.classes['Profile32Bits']()
        profile.add_types({
                'Test': [ 0x10, {
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
            config=None, data="\x08\x00\x00\x00\x00\x00\x00\x00"
            "\x66\x55\x44\x33\x00\x00\x00\x00"
            "\x99\x88\x77\x66\x55\x44\x33\x22")

        vtype = {'Test': [ 0x10, {
                    # Check simple type dereferencing
                    'ptr32': [0x00, ['pointer', ['unsigned long']]],
                    'ptr64': [0x00, ['pointer', ['long long']]],

                    # Check struct dereferencing
                    'next': [0x00, ['pointer', ['Test']]],

                    # A pointer to an invalid location
                    'invalid': [0x08, ['pointer', ['long']]],

                    # A void pointer
                    'void': [0x00, ['pointer', ['void']]],
                    }]}

        # We build a simple profile with just the native types here.
        profile = obj.Profile.classes['Profile32Bits']()
        profile.add_types(vtype)

        test = profile.Object("Test", offset=0, vm=address_space)

        ptr = test.ptr32

        # Can we check the offset of members?
        self.assertEqual(profile.get_obj_offset("Test", "invalid"), 8)

        # 32 bit pointers.
        self.assertEqual(ptr.size(), 4)

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

        # Alas it cant be dereferenced.
        self.assertEqual(type(ptr2.dereference()), obj.NoneObject)
        self.assert_("invalid" in ptr2.dereference().reason)

        # This is also invalid.
        self.assertEqual(type(test.invalid.dereference()), obj.NoneObject)

        # Test nonzero.
        self.assert_(test.ptr32)

        # Note this pointer is actually zero, but it is actually valid in this AS.
        self.assert_(test.ptr32 + 1)

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
        profile = obj.Profile.classes['Profile64Bits']()
        profile.add_types(vtype)

        test = profile.Object("Test", offset=0, vm=address_space)

        ptr = test.ptr32

        # 64 bit pointers.
        self.assertEqual(ptr.size(), 8)

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
        self.assertEqual(test.void.dereference(), 0x33445566)

    def testArray(self):
        # Create an address space from a buffer for testing
        address_space = addrspace.BufferAddressSpace(
            config=None, data="abcdefghijklmnopqrstuvwxyz")

        profile = obj.Profile.classes['Profile32Bits']()
        test = profile.Object("Array", vm=address_space, offset=0,
                              target="int", count=0)

        self.assertEqual(test[0], 0x64636261)
        self.assertEqual(test[1], 0x68676665)

        # Can read past the end of the array but this returns a None object.
        self.assertEqual(test[100], None)


class WinXPProfileTests(unittest.TestCase):
    """Tests for basic profile functionality for the WinXP profile."""

    def setUp(self):
        # Create the address spaces from our test image. Note that we specify
        # stacking order precisely here.
        self.physical_address_space = addrspace.AddressSpaceFactory(
            specification="FileAddressSpace",
            filename="test_data/xp-laptop-2005-06-25.img")

        self.kernel_address_space = addrspace.AddressSpaceFactory(
            specification="FileAddressSpace:IA32PagedMemory",
            filename="test_data/xp-laptop-2005-06-25.img",
            dtb=0x39000)


    def testWindowsXPProfile(self):
        # We build a simple profile with just the native types here.
        profile = obj.Profile.classes['WinXPSP2x86']()

        # There is an _EPROCESS in the physical AS at this physical offset
        eprocess = profile.Object("_EPROCESS", offset=0x01343790,
                                  vm=self.physical_address_space)

        self.assertEqual(eprocess.ImageFileName, 'mqtgsvc.exe')

        # This is basically a Poor man's pslist - just follow the
        # _EPROCESS.PsActiveList around (see filescan.py).

        # First find the virtual address of the next process by reflecting
        # through the kernel AS.
        list_entry = eprocess.ThreadListHead.Flink.dereference_as(
            '_LIST_ENTRY', vm=self.kernel_address_space).Blink.dereference()

        # Take us back to the _EPROCESS offset by subtracting the _LIST_ENTRY
        # offset.
        list_entry_offset = profile.get_obj_offset('_EPROCESS', 'ThreadListHead')

        # This is now the virtual offset of the _EPROCESS.
        kernel_eprocess_offset = list_entry.obj_offset - list_entry_offset

        # Now lets get the _EPROCESS from the kernel AS this time.
        eprocess = profile.Object("_EPROCESS", offset=kernel_eprocess_offset,
                                  vm=self.kernel_address_space)

        # Lets get all the process names now. Note that we will be finding
        # PsActiveProcessHead so one name will be screwed up (because thats not
        # an _EPROCESS as all).
        names = []
        for p in eprocess.ActiveProcessLinks:
            names.append(p.ImageFileName)

        expected_names = ['alg.exe', 'wuauclt.exe','firefox.exe','PluckSvr.exe',
                          'iexplore.exe','PluckTray.exe','PluckUpdater.ex',
                          'PluckUpdater.ex','PluckTray.exe','cmd.exe','wmiprvse.exe',
                          'PluckTray.exe','dd.exe', None,'System','smss.exe','csrss.exe',
                          'winlogon.exe','services.exe','lsass.exe','svchost.exe',
                          'svchost.exe','svchost.exe','Smc.exe','svchost.exe',
                          'svchost.exe','spoolsv.exe','ssonsvr.exe','explorer.exe',
                          'Directcd.exe','TaskSwitch.exe','Fast.exe','VPTray.exe',
                          'atiptaxx.exe','jusched.exe','EM_EXEC.EXE','ati2evxx.exe',
                          'Crypserv.exe','DefWatch.exe','msdtc.exe','Rtvscan.exe',
                          'tcpsvcs.exe','snmp.exe','svchost.exe','wdfmgr.exe',
                          'Fast.exe','mqsvc.exe','']

        for i, (name, expected_name) in enumerate(zip(names, expected_names)):
            if expected_name is not None:
                self.assertEqual(name, expected_name)

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
