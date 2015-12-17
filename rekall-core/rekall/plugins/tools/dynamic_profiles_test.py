import mock
from rekall import testlib
from rekall.plugins.tools import dynamic_profiles


class MockAddressResolver(object):
    def __init__(self, name_map):
        self.name_map = name_map

    def format_address(self, address):
        return self.name_map.get(address, "")


class TestDynamicProfile(testlib.RekallBaseUnitTestCase):
    """Tests the dynamic profile mechanism."""

    TEST_CASES = [
        dict(
            expected={"$out": 0x20},
            mode="AMD64",
            # Taken from Windows 7 x64
            offset=0xf800029eb5d0,
            data=('48895c240848896c24104889742418574883ec2033ff418bf08bea488bd'
                  '948393975218d572833c941b848546162e80d4602004889034885c07504'
                  '32c0eb49bf01000000488b1b33d2448d4228488bcbe86b27efff83630c0'
                  '00bfe893bc7430880000000c743107f000000896b04e80583e9ff4885c0'
                  '750a488bcbe8f0feffffebb948894320b001488b5c2430'),
            example="""
0xf800029eb63e           0x6e e80583e9ff           call 0xf80002883948                      nt!RtlpAllocateSecondLevelDir
0xf800029eb643           0x73 4885c0               test rax, rax
0xf800029eb646           0x76 750a                 jne 0xf800029eb652                       nt!RtlCreateHashTable+0x82
0xf800029eb648           0x78 488bcb               mov rcx, rbx
0xf800029eb64b           0x7b e8f0feffff           call 0xf800029eb540                      nt!RtlDeleteHashTable
0xf800029eb650           0x80 ebb9                 jmp 0xf800029eb60b                       nt!RtlCreateHashTable+0x3b
0xf800029eb652           0x82 48894320             mov qword ptr [rbx + 0x20], rax
""",
            rules=[
                {'mnemonic': 'CALL',
                 'comment': 'nt!RtlpAllocateSecondLevelDir'},

                {'mnemonic': 'MOV',
                 'operands': [{'disp': "$out", 'base': '$rbx'},
                              {'type': 'REG', 'reg': 'RAX'}]},
            ],
            # Used to pre-seed the address resolver with symbol names for
            # testing.
            name_map={
                0xf80002883948: ["nt!RtlpAllocateSecondLevelDir"],
            },
        ),


        # Example from MiSessionInsertImage()
        # http://gate.upm.ro/os/LABs/Windows_OS_Internals_Curriculum_Resource_Kit-ACADEMIC/WindowsResearchKernel-WRK/WRK-v1.2/base/ntos/mm/sessload.c
        dict(
            # Taken from Windows 8 x64 dis "nt!MiSessionInsertImage"
            offset=0xf801ea55f680,
            data=('48895c240848896c2410488974241857415641574883ec20498bf0488bea'
                  '488bf941be5000000041b84d6d4869b900020000418bd6e856091200488b'
                  'd84885c00f84fee60900458bc633d2488bc8e89d03f3ffc7433001000000'
                  '4883cf0348897b20654c8b342588010000498b86b8000000488b88f00300'
                  '008b41084c8db9f80b0000488d7968498bd7498bce48896b38894334e8ef'
                  '16f7ff4c8b1f4c3bdf'),
            rules=[
                {'mnemonic': 'MOV', 'operands': [
                    {'type': 'REG', 'reg': '$RDI'},
                    {'type': 'REG', 'reg': 'RCX'}]},

                {'mnemonic': 'CALL',
                 'comment': 'nt!ExAllocatePoolWithTag'},

                {'mnemonic': 'MOV', 'operands': [
                    {'type': 'REG', 'reg': '$RBX'},
                    {'type': 'REG', 'reg': 'RAX'}]},

                # RtlZeroMemory (NewImage, sizeof(IMAGE_ENTRY_IN_SESSION));
                {'mnemonic': 'CALL', 'comment': 'nt!memset'},

                # NewImage->ImageCountInThisSession = 1;
                {'mnemonic': 'MOV', 'operands': [
                    {'disp': "$ImageCountInThisSession",
                     'base': '$RBX', 'type': 'MEM'},
                    {'address': 1, 'type': 'IMM'}]},

                # NewImage->Address = BaseAddress;
                {'mnemonic': 'MOV', 'operands': [
                    {'disp': "$Address",
                     'base': '$RBX', 'type': 'MEM'},
                    {'type': 'REG', 'reg': '$RDI'}]},
            ],
            name_map={
                0xf801ea680010: ["nt!ExAllocatePoolWithTag"],
                0xf801ea48fa70: ["nt!memset"],
            },
            expected={"$Address": 0x20, "$ImageCountInThisSession": 0x30},
        ),

    ]

    def testDynamicProfile(self):
        for case in self.TEST_CASES:
            self.session = mock.Mock(
                wraps=self.MakeUserSession(),
                address_resolver=MockAddressResolver(
                    case.get("name_map", {}))
            )

            matcher = dynamic_profiles.DisassembleMatcher(
                mode=case.get("mode", "AMD64"),
                rules=case["rules"],
                session=self.session)

            match = matcher.Match(offset=case.get("offset", 0),
                                  data=case["data"].decode("hex"))

            for k, v in case["expected"].iteritems():
                self.assertEqual(match[k], v)
