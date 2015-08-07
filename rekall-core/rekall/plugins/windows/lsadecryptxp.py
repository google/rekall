#!/usr/bin/python

# LsaDecryptXp
# Copyright 2015 Francesco "dfirfpi" Picasso. All Rights Reserved.
# Author email: <francesco.picasso@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
'''Windows NT 5.1 and 5.2 LsaEncryptMemory decryption algorithm.'''

import struct


class XP_DES():
    '''NT 5.1 and NT 5.2 lsasrv.dll DES decryption 32 bits implementation.'''

    sboxul = [
      [0x02080800, 0x00080000, 0x02000002, 0x02080802,
       0x02000000, 0x00080802, 0x00080002, 0x02000002,
       0x00080802, 0x02080800, 0x02080000, 0x00000802,
       0x02000802, 0x02000000, 0x00000000, 0x00080002,
       0x00080000, 0x00000002, 0x02000800, 0x00080800,
       0x02080802, 0x02080000, 0x00000802, 0x02000800,
       0x00000002, 0x00000800, 0x00080800, 0x02080002,
       0x00000800, 0x02000802, 0x02080002, 0x00000000,
       0x00000000, 0x02080802, 0x02000800, 0x00080002,
       0x02080800, 0x00080000, 0x00000802, 0x02000800,
       0x02080002, 0x00000800, 0x00080800, 0x02000002,
       0x00080802, 0x00000002, 0x02000002, 0x02080000,
       0x02080802, 0x00080800, 0x02080000, 0x02000802,
       0x02000000, 0x00000802, 0x00080002, 0x00000000,
       0x00080000, 0x02000000, 0x02000802, 0x02080800,
       0x00000002, 0x02080002, 0x00000800, 0x00080802],

      [0x40108010, 0x00000000, 0x00108000, 0x40100000,
       0x40000010, 0x00008010, 0x40008000, 0x00108000,
       0x00008000, 0x40100010, 0x00000010, 0x40008000,
       0x00100010, 0x40108000, 0x40100000, 0x00000010,
       0x00100000, 0x40008010, 0x40100010, 0x00008000,
       0x00108010, 0x40000000, 0x00000000, 0x00100010,
       0x40008010, 0x00108010, 0x40108000, 0x40000010,
       0x40000000, 0x00100000, 0x00008010, 0x40108010,
       0x00100010, 0x40108000, 0x40008000, 0x00108010,
       0x40108010, 0x00100010, 0x40000010, 0x00000000,
       0x40000000, 0x00008010, 0x00100000, 0x40100010,
       0x00008000, 0x40000000, 0x00108010, 0x40008010,
       0x40108000, 0x00008000, 0x00000000, 0x40000010,
       0x00000010, 0x40108010, 0x00108000, 0x40100000,
       0x40100010, 0x00100000, 0x00008010, 0x40008000,
       0x40008010, 0x00000010, 0x40100000, 0x00108000],

      [0x04000001, 0x04040100, 0x00000100, 0x04000101,
       0x00040001, 0x04000000, 0x04000101, 0x00040100,
       0x04000100, 0x00040000, 0x04040000, 0x00000001,
       0x04040101, 0x00000101, 0x00000001, 0x04040001,
       0x00000000, 0x00040001, 0x04040100, 0x00000100,
       0x00000101, 0x04040101, 0x00040000, 0x04000001,
       0x04040001, 0x04000100, 0x00040101, 0x04040000,
       0x00040100, 0x00000000, 0x04000000, 0x00040101,
       0x04040100, 0x00000100, 0x00000001, 0x00040000,
       0x00000101, 0x00040001, 0x04040000, 0x04000101,
       0x00000000, 0x04040100, 0x00040100, 0x04040001,
       0x00040001, 0x04000000, 0x04040101, 0x00000001,
       0x00040101, 0x04000001, 0x04000000, 0x04040101,
       0x00040000, 0x04000100, 0x04000101, 0x00040100,
       0x04000100, 0x00000000, 0x04040001, 0x00000101,
       0x04000001, 0x00040101, 0x00000100, 0x04040000],

      [0x00401008, 0x10001000, 0x00000008, 0x10401008,
       0x00000000, 0x10400000, 0x10001008, 0x00400008,
       0x10401000, 0x10000008, 0x10000000, 0x00001008,
       0x10000008, 0x00401008, 0x00400000, 0x10000000,
       0x10400008, 0x00401000, 0x00001000, 0x00000008,
       0x00401000, 0x10001008, 0x10400000, 0x00001000,
       0x00001008, 0x00000000, 0x00400008, 0x10401000,
       0x10001000, 0x10400008, 0x10401008, 0x00400000,
       0x10400008, 0x00001008, 0x00400000, 0x10000008,
       0x00401000, 0x10001000, 0x00000008, 0x10400000,
       0x10001008, 0x00000000, 0x00001000, 0x00400008,
       0x00000000, 0x10400008, 0x10401000, 0x00001000,
       0x10000000, 0x10401008, 0x00401008, 0x00400000,
       0x10401008, 0x00000008, 0x10001000, 0x00401008,
       0x00400008, 0x00401000, 0x10400000, 0x10001008,
       0x00001008, 0x10000000, 0x10000008, 0x10401000],

      [0x08000000, 0x00010000, 0x00000400, 0x08010420,
       0x08010020, 0x08000400, 0x00010420, 0x08010000,
       0x00010000, 0x00000020, 0x08000020, 0x00010400,
       0x08000420, 0x08010020, 0x08010400, 0x00000000,
       0x00010400, 0x08000000, 0x00010020, 0x00000420,
       0x08000400, 0x00010420, 0x00000000, 0x08000020,
       0x00000020, 0x08000420, 0x08010420, 0x00010020,
       0x08010000, 0x00000400, 0x00000420, 0x08010400,
       0x08010400, 0x08000420, 0x00010020, 0x08010000,
       0x00010000, 0x00000020, 0x08000020, 0x08000400,
       0x08000000, 0x00010400, 0x08010420, 0x00000000,
       0x00010420, 0x08000000, 0x00000400, 0x00010020,
       0x08000420, 0x00000400, 0x00000000, 0x08010420,
       0x08010020, 0x08010400, 0x00000420, 0x00010000,
       0x00010400, 0x08010020, 0x08000400, 0x00000420,
       0x00000020, 0x00010420, 0x08010000, 0x08000020],

      [0x80000040, 0x00200040, 0x00000000, 0x80202000,
       0x00200040, 0x00002000, 0x80002040, 0x00200000,
       0x00002040, 0x80202040, 0x00202000, 0x80000000,
       0x80002000, 0x80000040, 0x80200000, 0x00202040,
       0x00200000, 0x80002040, 0x80200040, 0x00000000,
       0x00002000, 0x00000040, 0x80202000, 0x80200040,
       0x80202040, 0x80200000, 0x80000000, 0x00002040,
       0x00000040, 0x00202000, 0x00202040, 0x80002000,
       0x00002040, 0x80000000, 0x80002000, 0x00202040,
       0x80202000, 0x00200040, 0x00000000, 0x80002000,
       0x80000000, 0x00002000, 0x80200040, 0x00200000,
       0x00200040, 0x80202040, 0x00202000, 0x00000040,
       0x80202040, 0x00202000, 0x00200000, 0x80002040,
       0x80000040, 0x80200000, 0x00202040, 0x00000000,
       0x00002000, 0x80000040, 0x80002040, 0x80202000,
       0x80200000, 0x00002040, 0x00000040, 0x80200040],

      [0x00004000, 0x00000200, 0x01000200, 0x01000004,
       0x01004204, 0x00004004, 0x00004200, 0x00000000,
       0x01000000, 0x01000204, 0x00000204, 0x01004000,
       0x00000004, 0x01004200, 0x01004000, 0x00000204,
       0x01000204, 0x00004000, 0x00004004, 0x01004204,
       0x00000000, 0x01000200, 0x01000004, 0x00004200,
       0x01004004, 0x00004204, 0x01004200, 0x00000004,
       0x00004204, 0x01004004, 0x00000200, 0x01000000,
       0x00004204, 0x01004000, 0x01004004, 0x00000204,
       0x00004000, 0x00000200, 0x01000000, 0x01004004,
       0x01000204, 0x00004204, 0x00004200, 0x00000000,
       0x00000200, 0x01000004, 0x00000004, 0x01000200,
       0x00000000, 0x01000204, 0x01000200, 0x00004200,
       0x00000204, 0x00004000, 0x01004204, 0x01000000,
       0x01004200, 0x00000004, 0x00004004, 0x01004204,
       0x01000004, 0x01004200, 0x01004000, 0x00004004],

      [0x20800080, 0x20820000, 0x00020080, 0x00000000,
       0x20020000, 0x00800080, 0x20800000, 0x20820080,
       0x00000080, 0x20000000, 0x00820000, 0x00020080,
       0x00820080, 0x20020080, 0x20000080, 0x20800000,
       0x00020000, 0x00820080, 0x00800080, 0x20020000,
       0x20820080, 0x20000080, 0x00000000, 0x00820000,
       0x20000000, 0x00800000, 0x20020080, 0x20800080,
       0x00800000, 0x00020000, 0x20820000, 0x00000080,
       0x00800000, 0x00020000, 0x20000080, 0x20820080,
       0x00020080, 0x20000000, 0x00000000, 0x00820000,
       0x20800080, 0x20020080, 0x20020000, 0x00800080,
       0x20820000, 0x00000080, 0x00800080, 0x20020000,
       0x20820080, 0x00800000, 0x20800000, 0x20000080,
       0x00820000, 0x00020080, 0x20020080, 0x20800000,
       0x00000080, 0x20820000, 0x00820080, 0x00000000,
       0x20000000, 0x20800080, 0x00020000, 0x00820080]
    ]

    def __init__(self, des_key):

        if len(des_key) != 128:
            raise ValueError("DES KEY must be 128 bytes long!")

        self.des_key = des_key

        # Fixed 32 bits architecture.
        self.max_bits = 32
        self.max_bits_mask = (2**self.max_bits - 1)

    def rol(self, value, r_bits):
        r_bits %= self.max_bits

        return ((value << r_bits | (value >> (self.max_bits - r_bits))) &
            self.max_bits_mask)

    def ror(self, value, r_bits):
        r_bits %= self.max_bits

        return ((value << (self.max_bits - r_bits) | (value >> r_bits)) &
            self.max_bits_mask)

    def _decrypt_loop(self, dst, src, ecx, round):

        eax, edx = struct.unpack('<LL', self.des_key[round * 8:round * 8 + 8])
        ebx = 0
        eax ^= src
        edx ^= src
        eax &= 0x0FCFCFCFC
        edx &= 0x0CFCFCFCF
        ebx = (ebx & 0xFFFFFF00) | (eax & 0x000000FF)
        ecx = (ecx & 0xFFFFFF00) | ((eax & 0x0000FF00) >> 8)
        edx = self.ror(edx, 4)
        ebp = self.sboxul[0][ebx >> 2]
        ebx = (ebx & 0xFFFFFF00) | (edx & 0x000000FF)
        dst ^= ebp
        ebp = self.sboxul[2][ecx >> 2]
        dst ^= ebp
        ecx = (ecx & 0xFFFFFF00) | ((edx & 0x0000FF00) >> 8)
        eax >>= 0x10
        ebp = self.sboxul[1][ebx >> 2]
        dst ^= ebp
        ebx = (ebx & 0xFFFFFF00) | ((eax & 0x0000FF00) >> 8)
        edx >>= 0x10
        ebp = self.sboxul[3][ecx >> 2]
        dst ^= ebp
        ecx = (ecx & 0xFFFFFF00) | ((edx & 0x0000FF00) >> 8)
        eax &= 0xFF
        edx &= 0xFF
        ebx = self.sboxul[6][ebx >> 2]
        dst ^= ebx
        ebx = self.sboxul[7][ecx >> 2]
        dst ^= ebx
        ebx = self.sboxul[4][eax >> 2]
        dst ^= ebx
        ebx = self.sboxul[5][edx >> 2]
        dst ^= ebx
        return dst, ecx

    def decrypt(self, encrypted):

        esi = encrypted
        eax = struct.unpack('<L', esi[:4])[0]
        edi = struct.unpack('<L', esi[4:])[0]
        eax = self.rol(eax, 4)
        esi = eax
        eax = eax ^ edi
        eax = eax & 0x0F0F0F0F0
        esi = esi ^ eax
        edi = edi ^ eax
        edi = self.rol(edi, 0x14)
        eax = edi
        edi = edi ^ esi
        edi = edi & 0x0FFF0000F
        eax = eax ^ edi
        esi = esi ^ edi
        eax = self.rol(eax, 0x0e)
        edi = eax
        eax = eax ^ esi
        eax = eax & 0x33333333
        edi = edi ^ eax
        esi = esi ^ eax
        esi = self.rol(esi, 0x16)
        eax = esi
        esi = esi ^ edi
        esi = esi & 0x3FC03FC
        eax = eax ^ esi
        edi = edi ^ esi
        eax = self.rol(eax, 0x9)
        esi = eax
        eax = eax ^ edi
        eax = eax & 0x0AAAAAAAA
        esi = esi ^ eax
        edi = edi ^ eax
        edi = self.rol(edi, 0x1)

        ecx = 0
        for round in range(15, 0, -2):
            edi, ecx = self._decrypt_loop(edi, esi, ecx, round)
            esi, ecx = self._decrypt_loop(esi, edi, ecx, round-1)

        esi = self.ror(esi, 1)
        eax = edi
        edi ^= esi
        edi &= 0x0AAAAAAAA
        eax ^= edi
        esi ^= edi
        eax = self.rol(eax, 0x17)
        edi = eax
        eax ^= esi
        eax &= 0x3FC03FC
        edi ^= eax
        esi ^= eax
        edi = self.rol(edi, 0x0A)
        eax = edi
        edi ^= esi
        edi &= 0x33333333
        eax ^= edi
        esi ^= edi
        esi = self.rol(esi, 0x12)
        edi = esi
        esi ^= eax
        esi &= 0x0FFF0000F
        edi ^= esi
        eax ^= esi
        edi = self.rol(edi, 0x0C)
        esi = edi
        edi ^= eax
        edi &= 0x0F0F0F0F0
        esi ^= edi
        eax ^= edi
        eax = self.ror(eax, 4)

        return struct.pack('<L', eax) + struct.pack('<L', esi)


class XP_DESX():
    '''NT 5.1 and NT 5.2 lsasrv.dll DESX implementation.'''

    def __init__(self, desx_key):

        if len(desx_key) != 144:
            raise ValueError("DESX KEY must be 144 bytes long!")

        self.desx_key = desx_key
        self.DES = XP_DES(desx_key[16:])

    def decrypt(self, encrypted):

        if len(encrypted) != 8:
            raise ValueError("Encrypted data length must be 8 bytes!")

        eax, esi = struct.unpack('<LL', encrypted)
        ecx, edx = struct.unpack('<LL', self.desx_key[8:16])
        ecx ^= eax
        edx ^= esi
        enc_64 = struct.pack('<L', ecx) + struct.pack('<L', edx)

        decrypted = self.DES.decrypt(enc_64)

        ecx, ebx = struct.unpack('<LL', self.desx_key[:8])
        edx, eax = struct.unpack('<LL', decrypted)
        edx ^= ecx
        eax ^= ebx

        return struct.pack('<L', edx) + struct.pack('<L', eax)


class XP_CBC_DESX():
    '''NT 5.1 and NT 5.2 lsasrv.dll CBC with DESX partial implementation.'''

    def __init__(self, desx_key):

        if len(desx_key) != 144:
            raise ValueError("DESX KEY must be 144 bytes long!")

        self.desx_key = desx_key
        self.DESX = XP_DESX(desx_key)

    def decrypt(self, encrypted, feedback):

        if len(encrypted) % 8:
            raise ValueError("Encrypted length is not multiple of 8 bytes")

        decrypted = self.DESX.decrypt(encrypted)

        decrypted_temp = struct.unpack('<Q', decrypted)[0]
        decrypted_temp ^= struct.unpack('<Q', feedback)[0]
        decrypted = struct.pack('<Q', decrypted_temp)

        feedback = encrypted

        return decrypted, feedback


class XP_LsaDecryptMemory():

    def __init__(self, desx_key, feedback):

        if len(desx_key) != 144:
            raise ValueError("DESX KEY must be 144 bytes long!")

        if len(feedback) != 8:
            raise ValueError("feedback must be 8 bytes long!")

        self.desx_key = desx_key
        self.feedback = feedback
        self.CBC_DESX = XP_CBC_DESX(desx_key)

    def decrypt(self, encrypted):
        if len(encrypted) % 8:
            raise ValueError("Encrypted length is not multiple of 8 bytes.")

        decrypted = ''
        feedback = self.feedback

        for i in range(0, len(encrypted) >> 3, 1):
            decrypted8, feedback = self.CBC_DESX.decrypt(
                encrypted[i*8:i*8+8], feedback)
            decrypted += decrypted8

        return decrypted
