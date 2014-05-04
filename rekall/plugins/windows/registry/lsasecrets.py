# Rekall Memory Forensics
# Copyright (c) 2008 Volatile Systems
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
# Copyright 2013 Google Inc. All Rights Reserved.
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
#

#pylint: disable-msg=C0111

"""
@author:       Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      bdolangavitt@wesleyan.edu
"""

import struct
from rekall.plugins.windows.registry import hashdump
from Crypto import Hash
from Crypto import Cipher


lsa_types = {
    'LSA_BLOB': [ 8, {
            'cbData': [0, ['unsigned int']],
            'cbMaxData': [4, ['unsigned int']],
            'szData': [8, ['String', dict(length=lambda x: x.cbData)]],
            }]
    }


def get_lsa_key(sec_registry, bootkey):
    enc_reg_key = sec_registry.open_key(["Policy", "PolSecretEncryptionKey"])

    enc_reg_value = enc_reg_key.ValueList.List.dereference()[0]
    if not enc_reg_value:
        return None

    obf_lsa_key = enc_reg_value.Data.dereference_as(
        "String", length=enc_reg_value.DataLength).v()

    if not obf_lsa_key:
        return None

    md5 = Hash.MD5.new()
    md5.update(bootkey)

    for _i in xrange(1000):
        md5.update(obf_lsa_key[60:76])
    rc4key = md5.digest()

    rc4 = Cipher.ARC4.new(rc4key)
    lsa_key = rc4.decrypt(obf_lsa_key[12:60])

    return lsa_key[0x10:0x20]

def decrypt_secret(secret, key):
    """Python implementation of SystemFunction005.

    Decrypts a block of data with DES using given key.
    Note that key can be longer than 7 bytes."""
    decrypted_data = ''
    j = 0   # key index
    for i in xrange(0, len(secret), 8):
        enc_block = secret[i:i + 8]
        block_key = key[j:j + 7]
        des_key = hashdump.str_to_key(block_key)

        des = Cipher.DES.new(des_key, Cipher.DES.MODE_ECB)
        decrypted_data += des.decrypt(enc_block)

        j += 7
        if len(key[j:j + 7]) < 7:
            j = len(key[j:j + 7])

    (dec_data_len,) = struct.unpack("<L", decrypted_data[:4])
    return decrypted_data[8:8 + dec_data_len]

def get_secret_by_name(secaddr, name, lsakey):
    root = rawreg.get_root(secaddr)
    if not root:
        return None

    enc_secret_key = rawreg.open_key(root, ["Policy", "Secrets", name, "CurrVal"])
    if not enc_secret_key:
        return None

    enc_secret_value = enc_secret_key.ValueList.List.dereference()[0]
    if not enc_secret_value:
        return None

    enc_secret = secaddr.read(enc_secret_value.Data,
            enc_secret_value.DataLength)
    if not enc_secret:
        return None

    return decrypt_secret(enc_secret[0xC:], lsakey)

def get_secrets(sys_registry, sec_registry):

    bootkey = hashdump.get_bootkey(sys_registry)
    lsakey = get_lsa_key(sec_registry, bootkey)

    secrets_key = sec_registry.open_key(["Policy", "Secrets"])
    if not secrets_key:
        return

    for key in secrets_key.subkeys():
        sec_val_key = key.open_subkey("CurrVal")

        if not sec_val_key:
            continue

        for enc_secret_value in sec_val_key.values():
            enc_secret = enc_secret_value.Data.dereference_as(
                "String", length=enc_secret_value.DataLength).v()

            if enc_secret:
                secret = decrypt_secret(enc_secret[0xC:], lsakey)
                yield key.Name, secret
