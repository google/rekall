# Rekall Memory Forensics
# Copyright 2015 Google Inc. All Rights Reserved.
#
# This file is part of Rekall Memory Forensics.
#
# Rekall Memory Forensics is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General Public
# License.
#
# Rekall Memory Forensics is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# Rekall Memory Forensics.  If not, see <http://www.gnu.org/licenses/>.
#

"""Emulation of the Mimikatz tool.

This code replicates the algorithm first implemented in the mimikatz tool, which
can be found here:

https://github.com/gentilkiwi/mimikatz

Based on the Volatility plugin by Francesco Picasso:
https://github.com/dfirfpi/hotoloti/blob/master/volatility/mimikatz.py
"""

# pylint: disable=protected-access

__author__ = ("Michael Cohen <scudette@google.com> and "
              "Francesco Picasso <francesco.picasso@gmail.com>")

from Crypto.Cipher import AES
from Crypto.Cipher import DES3

from rekall import plugin
from rekall.plugins.overlays.windows import pe_vtypes
from rekall.plugins.windows import common


class Lsasrv(pe_vtypes.BasicPEProfile):
    """A profile for lsasrv.dll"""


class Wdigest(pe_vtypes.BasicPEProfile):
    """A profile for wdigest.dll"""


def InitMimikatzProfile(profile):
    profile.add_overlay({
        "_KIWI_WDIGEST_LIST_ENTRY": [None, {
            "List": [0, ["_LIST_ENTRY"]],
            "Cred": [lambda x: x.LocallyUniqueIdentifier.obj_end + 8,
                     ["_KIWI_GENERIC_PRIMARY_CREDENTIAL"]]
        }],
        "_LSA_UNICODE_STRING": [None, {
            "Value": lambda x: x.Buffer.dereference_as(
                "UnicodeString", target_args=dict(length=x.Length)),
            "Raw": lambda x: x.Buffer.dereference_as(
                "String", target_args=dict(length=x.MaximumLength)).v()
        }],

        "_KIWI_HARD_KEY": [None, {
            "data": lambda x: x.m("data").cast(
                "String", term=None, length=x.cbSecret)
        }],
    })

    return profile


class LsaDecryptor(object):
    def __init__(self, session, profile):
        self.session = session
        self.profile = profile

        # Find the IV
        self.iv = self.session.address_resolver.get_constant_object(
            "lsasrv!InitializationVector", "String", length=16, term=None).v()

        aes_handle = self.profile._KIWI_BCRYPT_HANDLE_KEY(
            self.session.address_resolver.get_address_by_name(
                "*lsasrv!hAesKey"))

        self.aes_key = aes_handle.key.hardkey.data.v()
        des_handle = self.profile._KIWI_BCRYPT_HANDLE_KEY(
            self.session.address_resolver.get_address_by_name(
                "*lsasrv!h3DesKey"))

        self.des_key = des_handle.key.hardkey.data.v()
        if not self.iv or not (self.des_key and self.aes_key):
            raise IOError("Unable to decrypt keys.")

    def decrypt(self, encrypted):
        if len(encrypted) % 8:
            cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv)
        else:
            cipher = DES3.new(self.des_key, DES3.MODE_CBC, self.iv[:8])

        return cipher.decrypt(encrypted)


class Mimikatz(common.WindowsCommandPlugin):
    """Extract and decrypt passwords from the LSA Security Service."""

    name = "mimikatz"

    def __init__(self, **kwargs):
        super(Mimikatz, self).__init__(**kwargs)

        # Track the following modules. If we do not have them in the profile
        # repository then try to get them directly from Microsoft.
        tracked = self.session.GetParameter(
            "autodetect_build_local_tracked") or []

        needed = set(["lsasrv", "wdigest"])
        if not needed.issubset(tracked):
            needed.update(tracked)
            with self.session as session:
                session.SetParameter("autodetect_build_local_tracked", needed)

    def render(self, renderer):
        renderer.table_header([
            dict(name="Module", width=20),
            dict(name="User", width=20),
            dict(name="Domain", width=20),
            dict(name="Password", width=20)])

        # Get undocumented structs from mimikatz.
        arch = self.profile.metadata("arch")
        self.mimikatz_profile = InitMimikatzProfile(
            self.session.LoadProfile("mimikatz/%s" % arch))

        cc = self.session.plugins.cc()
        # Switch to the lsass process.
        for task in self.session.plugins.pslist(
                proc_regex="lsass.exe").filter_processes():
            cc.SwitchProcessContext(task)

            try:
                decryptor = LsaDecryptor(self.session, self.mimikatz_profile)
            except IOError:
                raise plugin.PluginError("Unable to decrypt LSA secret.")

            list_head = self.mimikatz_profile._LIST_ENTRY(
                offset=self.session.address_resolver.get_address_by_name(
                    "wdigest!l_LogSessList"))

            seen = set()
            for entry in list_head.list_of_type(
                    "_KIWI_WDIGEST_LIST_ENTRY", "List"):
                row = ("wdigest",
                       entry.Cred.UserName.Value,
                       entry.Cred.Domaine.Value,
                       decryptor.decrypt(entry.Cred.Password.Raw))
                if row in seen:
                    continue

                seen.add(row)

                if not row[1].v():
                    continue

                renderer.table_row(*row)
