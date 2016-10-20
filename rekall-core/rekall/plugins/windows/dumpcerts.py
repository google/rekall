# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Authors:
# Michael Hale Ligh <michael.ligh@mnin.org>
# Michael Cohen <scudette@google.com>
#
# Contributors/References:
#   ## Based on sslkeyfinder: http://www.trapkit.de/research/sslkeyfinder/

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

try:
    from M2Crypto import X509, RSA
except ImportError:
    X509 = RSA = None

from rekall import plugin
from rekall import scan
from rekall import testlib
from rekall import utils

from rekall.plugins import core
from rekall.plugins import yarascanner
from rekall.plugins.windows import common
from rekall.plugins.overlays import basic


class CertScanner(scan.BaseScanner):
    """A scanner for certificate ASN.1 objects.

    Yara rules for the two ASN.1 encoded objects we are looking for:

    'x509' : 'rule x509 {
       strings: $a = {30 82 ?? ?? 30 82 ?? ??} condition: $a
       }',

    'pkcs' : 'rule pkcs {
       strings: $a = {30 82 ?? ?? 02 01 00} condition: $a
       }',

    These rules are very simple, and so we don't really use Yara for this - its
    faster to just scan directly.
    """

    checks = [
        ('StringCheck', dict(needle="\x30\x82"))
        ]

    def scan(self, offset=0, maxlen=None):
        for hit in super(CertScanner, self).scan(offset=offset, maxlen=maxlen):
            signature = self.address_space.read(hit + 4, 3)
            size = self.profile.Object(
                "unsigned be short", offset=hit+2, vm=self.address_space)
            description = None

            if signature.startswith("\x30\x82"):
                data = self.address_space.read(hit, size + 4)
                if X509:
                    try:
                        cert = X509.load_cert_der_string(data)
                        description = utils.SmartStr(cert.get_subject())
                    except X509.X509Error:
                        pass

                yield hit, "X509", data, description

            elif signature.startswith("\x02\x01\x00"):
                data = self.address_space.read(hit, size + 4)
                if RSA:
                    try:
                        pem = ("-----BEGIN RSA PRIVATE KEY-----\n" +
                                 data.encode("base64") +
                                 "-----END RSA PRIVATE KEY-----")
                        key = RSA.load_key_string(pem)
                        description = "Verified: %s" % key.check_key()
                    except Exception:
                        pass

                yield hit, "RSA", data, description


class CertScan(plugin.PhysicalASMixin, plugin.TypedProfileCommand,
               plugin.Command):
    """Dump RSA private and public SSL keys from the physical address space."""
    __name = "simple_certscan"

    # We can just display the certs instead of dumping them.
    dump_dir_optional = True
    default_dump_dir = None

    table_header = [
        dict(name="address", style="address"),
        dict(name="type", width=10),
        dict(name="length", width=10),
        dict(name="data", hidden=True),
        dict(name="description"),
    ]

    def collect(self):
        scanner = CertScanner(
            address_space=self.physical_address_space,
            session=self.session,
            profile=basic.Profile32Bits(session=self.session))

        for hit, type, data, description in scanner.scan(
                0, self.physical_address_space.end()):
            yield dict(address=hit,
                       type=type,
                       length=len(data),
                       data=data,
                       description=description)


class CertDump(core.DirectoryDumperMixin, CertScan):
    """Dump certs found by cert scan."""

    name = "simple_certdump"

    table_header = [
        dict(name="address", style="address"),
        dict(name="type", width=10),
        dict(name="Filename", width=30),
        dict(name="description"),
    ]

    def collect(self):
        renderer = self.session.GetRenderer()
        for row in super(CertDump, self).collect():
            if self.dump_dir:
                row["Filename"] = "%s.%08X.der" % (row["type"], row["address"])
                with renderer.open(directory=self.dump_dir,
                                   filename=row["Filename"],
                                   mode="wb") as fd:
                    fd.write(row["data"])
                    yield row


class TestCertDump(testlib.HashChecker):
    PARAMETERS = dict(
        commandline="certdump -D %(tempdir)s",
        )


class CertYaraScan(yarascanner.YaraScanMixin, common.WinScanner):
    """Scan certificates in windows memory regions."""
    name = "certscan"

    table_header = [
        dict(name="Owner", width=20),
        dict(name="Offset", style="address"),
        dict(name="type", width=10),
        dict(name="description", width=80),
        dict(name="data", hidden=True),
        dict(name="Context"),
    ]

    scanner_defaults = dict(
        scan_physical=True
    )

    __args = [
        dict(name="yara_file", default=None, hidden=True),
        dict(name="yara_expression", hidden=True, default="""
rule x509 {
  strings: $a = {30 82 ?? ?? 30 82 ?? ??} condition: $a
}
rule pkcs {
  strings: $a = {30 82 ?? ?? 02 01 00} condition: $a
}
"""),
        dict(name="hits", default=1000000, type="IntParser",
             help="Total number of hits to report."),
    ]

    def verify_hit(self, hit, address_space):
        signature = address_space.read(hit + 4, 3)
        size = self.profile.Object(
            "unsigned be short", offset=hit+2, vm=address_space)
        description = None

        if signature.startswith("\x30\x82"):
            data = address_space.read(hit, size + 4)
            if X509:
                try:
                    cert = X509.load_cert_der_string(data)
                    description = utils.SmartStr(cert.get_subject())
                except X509.X509Error:
                    pass

            return "X509", data, description

        elif signature.startswith("\x02\x01\x00"):
            data = address_space.read(hit, size + 4)
            if RSA:
                try:
                    pem = ("-----BEGIN RSA PRIVATE KEY-----\n" +
                             data.encode("base64") +
                             "-----END RSA PRIVATE KEY-----")
                    key = RSA.load_key_string(pem)
                    description = "Verified: %s" % key.check_key()
                except Exception:
                    pass

            return "RSA", data, description

        return None, None, None

    def collect(self):
        for row in super(CertYaraScan, self).collect():
            type, data, description = self.verify_hit(
                row["Offset"], row["address_space"])

            if type is not None:
                yield dict(Owner=row["Owner"],
                           Offset=row["Offset"],
                           type=type,
                           description=description,
                           Context=row["Context"],
                           data=data)


class TestCertYaraScan(testlib.SimpleTestCase):
    PARAMETERS = dict(
        commandline="certscan --limit %(limit)s",
        limit=20000000
    )


class TestCertVadScan(testlib.HashChecker):
    PARAMETERS = dict(
        commandline="cert_vad_scan --proc_regex %(regex)s -D %(tempdir)s ",
        regex="csrss.exe"
        )
