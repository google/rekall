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
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
except ImportError:
    x509 = None

import base64

from rekall import plugin
from rekall import scan
from rekall import testlib

from rekall.plugins import core
from rekall.plugins import yarascanner
from rekall.plugins.windows import common
from rekall.plugins.overlays import basic
from rekall_lib import utils


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
        ('StringCheck', dict(needle=b"\x30\x82"))
        ]

    def scan(self, offset=0, maxlen=None):
        for hit in super(CertScanner, self).scan(offset=offset, maxlen=maxlen):
            signature = self.address_space.read(hit + 4, 3)
            size = self.profile.Object(
                "unsigned be short", offset=hit+2, vm=self.address_space)
            description = None

            if signature.startswith(b"\x30\x82"):
                data = self.address_space.read(hit, size + 4)
                if x509:
                    try:
                        cert = x509.load_der_x509_certificate(data, default_backend())
                        description = dict((
                            attr.oid._name, attr.value) for attr in cert.subject)
                    except Exception:
                        pass

                yield hit, "X509", data, description

            elif signature.startswith(b"\x02\x01\x00"):
                data = self.address_space.read(hit, size + 4)
                if x509:
                    try:
                        pem = (b"-----BEGIN RSA PRIVATE KEY-----\n" +
                               base64.b64encode(data) +
                               b"-----END RSA PRIVATE KEY-----")
                        key = serialization.load_pem_private_key(
                            pem, password=None, backend=default_backend())
                        description = ""
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
        dict(name="length", width=10),
        dict(name="Filename", width=30),
        dict(name="data", hidden=True),
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

        if signature.startswith(b"\x30\x82"):
            data = address_space.read(hit, size + 4)
            if x509:
                try:
                    cert = x509.load_der_x509_certificate(data, default_backend())
                    description = dict((
                        attr.oid._name, attr.value) for attr in cert.subject)
                except Exception:
                    pass

            return "X509", data, description

        elif signature.startswith(b"\x02\x01\x00"):
            data = address_space.read(hit, size + 4)
            if x509:
                try:
                    pem = (b"-----BEGIN RSA PRIVATE KEY-----\n" +
                           base64.b64encode(data) +
                           b"-----END RSA PRIVATE KEY-----")
                    key = serialization.load_pem_private_key(
                        pem, password=None, backend=default_backend())
                    description = ""
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
