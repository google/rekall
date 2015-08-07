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

import os

try:
    from M2Crypto import X509, RSA
except ImportError:
    X509 = RSA = None

from rekall import plugin
from rekall import scan
from rekall import testlib
from rekall import utils

from rekall.plugins import core
from rekall.plugins.windows import common
from rekall.plugins.windows import vadinfo
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


class CertScan(core.DirectoryDumperMixin, plugin.PhysicalASMixin,
               plugin.Command):
    """Dump RSA private and public SSL keys from the physical address space."""

    __name = "certscan"

    # We can just display the certs instead of dumping them.
    dump_dir_optional = True
    default_dump_dir = None

    def render(self, renderer):
        headers = [("Address", "address", "[addrpad]"),
                   ("Type", "type", "10"),
                   ("Length", "length", "10")]

        if self.dump_dir:
            headers.append(("Filename", "filename", "20"))

        headers.append(("Description", "description", ""))

        renderer.table_header(headers)

        scanner = CertScanner(
            address_space=self.physical_address_space,
            session=self.session,
            profile=basic.Profile32Bits(session=self.session))

        for hit, type, data, description in scanner.scan():
            args = [hit, type, len(data)]

            if self.dump_dir:
                filename = "%s.%08X.der" % (type, hit)

                with renderer.open(directory=self.dump_dir,
                                   filename=filename,
                                   mode="wb") as fd:
                    fd.write(data)
                    args.append(filename)

            args.append(description)
            renderer.table_row(*args)


class TestCertScan(testlib.HashChecker):
    PARAMETERS = dict(
        commandline="certscan -D %(tempdir)s",
        )


class VadCertScanner(CertScanner, vadinfo.VadScanner):
    """Scanner for certs in vads."""


class CertVadScan(core.DirectoryDumperMixin, common.WinProcessFilter):
    """Scan certificates in process Vads."""

    __name = "cert_vad_scan"

    # We can just display the certs instead of dumping them.
    dump_dir_optional = True
    default_dump_dir = None

    def render(self, renderer):
        headers = [
            ("Pid", "pid", "5"),
            ("Command", "command", "10"),
            ("Address", "address", "[addrpad]"),
            ("Type", "type", "5"),
            ("Length", "length", "5")]

        if self.dump_dir:
            headers.append(("Filename", "filename", "20"))

        headers.append(("Description", "description", ""))

        renderer.table_header(headers)

        for task in self.filter_processes():
            scanner = VadCertScanner(task=task)

            for hit, type, data, description in scanner.scan():
                args = [task.UniqueProcessId, task.ImageFileName,
                        hit, type, len(data)]

                if self.dump_dir:
                    filename = "%s.%s.%08X.der" % (
                        task.UniqueProcessId, type, hit)
                    with renderer.open(directory=self.dump_dir,
                                       filename=filename,
                                       mode="wb") as fd:
                        fd.write(data)

                        args.append(filename)

                args.append(description)
                renderer.table_row(*args)


class TestCertVadScan(testlib.HashChecker):
    PARAMETERS = dict(
        commandline="cert_vad_scan --proc_regex %(regex)s -D %(tempdir)s ",
        regex="csrss.exe"
        )
