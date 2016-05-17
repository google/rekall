# Rekall Memory Forensics
# Copyright 2015 Google Inc. All Rights Reserved.
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

__author__ = "Andreas Moser <grrrrrrrrr@surfsup.at>"


import re

from rekall import plugin
from rekall import scan
from rekall import testlib


class SignatureScannerCheck(scan.ScannerCheck):
    """A scanner that searches for a signature.

    The signature is given as a list of strings and this scanner checks that
    each part of the signature is present in memory in ascending order.
    """

    def __init__(self, needles=None, **kwargs):
        """Init.

        Args:
          needles: A list of strings we search for.
          **kwargs: passthrough.
        Raises:
          RuntimeError: No needles provided.
        """
        super(SignatureScannerCheck, self).__init__(**kwargs)

        # It is an error to not provide something to search for.
        if not needles:
            raise RuntimeError("No needles provided to search.")

        self.needles = needles
        self.current_needle = 0

    def check(self, buffer_as, offset):
        if self.current_needle >= len(self.needles):
            # We have found all parts already.
            return False

        # Just check the buffer without needing to copy it on slice.
        buffer_offset = buffer_as.get_buffer_offset(offset)
        next_part = self.needles[self.current_needle]
        if buffer_as.data.startswith(next_part, buffer_offset):
            self.current_needle += 1
            return next_part
        else:
            return False

    def skip(self, buffer_as, offset):
        if self.current_needle >= len(self.needles):
            # We have found all parts already, just skip the whole buffer.
            return buffer_as.end() - offset

        # Search the rest of the buffer for the needle.
        buffer_offset = buffer_as.get_buffer_offset(offset)
        next_part = self.needles[self.current_needle]
        correction = 0
        if self.current_needle:
            # If this is not the very first hit we need to increase the offset
            # or we might report identical parts only once.
            correction = len(self.needles[self.current_needle - 1])
        dindex = buffer_as.data.find(next_part, buffer_offset + correction)
        if dindex > -1:
            return dindex - buffer_offset

        # Skip entire region.
        return buffer_as.end() - offset


class SignatureScanner(scan.BaseScanner):

    def __init__(self, needles=None, **kwargs):
        super(SignatureScanner, self).__init__(**kwargs)
        self.needles = needles

        self.check = SignatureScannerCheck(
            profile=self.profile, address_space=self.address_space,
            needles=self.needles)

    def check_addr(self, offset, buffer_as=None):
        # Ask the check if this offset is possible.
        val = self.check.check(buffer_as, offset)
        if val:
            return offset, val

    def skip(self, buffer_as, offset):
        return self.check.skip(buffer_as, offset)

    def scan(self, **kwargs):
        for hit in super(SignatureScanner, self).scan(**kwargs):
            yield hit

            # If a single hit is found, we are done.
            if self.check.current_needle >= len(self.check.needles):
                break


class SigScanMixIn(object):
    """Scan memory for signatures."""

    name = "sigscan"

    @classmethod
    def args(cls, parser):
        super(SigScanMixIn, cls).args(parser)
        parser.add_argument("signature", default=None, nargs="*",
                            help="The signature(s) to scan for. Format is "
                            "000102*0506*AAFF")

        parser.add_argument(
            "--scan_physical", default=False, type="Boolean",
            help="If specified we scan the physcial address space.")

        parser.add_argument(
            "--scan_kernel", default=False, type="Boolean",
            help="If specified we scan the kernel address space.")

    def __init__(self, signature=None, scan_kernel=False, scan_physical=False,
                 **kwargs):
        """Scan using custom signatures."""
        super(SigScanMixIn, self).__init__(**kwargs)
        # If nothing is specified just scan the physical address space.
        if not self.filtering_requested and not scan_kernel:
            scan_physical = True

        if not signature:
            raise plugin.PluginError("No signature given.")
        sig_re = re.compile("^[0-9A-F*]*$")

        if isinstance(signature, basestring):
            signature = [signature]

        self.signatures = []
        for sig in signature:
            sig = sig.upper()
            if not sig_re.match(sig):
                raise plugin.PluginError(
                    "Signature %s has invalid format. Format is eg. "
                    "000102*0506*AAFF" % sig)
            parts = sig.split("*")
            decoded_parts = []
            for p in parts:
                try:
                    decoded_parts.append(p.decode("hex"))
                except TypeError:
                    raise plugin.PluginError(
                        "Signature %s has invalid format." % sig)
            self.signatures.append(decoded_parts)
        self.scan_physical = scan_physical
        self.scan_kernel = scan_kernel

    def render(self, renderer):
        """Render output."""

        if self.scan_physical:
            self.render_physical_scan(renderer)
        if self.scan_kernel:
            self.render_kernel_scan(renderer)
        if self.filtering_requested:
            for task in self.filter_processes():
                self.render_task_scan(renderer, task)

    def generate_hits(self, address_space, end=2**64):
        for sig in self.signatures:
            scanner = SignatureScanner(
                session=self.session, profile=self.profile, needles=sig,
                address_space=address_space)

            results = list(scanner.scan(maxlen=end))
            if len(results) == len(sig):
                yield results

    def _scan(self, renderer, hit_msg, address_space, end=2**64):
        for hit in self.generate_hits(address_space, end=end):
            renderer.format(hit_msg)

            # A hit is a list of pairs (offset, signature part).
            renderer.table_header([("Offset", "offset", "[addrpad]"),
                                   ("Matching part", "part", "")])
            for offset, part in hit:
                renderer.table_row(offset, part.encode("hex"))

    def render_physical_scan(self, renderer):
        """This method scans the physical memory."""
        self.session.logging.debug("sigscanning against physical memory: %s.",
                                   self.physical_address_space)
        return self._scan(renderer, "Hit in physical AS:\n",
                          self.physical_address_space)

    def render_kernel_scan(self, renderer):
        """This method scans the kernel memory."""
        self.session.logging.debug("sigscanning against the kernel.")
        return self._scan(renderer, "Hit in kernel AS:\n",
                          self.kernel_address_space)

    def render_task_scan(self, renderer, task):
        """This method scans the AS of a single task."""
        self.session.logging.debug("sigscanning task %s", task.name)
        return self._scan(
            renderer, "Hit in task %s (%s):\n" % (task.name, task.pid),
            task.get_process_address_space(),
            end=self.session.GetParameter("highest_usermode_address"))


class TestSigScanPhysical(testlib.SimpleTestCase):
    """Runs sigscan against physical memory."""

    PARAMETERS = dict(
        commandline="sigscan --signature %(signature)s --scan_physical",
        signature="")


class TestSigScanKernel(testlib.SimpleTestCase):
    """Runs sigscan against the kernel."""

    PARAMETERS = dict(
        commandline="sigscan --signature %(signature)s --scan_kernel",
        signature="")


class TestSigScanProcess(testlib.SimpleTestCase):
    """Runs sigscan against processes."""

    PARAMETERS = dict(
        commandline=("sigscan --signature %(signature)s "
                     "--proc_regex %(proc_regex)s"),
        signature="",
        proc_regex=".")
