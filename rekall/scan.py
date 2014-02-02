# Rekall Memory Forensics
#
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
#

__author__ = "Michael Cohen <scudette@gmail.com>"

import ahocorasick
import re

from rekall import addrspace
from rekall import registry
from rekall import constants


class BaseScanner(object):
    """ A more thorough scanner which checks every byte """

    __metaclass__ = registry.MetaclassRegistry

    checks = []
    def __init__(self, profile=None, address_space=None, window_size=8,
                 session=None):
        """The base scanner.

        Args:
           profile: The kernel profile to use for this scan.
           address_space: The address space we use for scanning.
           window_size: The size of the overlap window between each buffer read.
        """
        self.address_space = address_space
        self.window_size = window_size
        self.constraints = None
        self.profile = profile or session.profile
        self.max_length = None
        self.base_offset = None
        self.session = session

    def build_constraints(self):
        self.constraints = []
        for class_name, args in self.checks:
            check = ScannerCheck.classes[class_name](
                profile=self.profile, address_space=self.address_space, **args)
            self.constraints.append(check)

        self.skippers = [c for c in self.constraints if hasattr(c, "skip")]
        self.hits = None

    def check_addr(self, offset, buffer_as=None):
        """Calls our constraints on the offset and returns if any contraints did
        not match.

        Args:
           offset: The offset to test (in self.address_space).
        """
        for check in self.constraints:
            # Ask the check if this offset is possible.
            val = check.check(buffer_as, offset)

            # Break out on the first negative hit.
            if not val:
                return False

        return True

    def skip(self, buffer_as, offset):
        """Skip uninteresting regions.

        Where should we go next? By default we go 1 byte ahead, but if some of
        the checkers have skippers, we may actually go much farther. Checkers
        with skippers basically tell us that there is no way they can match
        anything before the skipped result, so there is no point in trying them
        on all the data in between. This optimization is useful to really speed
        things up.
        """
        skip = 1
        for s in self.skippers:
            skip_value = s.skip(buffer_as, offset)
            skip = max(skip, skip_value)

        return skip

    overlap = 1024
    def scan(self, offset=0, maxlen=None):
        """Scan the region from offset for maxlen.

        Args:
          offset: The starting offset in our current address space to scan.

          maxlen: The maximum length to scan. If no provided we just scan until
            there is no data.

        Yields:
          offsets where all the constrainst are satisfied.
        """
        if maxlen is None:
            last_range = list(self.address_space.get_available_addresses())[-1]
            maxlen = last_range[0] + last_range[1]

        # Delay building the constraints so they can be added after scanner
        # construction.
        if self.constraints is None:
            self.build_constraints()

        # Start scanning from offset until maxlen:
        i = offset

        buffer_as = addrspace.BufferAddressSpace()
        while i < offset + maxlen:
            # Update the progress bar.
            if self.session:
                self.session.report_progress(
                    "Scanning 0x%08X with %s" % (i, self.__class__.__name__))

            # Refresh the buffer if current index is too close to the end.
            if i + self.overlap > buffer_as.end():
                # Current region is not valid.
                if not self.address_space.is_valid_address(i):
                    break

                to_read = min(constants.SCAN_BLOCKSIZE, maxlen - (i - offset))

                # Refresh the data buffer.
                buffer_as.assign_buffer(
                    self.address_space.read(i, to_read), base_offset=i)

            # Check the current offset for a match.
            if self.check_addr(i, buffer_as=buffer_as):
                yield i

            # First check if we can skip this point.
            skip = self.skip(buffer_as, i)
            i += skip


class DiscontigScanner(object):
    """A Mixin for Discontiguous scanning."""

    def scan(self, offset=0, maxlen=None):
        maxlen = maxlen or self.profile.get_constant("MaxPointer")

        for (start, length) in self.address_space.get_available_addresses():
            if start < offset:
                continue

            for match in super(DiscontigScanner, self).scan(start, length):
                yield match


class PointerScanner(DiscontigScanner, BaseScanner):
    """Scan for a bunch of pointers at the same time.

    This scanner takes advantage of the fact that usually the most significant
    bytes of a group of pointers is the same. This common part is scanned for
    first, thereby taking advantage of the scanner skippers.
    """
    def __init__(self, pointers=None, **kwargs):
        """Creates the Pointer Scanner.

        Args:
          pointers: A list of Pointer objects, or simply memory addresses. This
            scanner finds direct references to these addresses in memory.
        """
        super(PointerScanner, self).__init__(**kwargs)

        # The size of a pointer depends on the profile.
        self.address_size = self.profile.get_obj_size("address")
        self.needles = []

        # Find the common string between all the addresses.
        for address in pointers:
            # Encode the address as a pointer according to the current profile.
            tmp = self.profile.address()
            tmp.write(address)

            self.needles.append(tmp.obj_vm.read(0, tmp.size()))

        # The common string between all the needles.
        self.common = self.FindCommonString(self.needles)
        self.checks = [
            ('StringCheck', dict(needle=self.common)),
            ]

    def FindCommonString(self, needles):
        """Find the largest common suffix among all the needles.

        Note we assume all the needles are the same size and pointers are little
        endian (so we work from the end of the string to the beginning).
        """
        common = ""
        for i in range(1, self.address_size):
            possible_match = None
            for needle in needles:
                # If this does not match we stop early.
                if possible_match is not None and possible_match != needle[-i]:
                    return common

                possible_match = needle[-i]

            common = possible_match + common

        return common

    def scan(self, **kwargs):
        for hit in super(PointerScanner, self).scan(**kwargs):
            # Correct the hit for the common suffix.
            hit -= self.address_size - len(self.common)
            data = self.address_space.read(hit, self.address_size)

            if data in self.needles:
                yield hit


class ScannerCheck(object):
    """ A scanner check is a special class which is invoked on an AS to check
    for a specific condition.

    The main method is def check(self, offset):
    This will return True if the condition is true or False otherwise.

    This class is the base class for all checks.
    """

    __metaclass__ = registry.MetaclassRegistry
    __abstract = True

    def __init__(self, profile=None, address_space=None, **_kwargs):
        """The profile that this scanner check should use."""
        self.profile = profile
        self.address_space = address_space

    def object_offset(self, offset):
        return offset

    def check(self, buffer_as, offset):
        _ = offset
        _ = buffer_as
        return False

    def skip(self, buffer_as, offset):
        """Determine how many bytes we can skip.

        If you want to speed up the scanning define this method - it
        will be used to skip the data which is obviously not going to
        match. You will need to return the number of bytes from offset
        to skip to. We take the maximum number of bytes to guarantee
        that all checks have a chance of passing.

        Args:
          buffer_as: A BufferAddressSpace instance wrapping self.address_space,
          containing a copy of the data at the specified offset.

          offset: The offset in the address space to check.

        Returns:
          number of bytes to be skipped.
        """
        _ = buffer_as
        _ = offset
        return 0


class MultiStringFinderCheck(ScannerCheck):
    """A scanner checker for multiple strings."""

    def __init__(self, needles=None, **kwargs):
        """
        Args:
          needles: A list of strings we search for.
        """
        super(MultiStringFinderCheck, self).__init__(**kwargs)
        if not needles:
            needles = []

        self.tree = ahocorasick.KeywordTree()

        for needle in needles:
            self.tree.add(needle)

        self.tree.make()
        self.base_offset = None
        self.next_hit = None

    def check(self, buffer_as, offset):
        data_offset = offset - buffer_as.base_offset

        self.next_hit = self.tree.search(buffer_as.data, data_offset)
        if self.next_hit and self.next_hit[0] == data_offset:
            return True

        return False

    def skip(self, buffer_as, offset):
        # Normally the scanner calls the check method first, then the skip
        # method immediately after. We are depending on this order so
        # self.next_hit will be set by the check method which was called
        # before us.
        data_offset = offset - buffer_as.base_offset
        if self.next_hit is None:
            # Eliminate this buffer.
            return buffer_as.end() - offset

        # Go to the next hit.
        return self.next_hit[0] - data_offset


class StringCheck(ScannerCheck):
    maxlen = 100

    def __init__(self, needle=None, **kwargs):
        super(StringCheck, self).__init__(**kwargs)
        self.needle = needle

    def check(self, buffer_as, offset):
        return buffer_as.read(offset, len(self.needle)) == self.needle

    def skip(self, buffer_as, offset):
        data_offset = offset - buffer_as.base_offset

        dindex = buffer_as.data.find(self.needle, data_offset + 1)
        if dindex > -1:
            return dindex - data_offset

        # Skip entire region.
        return buffer_as.end() - offset


class RegexCheck(ScannerCheck):
    """This check can be quite slow."""
    maxlen = 100

    def __init__(self, regex=None, **kwargs):
        super(RegexCheck, self).__init__(**kwargs)
        self.regex = re.compile(regex)

    def check(self, buffer_as, offset):
        verify = buffer_as.read(offset, self.maxlen)
        return bool(self.regex.match(verify))

    def skip(self, buffer_as, offset):
        data_offset = offset - buffer_as.base_offset

        m = self.regex.search(buffer_as.data[data_offset:])
        if m:
            return m.start() + 1

        return buffer_as.end() - offset


class ScannerGroup(BaseScanner):
    """Runs a bunch of scanners in one pass over the image."""

    def __init__(self, scanners=None, **kwargs):
        """Create a new scanner group.

        Args:
          scanners: A dict of BaseScanner instances. Keys will be used to refer
          to the scanner, while the value is the scanner instance.
        """
        super(ScannerGroup, self).__init__(**kwargs)
        self.scanners = scanners
        for scanner in scanners.values():
            scanner.address_space = self.address_space

        # A dict to hold all hits for each scanner.
        self.result = {}

    def scan(self, offset=0, maxlen=None):
        available_length = maxlen or self.profile.get_constant("MaxPointer")

        while available_length > 0:
            to_read = min(constants.SCAN_BLOCKSIZE + self.overlap,
                          available_length)

            # Now feed all the scanners from the same address space.
            for name, scanner in self.scanners.items():
                for hit in scanner.scan(offset=offset, maxlen=to_read):
                    # Yield the result as well as cache it.
                    yield name, hit

            # Move to the next scan block.
            offset += constants.SCAN_BLOCKSIZE
            available_length -= constants.SCAN_BLOCKSIZE


class DiscontigScannerGroup(ScannerGroup):
    """A scanner group which works over a virtual address space."""

    def scan(self, offset=0, maxlen=None):
        maxlen = maxlen or self.profile.get_constant("MaxPointer")

        for (start, length) in self.address_space.get_address_ranges(
            offset, offset + maxlen):
            for match in super(DiscontigScannerGroup, self).scan(
                start, maxlen=length):
                yield match


class DebugChecker(ScannerCheck):
    """A check that breaks into the debugger when a condition is met.

    Insert this check inside the check stack and we will break into the debugger
    when all the conditions below us are met.
    """
    def check(self, buffer_as, offset):
        _ = offset
        _ = buffer_as
        import pdb; pdb.set_trace() # pylint: disable=multiple-statements
        return True
