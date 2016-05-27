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

import acora
import re

from rekall import addrspace
from rekall import constants
from rekall import registry


class ScannerCheck(object):
    """A scanner check is a special class which is invoked on an AS to check
    for a specific condition.

    The main method is def check(self, buffer_as, offset):
    This will return True if the condition is true or False otherwise.

    This class is the base class for all checks.
    """

    __metaclass__ = registry.MetaclassRegistry
    __abstract = True

    def __init__(self, profile=None, address_space=None, session=None,
                 **_kwargs):
        # The profile that this scanner check should use.
        self.profile = profile
        self.address_space = address_space
        self.session = session

    def object_offset(self, offset):
        return offset

    def check(self, buffer_as, offset):
        """Is the needle found at 'offset'?

        Arguments:
          buffer_as: An address space object with a chunk of data that can be
            checked for the needle.
        offset: The offset in the address space to check.
        """
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
          Number of bytes to be skipped.
        """
        _ = buffer_as
        _ = offset
        return 0


class MultiStringFinderCheck(ScannerCheck):
    """A scanner checker for multiple strings."""

    def __init__(self, needles=None, **kwargs):
        """Init.

        Args:
          needles: A list of strings we search for.
          **kwargs: passthrough.
        Raises:
          RuntimeError: No needles provided.
        """
        super(MultiStringFinderCheck, self).__init__(**kwargs)

        # It is an error to not provide something to search for and Acora will
        # raise later.
        if not needles:
            raise RuntimeError("No needles provided to search.")

        # Passing large patterns to the acora module will cause huge memory
        # consumption.
        if max([len(x) for x in needles]) > 50:
            raise RuntimeError("Pattern too large to search with ahocorasic.")

        tree = acora.AcoraBuilder(*needles)
        self.engine = tree.build()

        self.base_offset = None
        self.hits = None

    def check(self, buffer_as, offset):
        # This indicates we haven't already generated hits for this buffer.
        if buffer_as.base_offset != self.base_offset:
            self.hits = sorted(self.engine.findall(buffer_as.data),
                               key=lambda x: x[1], reverse=True)
            self.base_offset = buffer_as.base_offset

        data_offset = offset - buffer_as.base_offset
        while self.hits:
            string, offset = self.hits[-1]
            if offset == data_offset:
                # This hit was reported, remove it.
                self.hits.pop()
                return string
            elif offset < data_offset:
                # We skipped over this hit, remove it and check for the
                # remaining hits.
                self.hits.pop()
            else:  # offset > data_offset
                return False
        return False

    def skip(self, buffer_as, offset):
        # Normally the scanner calls the check method first, then the skip
        # method immediately after. We are depending on this order so self.hits
        # will be set by the check method which was called before us.
        # This method also assumes that the offsets to skip/check will be
        # nondecreasing.

        data_offset = offset - buffer_as.base_offset
        while self.hits:
            _, offset = self.hits[-1]
            if offset < data_offset:
                self.hits.pop()
            else:
                return offset - data_offset

        # No more hits in this buffer, skip it.
        return buffer_as.end() - offset


class StringCheck(ScannerCheck):
    """Checks for a single string."""
    maxlen = 100
    needle = None
    needle_offset = None

    def __init__(self, needle=None, needle_offset=0, **kwargs):
        super(StringCheck, self).__init__(**kwargs)
        self.needle = needle
        self.needle_offset = needle_offset

    def check(self, buffer_as, offset):
        # Just check the buffer without needing to copy it on slice.
        buffer_offset = buffer_as.get_buffer_offset(offset) + self.needle_offset
        if buffer_as.data.startswith(self.needle, buffer_offset):
            return self.needle

    def skip(self, buffer_as, offset):
        # Search the rest of the buffer for the needle.
        buffer_offset = buffer_as.get_buffer_offset(offset) + self.needle_offset
        dindex = buffer_as.data.find(self.needle, buffer_offset + 1)
        if dindex > -1:
            return dindex - buffer_offset

        # Skip entire region.
        return buffer_as.end() - offset


class RegexCheck(ScannerCheck):
    """This check can be quite slow."""
    maxlen = 100

    def __init__(self, regex=None, **kwargs):
        super(RegexCheck, self).__init__(**kwargs)
        self.regex = re.compile(regex)

    def check(self, buffer_as, offset):
        m = self.regex.match(
            buffer_as.data, buffer_as.get_buffer_offset(offset))

        return bool(m)


class BaseScanner(object):
    """A more thorough scanner which checks every byte."""

    __metaclass__ = registry.MetaclassRegistry

    progress_message = "Scanning 0x%(offset)08X with %(name)s"

    checks = ()

    def __init__(self, profile=None, address_space=None, window_size=8,
                 session=None, checks=None):
        """The base scanner.

        Args:
           profile: The kernel profile to use for this scan.
           address_space: The address space we use for scanning.
           window_size: The size of the overlap window between each buffer read.
        """
        self.session = session or address_space.session
        self.address_space = address_space or self.session.default_address_space
        self.window_size = window_size
        self.constraints = None
        if profile is None and self.session.HasParameter("profile"):
            profile = self.session.profile

        self.profile = profile
        self.max_length = None
        self.base_offset = None
        self.scan_buffer_offset = None
        self.buffer_as = addrspace.BufferAddressSpace(session=self.session)
        if checks is not None:
            self.checks = checks

    def build_constraints(self):
        self.constraints = []
        for class_name, args in self.checks:
            check = ScannerCheck.classes[class_name](
                profile=self.profile, address_space=self.address_space,
                session=self.session, **args)
            self.constraints.append(check)

        self.skippers = [c for c in self.constraints if hasattr(c, "skip")]
        self.hits = None

    def check_addr(self, offset, buffer_as=None):
        """Check an address.

        This calls our constraints on the offset and returns if any contraints
        did not match.

        Args:
           offset: The offset to test (in self.address_space).

        Returns:
           None if the offset is not a hit, the hit if the hit is correct.
        """
        for check in self.constraints:
            # Ask the check if this offset is possible.
            val = check.check(buffer_as, offset)

            # Break out on the first negative hit.
            if not val:
                return

        return offset

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

          maxlen: The maximum length to scan. If not provided we just scan until
            there is no data.

        Yields:
          offsets where all the constrainst are satisfied.
        """
        if maxlen is None:
            maxlen = 2**64

        end = int(offset) + int(maxlen)
        overlap = ""

        # Record the last reported hit to prevent multiple reporting of the same
        # hits when using an overlap.
        last_reported_hit = -1

        # Delay building the constraints so they can be added after scanner
        # construction.
        if self.constraints is None:
            self.build_constraints()

        # We try to optimize the scanning by first merging contiguous ranges
        # and then passing up to constants.SCAN_BLOCKSIZE bytes to the checkers
        # and skippers.
        #
        # If range has less data than the block size, then the full range is
        # scanned at once.
        #
        # If a range is larger than the block size, it's split in chunks until
        # it's fully consumed. Overlap is applied only in this case, starting
        # from the second chunk.
        chunk_end = 0

        for run in self.address_space.merge_base_ranges(start=offset, end=end):
            # Store where this chunk will start. Absolute offset.
            chunk_offset = run.start
            buffer_as = addrspace.BufferAddressSpace(session=self.session)

            # Keep scanning this range as long as the current chunk isn't
            # past the end of the range or the end of the scanner.
            while chunk_offset < run.end:
                if self.session:
                    self.session.report_progress(
                        self.progress_message % dict(
                            offset=chunk_offset,
                            name=self.__class__.__name__))

                # This chunk does not begin where the last chunk ended - this
                # means there is a gap in the virtual address space and
                # therefore we should not use any overlap.
                if chunk_offset != chunk_end:
                    overlap = ""

                # Our chunk is SCAN_BLOCKSIZE long or as much data there's
                # left in the range.
                chunk_size = min(constants.SCAN_BLOCKSIZE,
                                 run.end - chunk_offset)

                chunk_end = chunk_offset + chunk_size

                # Consume the next block in this range. We read directly from
                # the physical address space to save an extra translation by the
                # virtual address space's read() method.
                phys_chunk_offset = run.file_offset + (chunk_offset - run.start)

                buffer_as.assign_buffer(
                    overlap + run.address_space.read(
                        phys_chunk_offset, chunk_size),
                    base_offset=chunk_offset - len(overlap))

                if self.overlap > 0:
                    overlap = buffer_as.data[-self.overlap:]

                scan_offset = buffer_as.base_offset
                while scan_offset < buffer_as.end():
                    # Check the current offset for a match.
                    res = self.check_addr(scan_offset, buffer_as=buffer_as)

                    # Remove multiple matches in the overlap region which we
                    # have previously reported.
                    if res is not None and scan_offset > last_reported_hit:
                        last_reported_hit = scan_offset
                        yield res

                    # Skip as much data as the skippers tell us to, up to the
                    # end of the buffer.
                    scan_offset += min(len(buffer_as),
                                       self.skip(buffer_as, scan_offset))

                chunk_offset = scan_offset


class FastStructScanner(BaseScanner):
    """This scanner looks for a struct in memory.

    Arguments:
        expected_values:
            Provide a list/tuple of dicts mapping member names to their
            expected values. Each dict in the list you provide will correspond
            to a struct at the same index in an array. If you're only looking
            for a single struct, pass a list with only one dict in it.
        type_name: Name of the type to scan for.
    """

    type_name = None
    prototype = None
    expected_values = None

    def __init__(self, type_name=None, expected_values=None, *args, **kwargs):
        super(FastStructScanner, self).__init__(*args, **kwargs)
        self.type_name = type_name
        self.expected_values = expected_values
        self.prototype = self.profile.Object(
            type_name=type_name, vm=addrspace.BufferAddressSpace(
                session=self.session,
                data="\x00" * self.profile.get_obj_size(type_name)))

        if not self.checks:
            self.checks = []
        elif isinstance(self.checks, tuple):
            # We need the checks array to be mutable.
            self.checks = list(self.checks)

        for array_idx, struct_members in enumerate(self.expected_values):
            self.checks.extend(self.build_checks(array_idx, struct_members))

    def build_checks(self, array_idx, struct_members):
        array_offset = array_idx * self.prototype.obj_size
        for member, expected_value in struct_members.iteritems():
            self.prototype.SetMember(member, expected_value)
            member_obj = self.prototype.m(member)
            expected_bytes = member_obj.GetData()
            rel_offset = member_obj.obj_offset
            yield ("StringCheck", dict(needle=expected_bytes,
                                       needle_offset=rel_offset + array_offset))


class MultiStringScanner(BaseScanner):
    """A scanner for multiple strings at once."""

    # Override with the needles to check for.
    needles = []

    def __init__(self, needles=None, **kwargs):
        super(MultiStringScanner, self).__init__(**kwargs)
        if needles is not None:
            self.needles = needles

        # For large patterns acora seems to use huge amount of memory and
        # CPU. Therefore when there is only a single pattern (common case) use
        # the normal StringScanner instead.
        if len(needles) == 1:
            self.check = StringCheck(
                profile=self.profile, address_space=self.address_space,
                needle=self.needles[0])
        else:
            self.check = MultiStringFinderCheck(
                profile=self.profile, address_space=self.address_space,
                needles=self.needles)

    def check_addr(self, offset, buffer_as=None):
        # Ask the check if this offset is possible.
        val = self.check.check(buffer_as, offset)
        if val:
            return offset, val

    def skip(self, buffer_as, offset):
        return self.check.skip(buffer_as, offset)


class PointerScanner(BaseScanner):
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
        self.address_size = self.session.profile.get_obj_size("address")
        self.needles = []

        # Find the common string between all the addresses.
        for address in pointers:
            # Encode the address as a pointer according to the current profile.
            tmp = self.session.profile.address()
            tmp.write(address)

            self.needles.append(tmp.obj_vm.read(0, tmp.obj_size))

        # The common string between all the needles.
        self.checks = [
            ("MultiStringFinderCheck", dict(needles=self.needles)),
            ]


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
        available_length = maxlen or self.session.profile.get_constant(
            "MaxPointer")

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
        maxlen = maxlen or self.session.profile.get_constant("MaxPointer")

        for (start, _, length) in self.address_space.get_address_ranges(
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
