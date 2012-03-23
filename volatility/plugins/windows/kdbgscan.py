# Volatility
#
# Authors:
# Michael Cohen <scudette@gmail.com>
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
import logging

from volatility import scan
from volatility import plugin
from volatility.plugins.windows import common


class MultiStringFinderCheck(scan.ScannerCheck):
    """A scanner checker for multiple strings."""

    def __init__(self, needles = None, **kwargs):
        """
        Args:
          needles: A list of strings we search for.
        """
        super(MultiStringFinderCheck, self).__init__(**kwargs)
        if not needles:
            needles = []
        self.needles = needles
        self.maxlen = 0
        for needle in needles:
            self.maxlen = max(self.maxlen, len(needle))
        if not self.maxlen:
            raise RuntimeError("No needles of any length were found for the "
                               "MultiStringFinderCheck")

    def check(self, offset):
        verify = self.address_space.read(offset, self.maxlen)
        for match in self.needles:
            if verify[:len(match)] == match:
                return True
        return False

    def skip(self, data, offset):
        nextval = len(data)
        for needle in self.needles:
            dindex = data.find(needle, offset + 1)
            if dindex > -1:
                nextval = min(nextval, dindex)
        return nextval - offset


class KDBGScanner(scan.DiscontigScanner):
    """Scans for _KDDEBUGGER_DATA64 structures.

    Note that this does not rely on signatures, as validity of hits is
    calculated through list reflection.
    """
    checks = [ ("MultiStringFinderCheck", dict(needles=["KDBG"])) ]

    def scan(self, offset = 0, maxlen = None):
        # How far into the struct the OwnerTag is.
        owner_tag_offset = self.profile.get_obj_offset("_DBGKD_DEBUG_DATA_HEADER64",
                                                       "OwnerTag")

        # Depending on the memory model this behaves slightly differently.
        memory_model = self.profile.metadata("memory_model", "32bit")

        # This basical iterates over all hits on the string "KDBG".
        for offset in super(KDBGScanner, self).scan(offset, maxlen):
            # For each hit we overlay a _DBGKD_DEBUG_DATA_HEADER64 on it and
            # reflect through the "List" member.
            result = self.profile.Object("_KDDEBUGGER_DATA64",
                                         offset=offset - owner_tag_offset,
                                         vm=self.address_space)

            # We verify this hit by reflecting through its header list.
            list_entry = result.Header.List

            # On 32 bit systems the Header.List member seems to actually be a
            # LIST_ENTRY32 instead of a LIST_ENTRY64, but it is still padded to
            # take the same space:
            if memory_model == "32bit":
                list_entry = list_entry.cast("LIST_ENTRY32")

            if list_entry.reflect():
                yield result
            elif list_entry.Flink == list_entry.Blink and not list_entry.Flink.dereference():
                logging.debug("KDBG list_head is not mapped, assuming its valid.")
                yield result


class KDBGScan(plugin.KernelASMixin, common.AbstractWindowsCommandPlugin):
    """A scanner for the kdbg structures."""

    __name = "kdbgscan"

    def __init__(self, **kwargs):
        """Scan for possible _KDDEBUGGER_DATA64 structures.

        The scanner is detailed here:
        http://moyix.blogspot.com/2008/04/finding-kernel-global-variables-in.html

        The relevant structures are detailed here:
        http://doxygen.reactos.org/d3/ddf/include_2psdk_2wdbgexts_8h_source.html

        We can see that _KDDEBUGGER_DATA64.Header is:

        typedef struct _DBGKD_DEBUG_DATA_HEADER64 {
            LIST_ENTRY64    List;
            ULONG           OwnerTag;
            ULONG           Size;
        }

        We essentially search for an owner tag of "KDBG", then overlay the
        _KDDEBUGGER_DATA64 struct on it. We test for validity by reflecting
        through the Header.List member.
        """
        super(KDBGScan, self).__init__(**kwargs)

    def hits(self):
        scanner = scan.BaseScanner.classes['KDBGScanner'](
            profile=self.profile, address_space=self.kernel_address_space)

        # Yield actual objects here
        for kdbg in scanner.scan():
            yield kdbg

    def render(self, fd=None):
        fd.write("Potential hits for kdbg strctures.\n")

        fd.write("  Offset (V)         Offset (P)\n"
                 "----------------  ----------------\n")

        for hit in self.hits():
            offset = hit.obj_offset
            fd.write("{0:#016x}   {1:#016x}\n".format(
                    offset, hit.obj_vm.vtop(offset)))
