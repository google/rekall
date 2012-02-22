# Volatility
#
# Authors:
# Michael Cohen <scudette@users.sourceforge.net>
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

""" This plugin contains CORE classes used by lots of other plugins """
import volatility.scan as scan
import volatility.obj as obj
import volatility.debug as debug #pylint: disable-msg=W0611
from volatility import commands
from volatility import profile
from volatility import plugin

#pylint: disable-msg=C0111

# We require both a physical AS set and a valid profile for
# AbstractWindowsCommandPlugins.

class AbstractWindowsCommandPlugin(plugin.PhysicalASMixin,
                                   plugin.ProfileCommand):
    """A base class for all windows based plugins.

    Windows based plugins require at a minimum a working profile, and a valid
    physical address space.
    """

    __abstract = True

    @classmethod
    def is_active(cls, config):
        """We are only active if the profile is windows."""
        return (getattr(config.profile, "_md_os", None) == 'windows' and
                plugin.Command.is_active(config))


# TODO: remove this when all the plugins have been switched over..
class AbstractWindowsCommand(commands.command):
    """A base class for all windows based plugins."""

    @classmethod
    def is_active(cls, config):
        """We are only active if the profile is windows."""
        return (getattr(config.profile, "_md_os", None) == 'windows' and
                plugin.Command.is_active(config))


class WinFindDTB(AbstractWindowsCommandPlugin):
    """A plugin to search for the Directory Table Base for windows systems.

    There are a number of ways to find the DTB:

    - Scanner method: Scans the image for a known kernel process, and read the
      DTB from its Process Environment Block (PEB).

    - Get the DTB from the KPCR structure.
    """

    __name = "find_dtb"

    # We scan this many bytes at once
    SCAN_BLOCKSIZE = 1024 * 1024

    def __init__(self, process_name = "Idle", physical_address_space = None,
                 profile = None, **kwargs):
        """Scans the image for the Idle process.

        Args:
          process_name: The name of the process we should look for. (If we are
            looking for the kernel DTB, any kernel process will do here.)

          physical_address_space: The address space to search. If None, we use
            the session's physical_address_space.

          profile: An optional profile to use (or we use the session's).
        """
        super(WinFindDTB, self).__init__(**kwargs)

        self.process_name = process_name

        # This is the offset from the ImageFileName member to the start of the
        # _EPROCESS
        self.image_name_offset = self.profile.get_obj_offset(
            "_EPROCESS", "ImageFileName")

    def generate_suggestions(self):
        needle = self.process_name + "\x00" * (16 - len(self.process_name))
        offset = 0
        while 1:
            data = self.physical_address_space.read(offset, self.SCAN_BLOCKSIZE)
            found = 0
            if not data:
                break

            while 1:
                found = data.find(needle, found + 1)
                if found >= 0:
                    # We found something that looks like the process we want.
                    eprocess = self.profile.Object(
                        "_EPROCESS", offset = offset + found - self.image_name_offset,
                        vm = self.physical_address_space)

                    if self._check_dtb(eprocess):
                        yield eprocess

                else:
                    break

            offset += len(data)

    def dtb_hits(self):
        for x in self.generate_suggestions():
            yield x.Pcb.DirectoryTableBase.v()

    def _check_dtb(self, eprocess):
        """Check the eprocess for sanity."""
        return True

    def render(self, fd = None):
        fd.write("_EPROCESS (P)   DTB\n")
        for eprocess in self.generate_suggestions():
            dtb = eprocess.Pcb.DirectoryTableBase.v()
                    
            fd.write("{0:#010x}  {1:#010x}\n".format(eprocess.obj_offset, dtb))





## The following are checks for pool scanners.

class PoolTagCheck(scan.ScannerCheck):
    """ This scanner checks for the occurance of a pool tag """
    def __init__(self, address_space, tag = None, **kwargs):
        scan.ScannerCheck.__init__(self, address_space, **kwargs)
        self.tag = tag

    def skip(self, data, offset):
        try:
            nextval = data.index(self.tag, offset + 1)
            return nextval - offset
        except ValueError:
            ## Substring is not found - skip to the end of this data buffer
            return len(data) - offset

    def check(self, offset):
        data = self.address_space.read(offset, len(self.tag))
        return data == self.tag

class CheckPoolSize(scan.ScannerCheck):
    """ Check pool block size """
    def __init__(self, address_space, condition = (lambda x: x == 8), **kwargs):
        scan.ScannerCheck.__init__(self, address_space, **kwargs)
        self.condition = condition

    def check(self, offset):
        pool_hdr = obj.Object('_POOL_HEADER', vm = self.address_space,
                             offset = offset - 4)

        block_size = pool_hdr.BlockSize.v()
        pool_align = obj.VolMagic(self.address_space).PoolAlignment.v()

        return self.condition(block_size * pool_align)

class CheckPoolType(scan.ScannerCheck):
    """ Check the pool type """
    def __init__(self, address_space, paged = False,
                 non_paged = False, free = False, **kwargs):
        scan.ScannerCheck.__init__(self, address_space, **kwargs)
        self.non_paged = non_paged
        self.paged = paged
        self.free = free

    def check(self, offset):
        pool_hdr = obj.Object('_POOL_HEADER', vm = self.address_space,
                             offset = offset - 4)

        ptype = pool_hdr.PoolType.v()

        if self.non_paged and (ptype % 2) == 1:
            return True

        if self.free and ptype == 0:
            return True

        if self.paged and (ptype % 2) == 0 and ptype > 0:
            return True

class CheckPoolIndex(scan.ScannerCheck):
    """ Checks the pool index """
    def __init__(self, address_space, value = 0, **kwargs):
        scan.ScannerCheck.__init__(self, address_space, **kwargs)
        self.value = value

    def check(self, offset):
        pool_hdr = obj.Object('_POOL_HEADER', vm = self.address_space,
                             offset = offset - 4)

        return pool_hdr.PoolIndex == self.value


class KDBGScan(AbstractWindowsCommandPlugin):
    """A scanner for the kdbg structures."""

    __name = "kdbgscan"

    def __init__(self, profile=None, physical_address_space=None, 
                 signatures=None, **kwargs):
        super(KDBGScan, self).__init__(**kwargs)

        self.physical_address_space = (physical_address_space or
                                       self.session.physical_address_space)

        if self.physical_address_space is None:
            raise plugin.PluginError("physical address space must be provided.")

        self.signatures = signatures

        # Use the signature from the profile
        if self.signatures is None:
            self.profile = profile or self.session.profile
            if self.profile is None:
                raise plugin.PluginError("Profile or signatures must be provided.")

            self.signatures = [self.profile.constants['KDBGHeader']]

    def hits(self):
        scanner = scan.BaseScanner.classes['KDBGScanner'](
            needles = self.signatures)

        for offset in scanner.scan(self.physical_address_space):
            yield offset


    def render(self, fd=None):
        fd.write("Potential hits for kdbg strctures.")

        fd.write("Offset (P)\n")
        for hit in self.hits():
            fd.write("{0:#010x}\n".format(hit))


class WinProcessFilter(plugin.KernelASMixin, AbstractWindowsCommandPlugin):
    """A class for filtering processes."""

    __abstract = True

    def __init__(self, phys_eprocess=None, pids=None, **kwargs):
        """Lists information about all the dlls mapped by a process.
        
        Args:
           physical_eprocess: One or more EPROCESS structs or offsets defined in
              the physical AS.
           
           pids: A list of pids.

        Returns:
           A List of _EPROCESS objects cast in the kernel AS.
        """
        super(WinProcessFilter, self).__init__(**kwargs)

        if isinstance(phys_eprocess, int):
            phys_eprocess = [phys_eprocess]
        elif phys_eprocess is None:
            phys_eprocess = []

        self.phys_eprocess = phys_eprocess

        if isinstance(pids, int):
            pids = [pids]
        elif pids is None:
            pids = []

        self.pids = pids

    def filter_processes(self):
        """Filters eprocess list using phys_eprocess and pids lists."""
        # No filtering required:
        if not self.phys_eprocess and not self.pids:
            for eprocess in self.session.plugins.pslist(
                session=self.session).list_eprocess():
                yield eprocess
        else:
            # We need to filter by phys_eprocess
            for offset in self.phys_eprocess:
                yield self.virtual_process_from_physical_offset(offset)

            # We need to filter by pids
            for eprocess in self.session.plugins.pslist(
                session=self.session).list_eprocess():
                if int(eprocess.UniqueProcessId) in self.pids:
                    yield eprocess

    def virtual_process_from_physical_offset(self, physical_offset):
        """Tries to return an eprocess in virtual space from a physical offset.

        We do this by reflecting off the list elements.

        Args:
           physical_offset: The physcial offset of the process.

        Returns:
           an _EPROCESS object or a NoneObject on failure.
        """
        physical_eprocess = self.profile.Object(
            theType="_EPROCESS", offset=int(physical_offset),
            vm=self.kernel_address_space.base)

        # We cast our list entry in the kernel AS by following Flink into the
        # kernel AS and then the Blink. Note the address space switch upon
        # dereferencing the pointer.
        our_list_entry = physical_eprocess.ActiveProcessLinks.Flink.dereference(
            vm=self.kernel_address_space).Blink.dereference()

        # Now we get the EPROCESS object from the list entry.
        return our_list_entry.dereference_as("_EPROCESS", "ActiveProcessLinks")


