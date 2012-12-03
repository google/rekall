# Volatility
# Copyright (C) 2012 Michael Cohen
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

"""This module guesses the current profile using various heuristics."""

__author__ = "Michael Cohen <scudette@gmail.com>"

import logging

from volatility import addrspace

from volatility import plugin
from volatility import obj
from volatility import scan

from volatility.plugins.addrspaces import amd64
from volatility.plugins.addrspaces import intel
from volatility.plugins.overlays import basic
from volatility.plugins.overlays.windows import windows


# The idea is to avoid importing all the plugins at once just to check a couple
# of offsets, so we just use an abbridged version of the full profiles.


class IdleScanner(scan.BaseScanner):
    def __init__(self, process_names=None, **kwargs):
        super(IdleScanner, self).__init__(**kwargs)
        self.checks = [('MultiStringFinderCheck', dict(
                    needles=process_names))]


class TestProfile32(basic.Profile32Bits, basic.BasicWindowsClasses):
    def __init__(self, **kwargs):
        super(TestProfile32, self).__init__(**kwargs)
        self.add_overlay(eprocess_vtypes)


class TestProfile64(basic.Profile64Bits, basic.BasicWindowsClasses):
    def __init__(self, **kwargs):
        super(TestProfile64, self).__init__(**kwargs)
        self.add_overlay(eprocess_vtypes)


class GuessProfile(plugin.PhysicalASMixin, plugin.Command):
    """Guess the exact windows profile using heuristics."""

    __name = "guess_profile"

    DEFAULT_PROCESS_NAMES = ['System']

    def __init__(self, process_names=None, quick=True, **kwargs):
        """Guess the potential windows profiles which could be used.

        Args:
          process_names: A list of process names to search for - default System.

          quick: If set we just update the session profile and quit after the
            first result is found.
        """
        super(GuessProfile, self).__init__(**kwargs)
        self.process_names = process_names or self.DEFAULT_PROCESS_NAMES
        self.process_names = [
            x + "\x00" * (15 - len(x)) for x in self.process_names]

        self.quick = quick

    def guess_profile_from_kdbg(self, kdbg):
        """Guess the profile from the PsActiveProcessList pointer.

        Sometimes we can arrive at a dtb and even a kdbg without needing to know
        the profile at all (e.g. if thes were provided on the commandline or are
        known in advance from the image). In this case, it is not necessary to
        scan the image for the System process since we have a valid
        PsActiveProcessList. The following algorithm guesses the profile from
        the PsActiveProcessHead and it much faster.

        We assume a valid physical_address_space is already known here.

        Args:
          kdbg: A valid _KDDEBUGGER_DATA64 offset.
        """
        kdbg_profile = windows.KDDebuggerProfile()
        lookup_map = self._build_lookup_map()

        # First try to get a valid kernel address space. At this point we dont
        # even know if its a 32 bit or 64 bit profile so we try both address
        # spaces.
        for address_space_cls in [intel.IA32PagedMemoryPae,
                                  amd64.AMD64PagedMemory]:
            try:
                kernel_as = address_space_cls(
                    base=self.session.physical_address_space,
                    session=self.session)

                kdbg = kdbg_profile._KDDEBUGGER_DATA64(
                    offset=self.session.kdbg, vm=kernel_as)

                if not kdbg: continue

                # Now try to see which profile fits the _EPROCESS best.
                for name, (test_profile, cls) in lookup_map.items():
                    active_process_list_offset = test_profile.get_obj_offset(
                        name, "ActiveProcessLinks")

                    # This is the first _EPROCESS linked from PsActiveProcessList.
                    eprocess = test_profile.Object(
                        name, vm=kernel_as,
                        offset=(kdbg.PsActiveProcessHead.Flink.v() -
                                active_process_list_offset))

                    if (eprocess.UniqueProcessId == 0 or
                        eprocess.UniqueProcessId > 10):
                        continue

                    dtb = eprocess.DirectoryTableBase.v()

                    # The first process should be the System process.
                    address_space = self.verify_profile(cls, eprocess, dtb)
                    if address_space:
                        yield cls(session=self.session), kernel_as, eprocess

            except addrspace.ASAssertionError:
                pass

    def _build_lookup_map(self):
        test_profile32 = TestProfile32()
        test_profile64 = TestProfile64()

        # Precalculate the offsets to save time later.
        lookup_map = {}
        for name, cls in obj.Profile.classes.items():
            if cls.metadata("os") == "windows":
                if cls.metadata("memory_model") == "64bit":
                    test_profile = test_profile64
                else:
                    test_profile = test_profile32

                lookup_map[name] = (test_profile, cls)

        return lookup_map

    def guess_profile(self):
        """Guess using the Idle process technique."""
        # First ensure there is an address space
        if not self.session.physical_address_space:
            return

        scanner = IdleScanner(session=self.session,
                              process_names=self.process_names,
                              address_space=self.session.physical_address_space)

        lookup_map = self._build_lookup_map()
        logging.info("Searching for suitable System Process")
        for hit in scanner.scan():
            # Try every profile until one works.
            for name, (test_profile, cls) in lookup_map.items():
                try:
                    eprocess_offset = test_profile.get_obj_offset(
                        name, 'ImageFileName')
                except AttributeError:
                    logging.warning("Missing definition for profile %s", name)
                    continue

                eprocess = test_profile.Object(
                    name, vm=self.session.physical_address_space,
                    offset=hit - eprocess_offset)

                if eprocess.UniqueProcessId == 0 or eprocess.UniqueProcessId > 10:
                    continue

                dtb = eprocess.DirectoryTableBase.v()

                address_space = self.verify_profile(cls, eprocess, dtb)
                if address_space:
                    yield cls(session=self.session), address_space, eprocess

    def verify_address_space(self, profile_cls, eprocess, address_space):
        """Check the eprocess for sanity."""
        # In windows the DTB must be page aligned, except for PAE images where
        # its aligned to a 0x20 size.
        if not profile_cls.metadata("pae") and address_space.dtb & 0xFFF != 0:
            return False

        if profile_cls.metadata("pae") and address_space.dtb & 0xF != 0:
            return False

        # Reflect through the address space at ourselves.
        list_head = eprocess.ThreadListHead.Flink
        if list_head == 0:
            return False

        me = list_head.dereference(vm=address_space).Blink.Flink
        if me.v() != list_head.v():
            return False

        return True

    def verify_profile(self, profile_cls, eprocess, dtb):
        """Verify potential profiles against the dtb hit."""
        # Make an address space to test the dtb
        try:
            if profile_cls.metadata("memory_model") == "64bit":
                virtual_as = amd64.AMD64PagedMemory(
                    session=self.session,
                    base=self.session.physical_address_space,
                    dtb=dtb)
            elif profile_cls.metadata("pae"):
                virtual_as = intel.IA32PagedMemoryPae(
                    session=self.session,
                    base=self.session.physical_address_space,
                    dtb=dtb)
            else:
                virtual_as = intel.IA32PagedMemory(
                    session=self.session,
                    base=self.session.physical_address_space,
                    dtb=dtb)

        except addrspace.Error:
            return

        # Do some basic checks of the address space.
        if not self.verify_address_space(profile_cls, eprocess, virtual_as):
            return

        return virtual_as

    def update_session(self):
        """Try to update the session from the profile guess."""
        logging.info("Examining image for possible profiles.")

        # If we have a kdbg and a valid kernel address space we can try a faster
        # approach:
        if self.session.kdbg and self.session.dtb:
            for profile, virtual_as, eprocess in self.guess_profile_from_kdbg(
                self.session.kdbg):
                self.session.profile = profile
                self.session.kernel_address_space = virtual_as
                self.session.default_address_space = virtual_as
                logging.info("Autoselected profile %s", profile.__class__.__name__)

                return True

        for profile, virtual_as, eprocess in self.guess_profile():
            self.session.profile = profile
            self.session.kernel_address_space = virtual_as
            self.session.default_address_space = virtual_as
            self.session.dtb = virtual_as.dtb

            # Try to set the correct _EPROCESS here.
            self.session.system_eprocess = profile._EPROCESS(
                vm=self.session.physical_address_space,
                offset=eprocess.obj_offset)

            logging.info("Autoselected profile %s", profile.__class__.__name__)

            return True

        logging.error("Can not autodetect profile - please set it "
                      "explicitely.")

    def render(self, renderer):
        if self.quick:
            renderer.format("Updating session profile and address spaces.\n")
            self.update_session()
            return

        renderer.table_header([("Potential Profile", "profile", "<30"),
                               ("Address Space", "as", "")])

        for profile, virtual_as, _ in self.guess_profile():
            renderer.table_row(profile.__class__.__name__,
                               virtual_as.name)


def generate_idle_lookup_list():
    """Generate the lookup table for _EPROCESS by loading all profiles."""
    eprocess_vtype = {}

    for name, cls in obj.Profile.classes.items():
        # Only care about the OS profiles.
        if cls.metadata("os") == "windows":
            kernel_profile = cls()
            eprocess = kernel_profile._EPROCESS(offset=0)

            list_entry = 'LIST_ENTRY32'
            if cls.metadata("memory_model") == "64bit":
                list_entry = 'LIST_ENTRY64'

            # For the idle method we want to know only the following members:
            eprocess_vtype[name] = [0, {
                    "ImageFileName": [eprocess.ImageFileName.obj_offset, [
                            'String', dict(length=16)]],
                    "ThreadListHead": [eprocess.ThreadListHead.obj_offset, [list_entry]],
                    "ActiveProcessLinks": [eprocess.ActiveProcessLinks.obj_offset, [list_entry]],
                    "UniqueProcessId": [eprocess.UniqueProcessId.obj_offset, ['unsigned int']],
                    "DirectoryTableBase": [
                        eprocess.Pcb.DirectoryTableBase.obj_offset, ["unsigned long"]],
                    }]

    return eprocess_vtype

# The following is generated from generate_idle_lookup_list() above.
eprocess_vtypes = {
  'VistaSP1x64': [0,
  {'ActiveProcessLinks': [232, ['LIST_ENTRY64']],
   'DirectoryTableBase': [40, ['unsigned long']],
   'ImageFileName': [568, ['String', {'length': 16}]],
   'ThreadListHead': [608, ['LIST_ENTRY64']],
   'UniqueProcessId': [224, ['unsigned int']]}],
 'VistaSP1x86': [0,
  {'ActiveProcessLinks': [160, ['LIST_ENTRY32']],
   'DirectoryTableBase': [24, ['unsigned long']],
   'ImageFileName': [332, ['String', {'length': 16}]],
   'ThreadListHead': [360, ['LIST_ENTRY32']],
   'UniqueProcessId': [156, ['unsigned int']]}],
 'VistaSP1x86PAE': [0,
  {'ActiveProcessLinks': [160, ['LIST_ENTRY32']],
   'DirectoryTableBase': [24, ['unsigned long']],
   'ImageFileName': [332, ['String', {'length': 16}]],
   'ThreadListHead': [360, ['LIST_ENTRY32']],
   'UniqueProcessId': [156, ['unsigned int']]}],
 'VistaSP2x64': [0,
  {'ActiveProcessLinks': [232, ['LIST_ENTRY64']],
   'DirectoryTableBase': [40, ['unsigned long']],
   'ImageFileName': [568, ['String', {'length': 16}]],
   'ThreadListHead': [608, ['LIST_ENTRY64']],
   'UniqueProcessId': [224, ['unsigned int']]}],
 'VistaSP2x86': [0,
  {'ActiveProcessLinks': [160, ['LIST_ENTRY32']],
   'DirectoryTableBase': [24, ['unsigned long']],
   'ImageFileName': [332, ['String', {'length': 16}]],
   'ThreadListHead': [360, ['LIST_ENTRY32']],
   'UniqueProcessId': [156, ['unsigned int']]}],
 'Win2008R2SP0x64': [0,
  {'ActiveProcessLinks': [392, ['LIST_ENTRY64']],
   'DirectoryTableBase': [40, ['unsigned long']],
   'ImageFileName': [736, ['String', {'length': 16}]],
   'ThreadListHead': [776, ['LIST_ENTRY64']],
   'UniqueProcessId': [384, ['unsigned int']]}],
 'Win2008R2SP1x64': [0,
  {'ActiveProcessLinks': [392, ['LIST_ENTRY64']],
   'DirectoryTableBase': [40, ['unsigned long']],
   'ImageFileName': [736, ['String', {'length': 16}]],
   'ThreadListHead': [776, ['LIST_ENTRY64']],
   'UniqueProcessId': [384, ['unsigned int']]}],
 'Win2008SP1x64': [0,
  {'ActiveProcessLinks': [232, ['LIST_ENTRY64']],
   'DirectoryTableBase': [40, ['unsigned long']],
   'ImageFileName': [568, ['String', {'length': 16}]],
   'ThreadListHead': [608, ['LIST_ENTRY64']],
   'UniqueProcessId': [224, ['unsigned int']]}],
 'Win2008SP1x86': [0,
  {'ActiveProcessLinks': [160, ['LIST_ENTRY32']],
   'DirectoryTableBase': [24, ['unsigned long']],
   'ImageFileName': [332, ['String', {'length': 16}]],
   'ThreadListHead': [360, ['LIST_ENTRY32']],
   'UniqueProcessId': [156, ['unsigned int']]}],
 'Win2008SP2x64': [0,
  {'ActiveProcessLinks': [232, ['LIST_ENTRY64']],
   'DirectoryTableBase': [40, ['unsigned long']],
   'ImageFileName': [568, ['String', {'length': 16}]],
   'ThreadListHead': [608, ['LIST_ENTRY64']],
   'UniqueProcessId': [224, ['unsigned int']]}],
 'Win2008SP2x86': [0,
  {'ActiveProcessLinks': [160, ['LIST_ENTRY32']],
   'DirectoryTableBase': [24, ['unsigned long']],
   'ImageFileName': [332, ['String', {'length': 16}]],
   'ThreadListHead': [360, ['LIST_ENTRY32']],
   'UniqueProcessId': [156, ['unsigned int']]}],
 'Win7SP0x64': [0,
  {'ActiveProcessLinks': [392, ['LIST_ENTRY64']],
   'DirectoryTableBase': [40, ['unsigned long']],
   'ImageFileName': [736, ['String', {'length': 16}]],
   'ThreadListHead': [776, ['LIST_ENTRY64']],
   'UniqueProcessId': [384, ['unsigned int']]}],
 'Win7SP0x86': [0,
  {'ActiveProcessLinks': [184, ['LIST_ENTRY32']],
   'DirectoryTableBase': [24, ['unsigned long']],
   'ImageFileName': [364, ['String', {'length': 16}]],
   'ThreadListHead': [392, ['LIST_ENTRY32']],
   'UniqueProcessId': [180, ['unsigned int']]}],
 'Win7SP1x64': [0,
  {'ActiveProcessLinks': [392, ['LIST_ENTRY64']],
   'DirectoryTableBase': [40, ['unsigned long']],
   'ImageFileName': [736, ['String', {'length': 16}]],
   'ThreadListHead': [776, ['LIST_ENTRY64']],
   'UniqueProcessId': [384, ['unsigned int']]}],
 'Win7SP1x86': [0,
  {'ActiveProcessLinks': [184, ['LIST_ENTRY32']],
   'DirectoryTableBase': [24, ['unsigned long']],
   'ImageFileName': [364, ['String', {'length': 16}]],
   'ThreadListHead': [392, ['LIST_ENTRY32']],
   'UniqueProcessId': [180, ['unsigned int']]}],
 'Win8SP0x64': [0,
  {'ActiveProcessLinks': [744, ['LIST_ENTRY64']],
   'DirectoryTableBase': [40, ['unsigned long']],
   'ImageFileName': [1080, ['String', {'length': 16}]],
   'ThreadListHead': [1136, ['LIST_ENTRY64']],
   'UniqueProcessId': [736, ['unsigned int']]}],
 'WinXPSP2x86': [0,
  {'ActiveProcessLinks': [136, ['LIST_ENTRY32']],
   'DirectoryTableBase': [24, ['unsigned long']],
   'ImageFileName': [372, ['String', {'length': 16}]],
   'ThreadListHead': [400, ['LIST_ENTRY32']],
   'UniqueProcessId': [132, ['unsigned int']]}],
 'WinXPSP3x86': [0,
  {'ActiveProcessLinks': [136, ['LIST_ENTRY32']],
   'DirectoryTableBase': [24, ['unsigned long']],
   'ImageFileName': [372, ['String', {'length': 16}]],
   'ThreadListHead': [400, ['LIST_ENTRY32']],
   'UniqueProcessId': [132, ['unsigned int']]}],
 'WinXPSP3x86PAE': [0,
  {'ActiveProcessLinks': [136, ['LIST_ENTRY32']],
   'DirectoryTableBase': [24, ['unsigned long']],
   'ImageFileName': [372, ['String', {'length': 16}]],
   'ThreadListHead': [400, ['LIST_ENTRY32']],
   'UniqueProcessId': [132, ['unsigned int']]}]}

