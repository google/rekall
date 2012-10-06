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

from volatility import plugin
from volatility import obj
from volatility import scan

from volatility.plugins.addrspaces import amd64
from volatility.plugins.addrspaces import intel
from volatility.plugins.overlays import basic


# The idea is to avoid importing all the plugins at once just to check a couple
# of offsets, so we just use an abbridged version of the full profiles.


class IdleScanner(scan.BaseScanner):
    def __init__(self, process_names=None, **kwargs):
        super(IdleScanner, self).__init__(**kwargs)
        self.checks = [('MultiStringFinderCheck', dict(needles=process_names))]


class TestProfile(basic.Profile64Bits, basic.BasicWindowsClasses):
    def __init__(self, **kwargs):
        super(TestProfile, self).__init__(**kwargs)
        self.add_overlay(eprocess_vtypes)


class GuessProfile(plugin.PhysicalASMixin, plugin.Command):
    """Guess the exact windows profile using heuristics."""

    __name = "guess_profile"

    def __init__(self, process_names=("Idle",), **kwargs):
        super(GuessProfile, self).__init__(**kwargs)
        self.process_names = process_names

    def guess_using_idle_process(self):
        """Guess using the Idle process technique."""
        test_profile = TestProfile()

        scanner = IdleScanner(session=self.session,
                              process_names=self.process_names,
                              address_space=self.session.physical_address_space)

        for hit in scanner.scan():
            # Try every profile until one works.
            for name, cls in obj.Profile.classes.items():
                if cls.metadata("os") == "windows":
                    eprocess_offset = hit - test_profile.get_obj_offset(
                        name, 'ImageFileName')

                    if eprocess_offset == 0x02813140:
                        import pdb; pdb.set_trace()

                    eprocess = test_profile.Object(
                        name,
                        vm=self.session.physical_address_space,
                        offset=eprocess_offset)

                    dtb = eprocess.DirectoryTableBase.v()
                    # In windows the DTB must be page aligned.
                    if dtb < 0xFF or dtb & 0xFFF != 0:
                        continue

                    try:
                        # Make an address space to test the dtb
                        if cls.metadata("memory_model") == "64bit":
                            virtual_as = amd64.AMD64PagedMemory(
                                session=self.session,
                                base=self.session.physical_address_space,
                                dtb=dtb)
                        else:
                            virtual_as = intel.IA32PagedMemoryPae(
                                session=self.session,
                                base=self.session.physical_address_space,
                                dtb=dtb)
                    except addrspaces.Error:
                        continue

                    import pdb; pdb.set_trace()


    def render(self, renderer):
        self.guess_using_idle_process()



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
                    "DirectoryTableBase": [
                        eprocess.Pcb.DirectoryTableBase.obj_offset, ["unsigned long"]],
                    }]

    return eprocess_vtype

# The following is generated from generate_idle_lookup_list() above.
eprocess_vtypes = {
    'VistaSP1x64': [0, {
            'DirectoryTableBase': [40, ['unsigned long']],
            'ImageFileName': [568, ['String', dict(length=16)]],
            'Pcb': [0, ['_KPROCESSVistaSP1x64']],
            'ThreadListHead': [608, ['LIST_ENTRY64']]
            }],
    'VistaSP1x86': [0, {
            'DirectoryTableBase': [24, ['unsigned long']],
            'ImageFileName': [332, ['String', dict(length=16)]],
            'Pcb': [0, ['_KPROCESSVistaSP1x86']],
            'ThreadListHead': [360, ['LIST_ENTRY64']]
            }],
    'VistaSP2x64': [0, {
            'DirectoryTableBase': [40, ['unsigned long']],
            'ImageFileName': [568, ['String', dict(length=16)]],
            'Pcb': [0, ['_KPROCESSVistaSP2x64']],
            'ThreadListHead': [608, ['LIST_ENTRY64']]
            }],
    'VistaSP2x86': [0, {
            'DirectoryTableBase': [24, ['unsigned long']],
            'ImageFileName': [332, ['String', dict(length=16)]],
            'Pcb': [0, ['_KPROCESSVistaSP2x86']],
            'ThreadListHead': [360, ['LIST_ENTRY64']]
            }],
    'Win2008R2SP0x64': [0, {
            'DirectoryTableBase': [40, ['unsigned long']],
            'ImageFileName': [736, ['String', dict(length=16)]],
            'Pcb': [0, ['_KPROCESSWin2008R2SP0x64']],
            'ThreadListHead': [776, ['LIST_ENTRY64']]}],
    'Win2008R2SP1x64': [0, {
            'DirectoryTableBase': [40, ['unsigned long']],
            'ImageFileName': [736, ['String', dict(length=16)]],
            'Pcb': [0, ['_KPROCESSWin2008R2SP1x64']],
            'ThreadListHead': [776, ['LIST_ENTRY64']]}],
    'Win2008SP1x64': [0, {
            'DirectoryTableBase': [40, ['unsigned long']],
            'ImageFileName': [568, ['String', dict(length=16)]],
            'Pcb': [0, ['_KPROCESSWin2008SP1x64']],
            'ThreadListHead': [608, ['LIST_ENTRY64']]}],
    'Win2008SP1x86': [0, {
            'DirectoryTableBase': [24, ['unsigned long']],
            'ImageFileName': [332, ['String', dict(length=16)]],
            'Pcb': [0, ['_KPROCESSWin2008SP1x86']],
            'ThreadListHead': [360, ['LIST_ENTRY64']]}],
    'Win2008SP2x64': [0, {
            'DirectoryTableBase': [40, ['unsigned long']],
            'ImageFileName': [568, ['String', dict(length=16)]],
            'Pcb': [0, ['_KPROCESSWin2008SP2x64']],
            'ThreadListHead': [608, ['LIST_ENTRY64']]}],
    'Win2008SP2x86': [0,  {
            'DirectoryTableBase': [24, ['unsigned long']],
            'ImageFileName': [332, ['String', dict(length=16)]],
            'Pcb': [0, ['_KPROCESSWin2008SP2x86']],
            'ThreadListHead': [360, ['LIST_ENTRY64']]}],
    'Win7SP0x64': [0,  {
            'DirectoryTableBase': [40, ['unsigned long']],
            'ImageFileName': [736, ['String', dict(length=16)]],
            'Pcb': [0, ['_KPROCESSWin7SP0x64']],
            'ThreadListHead': [776, ['LIST_ENTRY64']]}],
    'Win7SP0x86': [0,  {
            'DirectoryTableBase': [24, ['unsigned long']],
            'ImageFileName': [364, ['String', dict(length=16)]],
            'Pcb': [0, ['_KPROCESSWin7SP0x86']],
            'ThreadListHead': [392, ['LIST_ENTRY64']]}],
    'Win7SP1x64': [0,  {
            'DirectoryTableBase': [40, ['unsigned long']],
            'ImageFileName': [736, ['String', dict(length=16)]],
            'Pcb': [0, ['_KPROCESSWin7SP1x64']],
            'ThreadListHead': [776, ['LIST_ENTRY64']]}],
    'Win7SP1x86': [0,  {
            'DirectoryTableBase': [24, ['unsigned long']],
            'ImageFileName': [364, ['String', dict(length=16)]],
            'Pcb': [0, ['_KPROCESSWin7SP1x86']],
            'ThreadListHead': [392, ['LIST_ENTRY64']]}],
    'Win8SP0x64': [0,  {
            'DirectoryTableBase': [40, ['unsigned long']],
            'ImageFileName': [1080, ['String', dict(length=16)]],
            'Pcb': [0, ['_KPROCESSWin8SP0x64']],
            'ThreadListHead': [1136, ['LIST_ENTRY64']]}],
    'WinXPSP2x86': [0,  {
            'DirectoryTableBase': [24, ['unsigned long']],
            'ImageFileName': [372, ['String', dict(length=16)]],
            'Pcb': [0, ['_KPROCESSWinXPSP2x86']],
            'ThreadListHead': [400, ['LIST_ENTRY64']]}],
    'WinXPSP3x86': [0,  {
            'DirectoryTableBase': [24, ['unsigned long']],
            'ImageFileName': [372, ['String', dict(length=16)]],
            'Pcb': [0, ['_KPROCESSWinXPSP3x86']],
            'ThreadListHead': [400, ['LIST_ENTRY64']]}]}


