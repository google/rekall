# Rekall Memory Forensics
# Copyright (C) 2007,2008 Volatile Systems
# Copyright (C) 2010,2011,2012 Michael Hale Ligh <michael.ligh@mnin.org>
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

import logging


from rekall import obj
from rekall.plugins.windows.gui import constants
from rekall.plugins.windows.gui import win32k_core

from rekall.plugins.windows.gui.vtypes import win7_sp0_x64_vtypes_gui
from rekall.plugins.windows.gui.vtypes import win7_sp1_x64_vtypes_gui
from rekall.plugins.windows.gui.vtypes import win7_sp0_x86_vtypes_gui
from rekall.plugins.windows.gui.vtypes import win7_sp1_x86_vtypes_gui


class _MM_SESSION_SPACE(win32k_core._MM_SESSION_SPACE):
    """A class for session spaces on Windows 7"""

    def find_shared_info(self):
        """The way we find win32k!gSharedInfo on Windows 7
        is different than before. For each DWORD in the
        win32k.sys module's .data section (DWORD-aligned)
        we check if its the HeEntrySize member of a possible
        tagSHAREDINFO structure. This should equal the size
        of a _HANDLEENTRY.

        The HeEntrySize member didn't exist before Windows 7
        thus the need for separate methods."""
        handle_table_size = self.obj_profile.get_obj_size("_HANDLEENTRY")

        handle_entry_offset = self.obj_profile.get_obj_offset(
            "tagSHAREDINFO", "HeEntrySize")

        import pdb; pdb.set_trace()

        for chunk in self._section_chunks(".data"):

            if chunk != handle_table_size:
                continue

            shared_info = self.obj_profile.tagSHAREDINFO(
                offset = chunk.obj_offset - handle_entry_offset,
                vm = self.obj_vm)

            if shared_info.is_valid():
                return shared_info

        return obj.NoneObject("Cannot find win32k!gSharedInfo")


class tagSHAREDINFO(win32k_core.tagSHAREDINFO):
    """A class for shared info blocks on Windows 7"""

    def is_valid(self):
        """Sanity checks for tagSHAREDINFO"""

        if not super(tagSHAREDINFO, self).is_valid():
            return False

        if self.ulSharedDelta != 0:
            return False

        if not self.psi.is_valid():
            return False

        return (self.psi.cbHandleTable / self.HeEntrySize ==
                self.psi.cHandleEntries)


class Win32GUIWin7(obj.ProfileModification):
    """Installs the win7 specific profiles for the GUI modules."""

    @classmethod
    def modify(cls, profile):
        version = ".".join(profile.metadatas('major', 'minor'))
        build = profile.metadata("build", 7601)
        architecture = profile.metadata("arch")

        if architecture == "AMD64":
            # http://doxygen.reactos.org/d5/dd0/timer_8h_source.html#l00019
            profile.add_overlay({
                    'tagTIMER' : [None, {
                            'head' : [0x00, ['_HEAD']],
                            'ListEntry' : [0x18, ['_LIST_ENTRY']],
                            'spwnd' : [0x28, ['pointer', ['tagWND']]],
                            'pti' : [0x30, ['pointer', ['tagTHREADINFO']]],
                            'nID' : [0x38, ['unsigned short']],
                            'cmsCountdown' : [0x40, ['unsigned int']],
                            'cmsRate' : [0x44, ['unsigned int']],
                            'flags' : [0x48, ['Flags', dict(
                                        bitmap=constants.TIMER_FLAGS)]],
                            'pfn' : [0x50, ['pointer', ['void']]],
                            }]})

            if build == 7600:
                profile.add_overlay(win7_sp0_x64_vtypes_gui.win32k_types)
            elif build == 7601:
                profile.add_overlay(win7_sp1_x64_vtypes_gui.win32k_types)
            else:
                logging.warning("Unsupported version %s, will use win7sp1",
                                version)

                profile.add_overlay(win7_sp1_x64_vtypes_gui.win32k_types)

        elif architecture == "I386":
            # http://doxygen.reactos.org/d5/dd0/timer_8h_source.html#l00019
            profile.vtypes.update({
                    'tagTIMER' : [None, {
                            'ListEntry' : [0xc, ['_LIST_ENTRY']],
                            'pti' : [0x18, ['pointer', ['tagTHREADINFO']]],
                            'spwnd' : [0x14, ['pointer', ['tagWND']]], #??
                            'nID' : [0x1C, ['unsigned short']],
                            'cmsCountdown' : [0x20, ['unsigned int']],
                            'cmsRate' : [0x24, ['unsigned int']],
                            'flags' : [0x28, ['Flags', dict(
                                        bitmap=constants.TIMER_FLAGS)
                                              ]],
                            'pfn' : [0x2C, ['pointer', ['void']]],
                            }]})

            if build == 7600:
                profile.add_overlay(win7_sp0_x86_vtypes_gui.win32k_types)

            elif build == 7601:
                profile.add_overlay(win7_sp1_x86_vtypes_gui.win32k_types)

            else:
                logging.warning("Unsupported version %s, will use win7sp1",
                                version)

                profile.add_overlay(win7_sp1_x86_vtypes_gui.win32k_types)

        profile.add_overlay({
                'tagHOOK': [None, {
                        'flags': [None, ['Flags', dict(
                                    bitmap=constants.HOOK_FLAGS
                                    )]],
                        }],
                '_HANDLEENTRY': [None, {
                        'bType': [None, ['Enumeration', dict(
                                    target='unsigned char',
                                    choices=constants.HANDLE_TYPE_ENUM_SEVEN
                                    )]],
                        }],
                'tagWINDOWSTATION' : [None, {
                        'pClipBase' : [None, ['Pointer', dict(
                                    target="Array",
                                    target_args=dict(
                                        count=lambda x : x.cNumClipFormats,
                                        target='tagCLIP'
                                        ),
                                    )]],
                        }],
                'tagCLIP': [None, {
                        'fmt' : [None, ['Enumeration', dict(
                                    target='unsigned long',
                                    choices=constants.CLIPBOARD_FORMAT_ENUM
                                    )]],
                        }]})

        profile.add_classes({
            '_MM_SESSION_SPACE': _MM_SESSION_SPACE,
            'tagSHAREDINFO': tagSHAREDINFO,
            })

        return profile
