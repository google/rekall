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

"""This file contains all the undocumented structs that were derived by
reversing. We try to also include references to the original reverser.

"""

AMD64 = {
    # Reference: http://gate.upm.ro/os/LABs/Windows_OS_Internals_Curriculum_Resource_Kit-ACADEMIC/WindowsResearchKernel-WRK/WRK-v1.2/base/ntos/mm/wrtfault.c

    # From http://www.cnblogs.com/kkindof/articles/2571227.html
    # Reversed from MiSessionInsertImage

    # typedef struct _IMAGE_ENTRY_IN_SESSION {
    #     LIST_ENTRY Link;
    #     PVOID Address;
    #     PVOID LastAddress;
    #     ULONG ImageCountInThisSession;
    #     LOGICAL ImageLoading;
    #     PMMPTE PrototypePtes;
    #     PKLDR_DATA_TABLE_ENTRY DataTableEntry;
    #     PSESSION_GLOBAL_SUBSECTION_INFO GlobalSubs;
    # } IMAGE_ENTRY_IN_SESSION, * PIMAGE_ENTRY_IN_SESSION;
    '_IMAGE_ENTRY_IN_SESSION': [None, {
            'Link': [0, ['_LIST_ENTRY']],
            'Address': [0x10, ['pointer', ['address']]],
            'LastAddress': [0x18, ['pointer', ['address']]],
            }],
}


I386 = {
    '_IMAGE_ENTRY_IN_SESSION': [None, {
            'Link': [0x00, ['_LIST_ENTRY']],
            'Address': [0x08, ['pointer', ['address']]],
            'LastAddress': [0x0b, ['pointer', ['address']]],
            }],
}
