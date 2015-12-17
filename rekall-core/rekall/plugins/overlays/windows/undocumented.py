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
    # Reference:
    # http://gate.upm.ro/os/LABs/Windows_OS_Internals_Curriculum_Resource_Kit-ACADEMIC/WindowsResearchKernel-WRK/WRK-v1.2/base/ntos/mm/wrtfault.c

    # From http://www.cnblogs.com/kkindof/articles/2571227.html
    # Reversed from MiSessionInsertImage

    # win8.1.raw 18:05:45> dis "nt!MiSessionInsertImage"
    # 0xf802d314344a   4E e871030300           CALL 0xf802d31737c0   nt!memset
    # ...
    # 0xf802d314345a   5E 48897b20             MOV [RBX+0x20], RDI

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
        'Address': [0x10, ['Pointer']],
        'LastAddress': [0x18, ['Pointer']],
    }],

    # Reversed from tcpip.sys!TcpStartPartitionModule
    "PARTITION_TABLE": [None, {
        "Partitions": [8, ["Array", dict(
            target="Pointer",

            count=lambda x: x.obj_profile.get_constant_object(
                "PartitionCount", "unsigned int"),

            target_args=dict(
                target="Array",
                target_args=dict(
                    count=4,
                    target="FIRST_LEVEL_DIR"
                    )
                )
            )]],
        }],

    # ntoskrnl.exe!RtlCreateHashTable (PoolTag:HTab)
    "FIRST_LEVEL_DIR": [0x24, {
        "SizeOfSecondLevel": [0x8, ["unsigned int"]],

        "Mask": [0x10, ["unsigned int"]],

        # Reversed from ntoskrnl.exe!RtlpAllocateSecondLevelDir
        "SecondLevel": [0x20, ["Pointer", dict(
            target="Array",
            # Actual hash table (PoolTag:HTab)
            target_args=dict(
                count=lambda x: x.SizeOfSecondLevel,
                target="_LIST_ENTRY"
                )
            )]],
        }],

    '_SERVICE_DESCRIPTOR_TABLE' : [0x40, {
        'Descriptors' : [0x0, ['Array', dict(
            target='_SERVICE_DESCRIPTOR_ENTRY',
            count=2
            )]],
        }],

    # In 64 bit the KiServiceTable is a list of RVAs based off the table base to
    # the destination pointers.
    # Ref:
    # http://forum.sysinternals.com/keservicedescriptortableshadow-address_topic14093.html
    '_SERVICE_DESCRIPTOR_ENTRY' : [0x20, {
        'KiServiceTable' : [0x0, ['Pointer', dict(
            target="Array",
            target_args=dict(
                count=lambda x: x.ServiceLimit,
                target="int",
                )
            )]],
        'CounterBaseTable' : [0x8, ['Pointer']],
        'ServiceLimit' : [0x10, ['unsigned long long']],
        'ArgumentTable' : [0x18, ['Pointer']],
        }],

    # Documented in ./base/ntos/inc/mm.h WRK-v1.2.
    "_UNLOADED_DRIVER": [0x28, {
        "Name": [0, ["_UNICODE_STRING"]],
        "StartAddress": [0x10, ["Pointer"]],
        "EndAddress": [0x18, ["Pointer"]],
        "CurrentTime": [0x20, ["WinFileTime"]],
        }],
}


I386 = {
    '_IMAGE_ENTRY_IN_SESSION': [None, {
        'Link': [0x00, ['_LIST_ENTRY']],
        'Address': [0x08, ['pointer', ['address']]],
        'LastAddress': [0x0b, ['pointer', ['address']]],
    }],

    # Reversed from tcpip.sys!TcpStartPartitionModule
    "PARTITION_TABLE": [None, {
        "Partitions": [4, ["Array", dict(
            target="Pointer",

            count=lambda x: x.obj_profile.get_constant_object(
                "PartitionCount", "unsigned int"),

            target_args=dict(
                target="Array",
                target_args=dict(
                    count=4,
                    target="FIRST_LEVEL_DIR"
                    )
                )
            )]],
        }],

    # ntoskrnl.exe!RtlCreateHashTable
    "FIRST_LEVEL_DIR": [0x24, {
        "SizeOfSecondLevel": [0x8, ["unsigned int"]],

        "Mask": [0x10, ["unsigned int"]],

        # Reversed from ntoskrnl.exe!RtlpAllocateSecondLevelDir
        "SecondLevel": [0x20, ["Pointer", dict(
            target="Array",
            target_args=dict(
                count=lambda x: x.SizeOfSecondLevel,
                target="_LIST_ENTRY"
                )
            )]],
        }],

    '_SERVICE_DESCRIPTOR_TABLE' : [0x20, {
        'Descriptors' : [0x0, ['Array', dict(
            target='_SERVICE_DESCRIPTOR_ENTRY',
            count=2
            )]],
        }],

    '_SERVICE_DESCRIPTOR_ENTRY' : [0x10, {
        'KiServiceTable' : [0x0, ['Pointer', dict(
            target="Array",
            target_args=dict(
                count=lambda x: x.ServiceLimit,
                target="unsigned int",
                )
            )]],
        'CounterBaseTable' : [0x4, ['Pointer']],
        'ServiceLimit' : [0x8, ['unsigned long']],
        'ArgumentTable' : [0xc, ['Pointer']],
        }],

    # Documented in ./base/ntos/inc/mm.h WRK-v1.2.
    "_UNLOADED_DRIVER": [24, {
        "Name": [0, ["_UNICODE_STRING"]],
        "StartAddress": [8, ["Pointer"]],
        "EndAddress": [12, ["Pointer"]],
        "CurrentTime": [16, ["WinFileTime"]],
        }],
}

# TODO: Move to their own profile.
# These come from the reactos ndk project.
ENUMS = {
    "_KOBJECTS": {
        "0": "EventNotificationObject",
        "1": "EventSynchronizationObject",
        "2": "MutantObject",
        "3": "ProcessObject",
        "4": "QueueObject",
        "5": "SemaphoreObject",
        "6": "ThreadObject",
        "7": "GateObject",
        "8": "TimerNotificationObject",
        "9": "TimerSynchronizationObject",
        "10": "Spare2Object",
        "11": "Spare3Object",
        "12": "Spare4Object",
        "13": "Spare5Object",
        "14": "Spare6Object",
        "15": "Spare7Object",
        "16": "Spare8Object",
        "17": "Spare9Object",
        "18": "ApcObject",
        "19": "DpcObject",
        "20": "DeviceQueueObject",
        "21": "EventPairObject",
        "22": "InterruptObject",
        "23": "ProfileObject",
        "24": "ThreadedDpcObject",
        "25": "MaximumKernelObject"
    },
}
