# Rekall Memory Forensics
#
# Copyright 2014 Google Inc. All Rights Reserved.
#
# Authors:
# Michael Cohen <scudette@google.com>
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

"""This module implements plugins to inspect Window's DNS resolver cache.

In windows DNS requests are cached by the DNS resolver service. This is a
service running in svchost.exe and implemented as the mostly undocumented DLL
dnsrslvr.dll.

"""
import logging
import socket

from rekall import scan
from rekall import utils
from rekall import obj
from rekall.plugins.windows import common


# Most common DNS types.
DNS_TYPES = {
    1: "A",
    5: "CNAME",
    28: "AAAA",
}

types = {
    "DNS_HASHTABLE_ENTRY": [None, {
        "Name": [0x8, ["Pointer", dict(
            target="UnicodeString"
            )]],
        "Record": [24, ["Pointer", dict(
            target="DNS_RECORD"
        )]],
    }],

    "DNS_RECORD": [None, {
        "Next": [0, ["Pointer", dict(
            target="DNS_RECORD"
            )]],
        "Name": [8, ["Pointer", dict(
            target="UnicodeString"
            )]],
        "Type": [16, ["Enumeration", dict(
            choices=DNS_TYPES,
            target="unsigned short"
        )]],
        "DataLength": [18, ['unsigned short']],
        "Data": [0x20, ['char']],
    }],
}

class DNS_RECORD(obj.Struct):
    @property
    def Data(self):
        if self.Type == "CNAME":
            return self.m("Data").cast(
                "Pointer", target="UnicodeString").deref()
        elif self.Type == "A":
            return utils.inet_ntop(
                socket.AF_INET, self.obj_vm.read(self.m("Data").obj_offset, 4))


def InitializedDNSTypes(profile):
    profile.add_types(types)
    profile.add_classes(
        DNS_RECORD=DNS_RECORD
    )

    return profile


class WinDNSCache(common.WindowsCommandPlugin):
    """Dump the windows DNS resolver cache."""

    name = "dns_cache"

    def __init__(self, **kwargs):
        super(WinDNSCache, self).__init__(**kwargs)
        self.profile = InitializedDNSTypes(self.profile)

    def _find_svchost_vad(self):
        """Returns the vad and _EPROCESS of the dnsrslvr.dll."""
        pslist = self.session.plugins.pslist(proc_regex="svchost.exe")
        for task in pslist.filter_processes():
            self.session.report_progress("Checking pid %s for dnsrslvr.dll",
                                         task.pid)

            for vad in task.RealVadRoot.traverse():
                try:
                    filename = vad.ControlArea.FilePointer.FileName.v()
                    if filename.endswith("\\dnsrslvr.dll"):
                        return vad, task
                except AttributeError:
                    pass

        return None, None

    def _verify_hash_table(self, start, length):
        """Verify the region between start and end for a possible hash table.
        """
        cache_hash_table = self.profile.Array(
            start,
            target="Pointer",
            target_args=dict(
                target="DNS_HASHTABLE_ENTRY",
            ),
            count=length / 8)

        for entry in cache_hash_table:
            if entry.v() != 0:
                name = entry.Name.deref().v()
                if name:
                    # name must be a valid utf16 string encodable to ascii,
                    # since it is a DNS name.
                    try:
                        name.encode("ascii")
                    except UnicodeError:
                        return None

        return cache_hash_table

    def _locate_heap(self, task, vad):
        # Find all heaps in this process.
        heaps = [x.v() for x in task.Peb.ProcessHeaps]

        # Locate the correct heap by scanning for its reference from the
        # dnsrslvr.dll vad. This will normally be stored in dnsrslvr.dll's
        # global variable called g_CacheHeap.
        scanner = scan.PointerScanner(
            pointers=heaps,
            session=self.session,
            address_space=self.session.GetParameter("default_address_space"))

        heap_profile = self.session.address_resolver.LoadProfileForName("ntdll")
        for hit in scanner.scan(vad.Start, maxlen=vad.Length):
            heap = heap_profile.Pointer(
                hit, target="_HEAP"
            )
            for entry in heap.Entries:
                hash_table = self._verify_hash_table(
                    entry.obj_offset + 0x10, entry.Size * 16)
                if hash_table:
                    return hash_table

    def locate_cache_hashtable(self):
        """Finds the DNS cache hashtable.

        The dns cache runs inside one of the svchost.exe processes and is
        implemented via the dnsrslvr.dll service. We therefore first search for
        the correct VAD region for this DLL. We then find the private heap that
        belongs to the resolver.
        """
        vad, task = self._find_svchost_vad()
        if task is None:
            raise RuntimeError("Unable to find svchost.exe for dnsrslvr.dll.")

        # Switch to the svchost process context now.
        self.cc.SwitchProcessContext(task)

        return self._locate_heap(task, vad)

    def render(self, renderer):
        self.cc = self.session.plugins.cc()
        with self.cc:
            cache_hash_table = self.locate_cache_hashtable()
            if cache_hash_table:
                renderer.table_header([
                    dict(name="Name", type="TreeNode", width=45),
                    ("Record", "record", "[addrpad]"),
                    ("Type", "type", "6"),
                    ("Data", "data", ""),
                ])

                for entry in cache_hash_table:
                    if entry.v() != 0:
                        name = entry.Name.deref()
                        renderer.table_row(
                            name, entry, "HTABLE", depth=0)
                        for record in entry.Record.walk_list("Next", True):
                            name = record.Name.deref() or name
                            renderer.table_row(
                                name,
                                record,
                                record.Type,
                                record.Data, depth=1)
