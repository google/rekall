# Rekall Memory Forensics
#
# Copyright 2014 Google Inc. All Rights Reserved.
#
# Authors:
# Michael Cohen <scudette@google.com>
#
# Acknowledgments:
# We would like to thank Chakib Gzenayi for his patient testing and suggestions
# in the development of this plugin.
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
import socket

from rekall import scan
from rekall import utils
from rekall import obj
from rekall.plugins.windows import common

# pylint: disable=protected-access


# Most common DNS types.
DNS_TYPES = {
    1: "A",
    5: "CNAME",
    28: "AAAA",
}

types = {
    "DNS_HASHTABLE_ENTRY": [None, {
        "List": [0x0, ["_LIST_ENTRY"]],
        "Name": [0x8, ["Pointer", dict(
            target="UnicodeString"
            )]],

        "Record": [0x18, ["Pointer", dict(
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

win10_overlays = {
    "DNS_HASHTABLE_ENTRY": [None, {
        "List": [0x8, ["_LIST_ENTRY"]],
        "Name": [0x38, ["Pointer", dict(
            target="UnicodeString"
            )]],

        "Record": [0x58, ["Pointer", dict(
            target="DNS_RECORD"
        )]],
    }],

}



class DNS_RECORD(obj.Struct):
    @utils.safe_property
    def Data(self):
        if self.Type == "CNAME":
            return self.m("Data").cast(
                "Pointer", target="UnicodeString").deref()
        elif self.Type == "A":
            return utils.inet_ntop(
                socket.AF_INET, self.obj_vm.read(self.m("Data").obj_offset, 4))


def InitializedDNSTypes(profile):
    profile.add_types(types)
    profile.add_types(dict(
        _LIST_ENTRY=profile.session.profile.vtypes["_LIST_ENTRY"]))

    # Windows 10 changes things around a bit.
    if profile.session.profile.metadata("major") == 10:
        profile.add_overlay(win10_overlays)

    profile.add_classes(
        DNS_RECORD=DNS_RECORD
    )

    return profile


class WinDNSCache(common.WindowsCommandPlugin):
    """Dump the windows DNS resolver cache."""

    name = "dns_cache"

    mode = ["mode_amd64", "mode_vista_plus"]

    __args = [
        dict(name="hashtable",
             help="Optionally provide the hashtable"),

        dict(name="no_index", type="Boolean",
             help="Should we not use the index"),
    ]

    table_header = [
        dict(name="Name", type="TreeNode", width=45),
        dict(name="record", style="address"),
        dict(name="type", width=16),
        dict(name="data"),
    ]

    def column_types(self):
        profile = InitializedDNSTypes(self.profile)
        return dict(
            Name=self.profile.UnicodeString(),
            record=profile.DNS_HASHTABLE_ENTRY(),
            type="",
            data="127.0.0.1"
        )

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

    def _verify_hash_table(self, allocation, heap):
        """Verify the allocation between start and end for a hash table.

        We have observed that often the hash table may contain corrupt data due
        to paging smear during acquisition, hence more rigorous checks might
        actually fail to find the correct hash table due to corrupted data
        confusing the sanity checks here. It is always better to detect the
        correct version using the profile repository.
        """
        self.session.logging.debug("Verifying hash table at %#x",
                                   allocation.obj_offset)

        if (self.plugin_args.hashtable and
            allocation.obj_offset != self.plugin_args.hashtable):
            return False

        # Find all segments in this heap.
        segments = utils.RangedCollection()
        for seg in heap.Segments:
            segments.insert(seg.FirstEntry, seg.LastValidEntry, seg)

        # We usually observe the hash table to be about 1600 bytes, but it might
        # grow.
        if allocation.length > 1600 * 3 or allocation.length < 1600:
            return False

        # Cast the allocation into a hash table.
        cache_hash_table = allocation.cast(
            "Array",
            target="Pointer",
            target_args=dict(
                target="DNS_HASHTABLE_ENTRY",
            ),
            profile=self.profile,
            size=allocation.length)

        count = 0
        for entry in cache_hash_table:
            # If the hashtable entry is null, keep searching.
            entry = entry.v()
            if entry == 0:
                continue

            # ALL entry pointers must point back into one of the other segments
            # in this heap (Since DNS_HASHTABLE_ENTRY are allocated from this
            # heap)..
            dest_segment = segments.get_range(entry)
            if dest_segment is None:
                return False

            count += 1

        # It may be that the hashtable is all empty but otherwise we will match
        # a zero allocated block.
        if count == 0:
            return False

        return cache_hash_table

    def _locate_heap_using_index(self, task):
        """Locate the heap by referencing the index.

        We consult the profile repository for all known versions of dnsrslvr.dll
        and use the known symbol offsets to identify the currently running
        version. Unfortunately often the RSDS section of the PE file is not
        mapped and so we can not directly identify the running version. We
        therefore use the following algorithm:

        1. Enumerate the g_CacheHeap constant for each known version and ensure
        it is referring to a valid heap.

        2. Using the matching profile, dereference the g_HashTable constant and
        ensure it refers to a valid allocation within the above heap.

        3. If both these conditions exist, we return the hash table without
        further checks.

        This method is generally more robust than scanning for the pointers.
        """
        # The base addresses of all valid heaps.
        heaps = set([x.v() for x in task.Peb.ProcessHeaps])
        dnsrslvr_index = self.session.LoadProfile("dnsrslvr/index")

        # The base address of dnsrslvr.dll.
        base_address = self.session.address_resolver.get_address_by_name(
            "dnsrslvr")

        # Now check all profiles for these symbols.
        for profile, symbols in dnsrslvr_index.index.iteritems():
            # Correct symbols offset for dll base address.
            lookup = dict((y[0], x + base_address) for x, y in symbols)

            # According to this profile, where is the cache heap and hash table?
            heap_pointer = self.profile.Pointer(lookup.get("g_CacheHeap")).v()
            hash_tbl_ptr = self.profile.Pointer(lookup.get("g_HashTable")).v()

            if heap_pointer in heaps:
                heap = self.heap_profile._HEAP(
                    offset=heap_pointer
                )

                for entry in heap.Entries:
                    if entry.Allocation.obj_offset == hash_tbl_ptr:
                        self.session.logging.info(
                            "dnsrslvr.dll match profile %s. Hash table is at "
                            "%#x", profile, hash_tbl_ptr)

                        return self.profile.Array(
                            hash_tbl_ptr,
                            target="Pointer",
                            target_args=dict(
                                target="DNS_HASHTABLE_ENTRY",
                            ),
                            count=entry.Allocation.length / 8)

        self.session.logging.info(
            "Failed to detect the exact version of dnsrslvr.dll, please "
            "consider sending a copy of this DLL's GUID to the Rekall team so "
            "we can add it to the index.")

    def _locate_heap(self, task, vad):
        """Locate the correct heap by scanning for its reference.

        Find the references into the heap from the dnsrslvr.dll vad. This will
        normally be stored in dnsrslvr.dll's global variable called g_CacheHeap.
        """
        scanner = scan.PointerScanner(
            pointers=task.Peb.ProcessHeaps,
            session=self.session,
            address_space=self.session.GetParameter("default_address_space"))

        seen = set()
        for hit in scanner.scan(vad.Start, maxlen=vad.Length):
            heap = self.heap_profile.Pointer(
                hit, target="_HEAP"
            ).deref()


            if heap in seen:
                continue

            seen.add(heap)

            for entry in heap.Entries:
                hash_table = self._verify_hash_table(entry.Allocation, heap)
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

        # Load the profile for dnsrslvr and add the new types.
        dnsrslvr_mod = self.session.address_resolver.GetModuleByName("dnsrslvr")
        if not dnsrslvr_mod:
            raise RuntimeError("Unable to find dnsrslvr.dll.")

        self.profile = InitializedDNSTypes(dnsrslvr_mod.profile)

        hash_table = self.session.address_resolver.get_constant_object(
            "dnsrslvr!g_HashTable",
            "Pointer",
            target_args=dict(
                target="Array",
                target_args=dict(
                    count=self.session.address_resolver.get_constant_object(
                        "dnsrslvr!g_HashTableSize", "unsigned int").v(),
                    target="Pointer",
                    target_args=dict(
                        target="DNS_HASHTABLE_ENTRY"
                    )
                )
            )
        )
        if hash_table:
            return hash_table.deref()

        ntdll_mod = self.session.address_resolver.GetModuleByName("ntdll")
        self.heap_profile = ntdll_mod.profile

        # First try to locate the hash table using the index, then fallback to
        # using scanning techniques:
        if not self.plugin_args.no_index:
            hash_table = self._locate_heap_using_index(task)
            if hash_table:
                return hash_table

        return self._locate_heap(task, vad)

    def collect(self):
        self.cc = self.session.plugins.cc()
        with self.cc:
            cache_hash_table = self.locate_cache_hashtable()
            if cache_hash_table:
                for bucket in cache_hash_table:
                    for entry in bucket.List.list_of_type_fast(
                            "DNS_HASHTABLE_ENTRY", "List",
                            include_current=True):
                        name = entry.Name.deref()

                        yield dict(Name=name,
                                   record=entry,
                                   type="HTABLE",
                                   depth=0)

                        for record in entry.Record.walk_list("Next", True):
                            name = record.Name.deref() or name
                            yield dict(Name=name,
                                       record=record,
                                       type=record.Type,
                                       data=record.Data,
                                       depth=1)
