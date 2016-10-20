# Rekall Memory Forensics
#
# Copyright 2016 Google Inc. All Rights Reserved.
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
#

""" Shimcache plugin.

This code is based on work by:

# Authors:
#   Volatility Plugin Development
#   * Fred House - Mandiant, a FireEye Company
#                  Twitter: @0xF2EDCA5A
#
#   Windows Shimcache Analysis
#   * Andrew Davis - Mandiant, a FireEye Company
#   * Claudiu Teodorescu - FireEye Inc.
#                        - Twitter: @cteo1

https://github.com/fireeye/Volatility-Plugins.git

and the paper:
https://www.fireeye.com/blog/threat-research/2015/10/shim_shady_live_inv/shim-shady-part-2.html
"""
import itertools

from rekall import plugin
from rekall.plugins.windows import common


# Add overlays
shimcache_win7_x64 = {
    "SHIM_CACHE_ENTRY": [None, {
        "ListEntry" : [0x0, ["_LIST_ENTRY"]],
        "Path" : [0x10, ["_UNICODE_STRING"]],
        "LastModified": [0x20, ["WinFileTime"]],
        "InsertFlags": [0x28, ["unsigned int"]],
        "ShimFlags": [0x2c, ["unsigned int"]],
        "BlobSize": [0x30, ["unsigned long long"]],
        "BlobBuffer" : [0x38, ["unsigned long"]],
    }],
}

shimcache_win7_x86 = {
    "SHIM_CACHE_ENTRY": [None, {
        "ListEntry" :[0x0, ["_LIST_ENTRY"]],
        "Path" : [0x08, ["_UNICODE_STRING"]],
        "LastModified" : [0x10, ["WinFileTime"]],
        "InsertFlags": [0x18, ["unsigned int"]],
        "ShimFlags": [0x1c, ["unsigned int"]],
        "BlobSize": [0x20, ["unsigned long long"]],
        "BlobBuffer" : [0x24, ["unsigned long"]],
    }],
}

shimcache_xp_x86 = {
    "SHIM_CACHE_HEADER": [None, {
        "Magic": [0, ["unsigned int"]],
        "MaxEntries": [0x4, ["unsigned int"]],
        "TotalEntries": [0x8, ["unsigned int"]],

        "LRU": [0x10, ["Array", dict(
            target="unsigned int",
            count=lambda x: x.TotalEntries
        )]],

        "Entries": [0x190, ["Array", dict(
            count=lambda x: x.TotalEntries,
            target="SHIM_CACHE_ENTRY",
        )]],
    }],

    "SHIM_CACHE_ENTRY" : [0x228, {
        "Path" : [0x0, ["UnicodeString", dict(length=0x208)]],
        "LastModified" : [0x210, ["WinFileTime"]],
        "FileSize": [0x218, ["long long"]],
        "LastUpdate" : [0x220, ["WinFileTime"]],
    }],
}

shimcache_win8_x64 = {
    "SHIM_CACHE_ENTRY_DETAIL": [None, {
        "LastModified": [0x0, ["WinFileTime"]],
        "InsertFlags": [0x08, ["unsigned int"]],
        "ShimFlags": [0x0c, ["unsigned int"]],
        "BlobSize": [0x10, ["unsigned long long"]],
        "Padding": [0x18, ["unsigned long long"]],
        "BlobBuffer": [0x20, ["unsigned long long"]],
    }],

    "SHIM_CACHE_ENTRY": [None, {
        "ListEntry" : [0x0, ["_LIST_ENTRY"]],
        "Path": [0x18, ["_UNICODE_STRING"]],
        "ListEntryDetail": [0x38, ["Pointer", dict(
            target="SHIM_CACHE_ENTRY_DETAIL"
        )]],
    }],
}

shimcache_win8_x86 = {
    "SHIM_CACHE_ENTRY_DETAIL": [None, {
        "LastModified": [0x0, ["WinFileTime"]],
        "InsertFlags": [0x08, ["unsigned int"]],
        "ShimFlags": [0x0c, ["unsigned int"]],
        "BlobSize": [0x10, ["unsigned long"]],
        "BlobBuffer": [0x14, ["unsigned long"]],
    }],

    "SHIM_CACHE_ENTRY": [None, {
        "ListEntry": [0x0, ["_LIST_ENTRY"]],
        "Path": [0x10, ["_UNICODE_STRING"]],
        "ListEntryDetail": [0x20, ["Pointer", dict(
            target="SHIM_CACHE_ENTRY_DETAIL"
        )]],
    }],
}

shimcache_win10_x64 = {
    "SHIM_CACHE_ENTRY": [None, {
        "ListEntry" : [0x0, ["_LIST_ENTRY"]],
        "Path": [0x18, ["_UNICODE_STRING"]],
        "ListEntryDetail" : [0x28, ["Pointer", dict(
            target="SHIM_CACHE_ENTRY_DETAIL"
        )]],
    }],

    "SHIM_CACHE_ENTRY_DETAIL" : [None, {
        "LastModified": [0x08, ["WinFileTime"]],
        "BlobSize": [0x10, ["unsigned long"]],
        "BlobBuffer": [0x18, ["unsigned long long"]],
    }],

    "SHIM_CACHE_HANDLE": [0x10, {
        "eresource": [0x0, ["Pointer", dict(target="_ERESOURCE")]],
        "avl_table": [0x8, ["Pointer", dict(target="_RTL_AVL_TABLE")]],
    }],
}


def AddShimProfiles(profile):
    profile = profile.copy()

    # Windows 7 uses this constant to store the shimcache.
    if profile.get_constant("g_ShimCache"):
        if profile.metadata("arch") == "AMD64":
            profile.add_overlay(shimcache_win7_x64)
        else:
            profile.add_overlay(shimcache_win7_x86)

    # Windows XP:
    elif 5 < profile.metadata("version") < 6:
        if profile.metadata("arch") == "I386":
            profile.add_overlay(shimcache_xp_x86)

    # Windows 8 uses a special driver to hold the cache.
    elif profile.get_constant("AhcCacheHandle"):
        if profile.metadata("arch") == "AMD64":
            profile.add_overlay(shimcache_win8_x64)
        else:
            profile.add_overlay(shimcache_win8_x86)

    # Windows 10 uses a special driver to hold the cache.
    elif profile.session.address_resolver.get_address_by_name("ahcache"):
        if profile.metadata("arch") == "AMD64":
            profile.add_overlay(shimcache_win10_x64)

    else:
        raise plugin.PluginError("Unable to identify windows version.")

    return profile


class ShimCacheMem(common.AbstractWindowsCommandPlugin):
    """Extract the Application Compatibility Shim Cache from kernel memory."""

    name = "shimcachemem"

    table_header = [
        dict(name="Shim", style="address"),
        dict(name="last_mod", width=30),
        dict(name="last_update", hidden=True),
        dict(name="size", width=10),
        dict(name="Path")
    ]

    def collect_xp(self):
        """Fetch the shimcache from XP.

        According to the paper, on XP the cache is in shared memory inside the
        process winlogon.exe. The cache begins with a header and a magic value
        of 0xDEADBEEF.

        For some reason the algorithm explained in the paper seems unnecessarily
        complex. In Rekall we just search for a handle to the ShimCacheMemory
        section object and use it.
        """
        for row in self.session.plugins.handles(proc_regex="winlogon",
                                                object_types="Section"):
            if "ShimSharedMemory" in row["details"]:
                # Found the section object.
                section = row["_OBJECT_HEADER"].Object

                # This is the process that created the shared object.
                process_owner = section.Segment.u1.CreatingProcess.deref()
                va = section.Segment.u2.FirstMappedVa.v()

                if unicode(process_owner.name).lower() != u"winlogon.exe":
                    continue

                # Switch to that process's context.
                with self.session.plugins.cc() as cc:
                    cc.SwitchProcessContext(process_owner)

                    header = self.profile.SHIM_CACHE_HEADER(va)
                    return header.Entries

        return []

    def collect_from_avl_table(self, avl_table):
        seen = set()

        for node in avl_table.BalancedRoot.traverse_children():
            entry = node.payload("SHIM_CACHE_ENTRY")
            if entry.obj_offset in seen:
                continue

            seen.add(entry.obj_offset)
            yield entry

            # Sometimes there are some entries in the linked lists too.
            for subentry in entry.ListEntry.list_of_type(
                    "SHIM_CACHE_ENTRY", "ListEntry"):
                if subentry.obj_offset in seen:
                    continue

                seen.add(subentry.obj_offset)
                yield subentry

    def collect_win7(self):
        avl_table = self.profile.get_constant_object(
            "g_ShimCache", "_RTL_AVL_TABLE")
        return self.collect_from_avl_table(avl_table)

    def collect_win8(self):
        header_pointer = self.session.address_resolver.get_constant_object(
            "nt!AhcCacheHandle", "Pointer")

        avl_table = header_pointer.dereference_as("_RTL_AVL_TABLE",
                                               profile=self.profile)
        return self.collect_from_avl_table(avl_table)

    def collect_win10(self):
        header_pointer = self.session.address_resolver.get_constant_object(
            "ahcache!AhcCacheHandle", "Pointer")

        header = header_pointer.dereference_as("SHIM_CACHE_HANDLE",
                                               profile=self.profile)
        return self.collect_from_avl_table(header.avl_table)

    def collect(self):
        # We need this module's symbols.
        self.session.address_resolver.track_modules("ahcache")

        self.profile = AddShimProfiles(self.session.profile)
        for entry in itertools.chain(self.collect_win10(),
                                     self.collect_win8(),
                                     self.collect_win7(),
                                     self.collect_xp()):

            # This field has moved around a bit between versions.
            last_modified = entry.multi_m(
                "LastModified",
                "ListEntryDetail.LastModified"
            )

            if last_modified == 0 or last_modified == None:
                continue

            yield dict(Shim=entry,
                       last_mod=last_modified,
                       last_update=entry.m("LastUpdate"),
                       size=entry.m("FileSize"),
                       Path=entry.Path)
