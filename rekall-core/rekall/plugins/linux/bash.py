# Rekall Memory Forensics
#
# Copyright 2013 Google Inc. All Rights Reserved.
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
# pylint: disable=protected-access

"""Scan for bash history entries.

Based on the algorithm by Andrew Case but greatly optimised for speed.
"""

__author__ = "Michael Cohen <scudette@gmail.com>"

from rekall import scan
from rekall.plugins.overlays import basic
from rekall.plugins.linux import common


class TimestampScanner(scan.BaseScanner):
    """Search for the realine timestamps.

    These have a special signature which looks like "#" followed by the
    time since the epoch - for example #1384457055.
    """
    checks = [
        # We use a quick string search first for this rather unique string.
        ('StringCheck', dict(needle="#")),

        # Refine the search with a more precise regex.
        ('RegexCheck', dict(regex=r"\#\d{10}")),
        ]


class HeapTimestampScanner(common.HeapScannerMixIn, TimestampScanner):
    pass


class LinHistoryScanner(scan.PointerScanner):
    """Scan for the realine history struct.

    This looks for references to the timestamps discovered by the
    TimestampScanner above.
    """
    def scan(self, **kwargs):
        for hit in super(LinHistoryScanner, self).scan(**kwargs):
            timestamp_relative_offset = self.profile.get_obj_offset(
                "_hist_entry", "timestamp")

            hist_entry = self.profile._hist_entry(
                offset=hit - timestamp_relative_offset,
                vm=self.address_space)

            yield hist_entry


class HeapHistoryScanner(common.HeapScannerMixIn, LinHistoryScanner):
    """Only scan for history in the heap."""


class BashProfile64(basic.ProfileLP64, basic.BasicClasses):
    """Profile to parse internal bash data structures."""

    __abstract = True

    # types come from bash's ./lib/readline/history.h
    bash_vtype_64 = {
        "_hist_entry": [24, {
            "line": [0, ["Pointer", dict(target="String")]],
            "timestamp": [8, ["Pointer", dict(target="String")]],
            "data": [16, ["Pointer", dict(target="String")]],
            }],
        }

    def __init__(self, **kwargs):
        super(BashProfile64, self).__init__(**kwargs)
        self.add_types(self.bash_vtype_64)


class BashProfile32(basic.Profile32Bits, basic.BasicClasses):
    """Profile to parse internal bash data structures."""

    __abstract = True

    # types come from bash's ./lib/readline/history.h
    bash_vtype_32 = {
        "_hist_entry": [0xC, {
            "line": [0, ["Pointer", dict(target="String")]],
            "timestamp": [4, ["Pointer", dict(target="String")]],
            "data": [8, ["Pointer", dict(target="String")]],
            }],
        }

    def __init__(self, **kwargs):
        super(BashProfile32, self).__init__(**kwargs)
        self.add_types(self.bash_vtype_32)


class BashHistory(common.LinProcessFilter):
    """Scan the bash process for history.

    Based on original algorithm by Andrew Case.
    """
    __name = "bash"

    __args = [
        dict(name="scan_entire_address_space", type="Boolean",
             help="Scan the entire process address space, not only the heap."),
        dict(name="proc_regex", default="^bash$", type="RegEx",
             help="The processes we should examine."),
    ]

    table_header = [
        dict(name="divider", type="Divider"),
        dict(name="task", hidden=True),
        dict(name="timestamp", width=24),
        dict(name="command"),
    ]

    def __init__(self, *args, **kwargs):
        super(BashHistory, self).__init__(*args, **kwargs)
        if self.profile.metadata("arch") == "AMD64":
            self.bash_profile = BashProfile64(session=self.session)
        else:
            self.bash_profile = BashProfile32(session=self.session)

    def get_timestamps(self, scanner):
        """Scan process memory for things that look like a timestamp."""
        results = {}
        for hit in scanner.scan():
            timestamp = int(scanner.address_space.read(hit+1, 10))
            results[hit] = timestamp

        return results

    def collect(self):
        for task in self.filter_processes():
            process_as = task.get_process_address_space()

            # Choose the correct scanner to use depending on the flags.
            if self.plugin_args.scan_entire_address_space:
                timestamp_scanner = TimestampScanner(
                    profile=self.profile, session=self.session,
                    address_space=process_as)
            else:
                timestamp_scanner = HeapTimestampScanner(
                    profile=self.profile, session=self.session,
                    address_space=process_as, task=task)

            timestamps = self.get_timestamps(timestamp_scanner)
            if not timestamps:
                continue

            yield dict(divider="Task: %s (%s)" % (task.name,
                                                  task.pid))


            if self.plugin_args.scan_entire_address_space:
                scanner = LinHistoryScanner(
                    profile=self.bash_profile, session=self.session,
                    address_space=process_as, pointers=timestamps)
            else:
                scanner = HeapHistoryScanner(
                    profile=self.bash_profile, session=self.session,
                    address_space=process_as, task=task,
                    pointers=timestamps)

            hits = sorted(scanner.scan(), key=lambda x: x.timestamp.deref())
            for hit in hits:
                timestamp = self.profile.UnixTimeStamp(
                    value=int(unicode(hit.timestamp.deref())[1:]))

                yield dict(
                    task=task,
                    timestamp=timestamp,
                    command=hit.line.deref())
