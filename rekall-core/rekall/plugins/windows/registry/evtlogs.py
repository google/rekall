# Rekall Memory Forensics
# Copyright (C) 2008-2011 Volatile Systems
# Copyright (C) 2011 Jamie Levy (Gleeda) <jamie.levy@gmail.com>
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Additional Authors:
# Michael Cohen <scudette@gmail.com>
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

"""
@author:       Jamie Levy (gleeda)
@license:      GNU General Public License 2.0 or later
@contact:      jamie.levy@gmail.com
@organization: Volatile Systems
"""
import ntpath

from rekall import obj
from rekall import scan
from rekall import utils
from rekall.plugins.windows.registry import registry
from rekall.plugins.windows.registry import getsids

# for more information on Event Log structures see WFA 2E pg 260-263 by Harlan
# Carvey
evt_log_types = {
    'EVTLogHeader' : [0x30, {
        'HeaderSize' : [0x0, ['unsigned int']],
        'Magic' : [0x4, ['String', dict(length=4)]],  # LfLe

        # Offset of oldest record.
        'OffsetOldest' : [0x10, ['int']],

        # Offset of next record to be written.
        'OffsetNextToWrite' : [0x14, ['int']],
        'NextID' : [0x18, ['int']],  # Next event record ID.
        'OldestID' : [0x1c, ['int']], # Oldest event record ID.

        # Maximum size of event record (from registry).
        'MaxSize' : [0x20, ['int']],

        # Retention time of records (from registry).
        'RetentionTime' : [0x28, ['int']],

        # Size of the record (repeat of DWORD at offset 0).
        'RecordSize' : [0x2c, ['int']],
        }],

    'EVTRecordStruct' : [0x38, {
        'RecordLength' : [0x0, ['int']],
        'Magic' : [0x4, ['String', dict(length=4)]],  # LfLe
        'RecordNumber' : [0x8, ['int']],

        'TimeGenerated' : [0xc, ['UnixTimeStamp']],
        'TimeWritten' : [0x10, ['UnixTimeStamp']],

        # Specific to event source and uniquely identifies the event.
        'EventID' : [0x14, ['unsigned short']],
        'EventType' : [0x18, ['Enumeration', dict(
            target='unsigned short',
            choices={0x01: "Error",
                     0x02: "Warning",
                     0x04: "Info",
                     0x08: "Success",
                     0x10: "Failure"})]],

        # Number of description strings in event message.
        'NumStrings' : [0x1a, ['unsigned short']],
        'EventCategory' : [0x1c, ['unsigned short']],
        'ReservedFlags' : [0x1e, ['unsigned short']],
        'ClosingRecordNum' : [0x20, ['int']],

        # Offset w/in record of description strings.
        'StringOffset' : [0x24, ['int']],

        # Length of SID: if 0 no SID is present.
        'SidLength' : [0x28, ['int']],

        # Offset w/in record to start of SID (if present).
        'SidOffset' : [0x2c, ['int']],

        # Length of binary data of record.
        'DataLength' : [0x30, ['int']],

        # Offset of data w/in record.
        'DataOffset' : [0x34, ['int']],

        'Source': [0x38, ['UnicodeString', dict(
            length=lambda x: x.RecordLength)]],

        # The computer name is right after the Source.
        'Computer': [lambda x: x.Source.obj_offset + x.Source.obj_size,
                     ['UnicodeString', dict(
                         length=lambda x: x.RecordLength)]],

        'Sid': [lambda x: x.obj_offset + x.SidOffset.v(), ['_SID']],

        'Data':[lambda x: x.obj_offset + x.StringOffset.v(), [
            "ListArray", dict(
                target="UnicodeString",
                target_args=dict(encoding="utf16"),
                maximum_size=lambda x: x.RecordLength,
                count=lambda x: x.NumStrings)]],
        }],

    "_SID": [None, {
        "IdentifierAuthority": [None, ["Enumeration", dict(
            choices={
                "\x00\x00\x00\x00\x00\x00": "Null Authority",
                "\x00\x00\x00\x00\x00\x01": "World Authority",
                "\x00\x00\x00\x00\x00\x02": "Local Authority",
                "\x00\x00\x00\x00\x00\x03": "Creator Authority",
                "\x00\x00\x00\x00\x00\x04": "NonUnique Authority",
                "\x00\x00\x00\x00\x00\x05": "NT Authority",
                },
            target="String",
            target_args=dict(length=6, term=None)
            )]],
        "NumericIdentifier": [0x4, ["unsigned be int"]],
        "SubAuthority": [None, ["Array", dict(
            target="unsigned long",
            count=lambda x: x.SubAuthorityCount)]],
        }],
    }



class _SID(obj.Struct):
    """A Pretty printing implementation of sids.

    Reference:
    http://www.sekchek.com/downloads/white-papers/windows-about-sids.pdf
    """
    def __unicode__(self):
        """Format the Sid using SDDL Notation."""
        components = [self.Revision, self.NumericIdentifier]
        components.extend(self.SubAuthority)

        result = u"S-" + u"-".join([str(x) for x in components])

        # Try to resolve a friendly name from the cache in the context.
        friendly_name = self.obj_context.get("sid_cache", {}).get(result)
        if friendly_name:
            result = u"%s (%s)" % (result, friendly_name)

        return result


class EVTObjectTypes(obj.ProfileModification):
    """An implementation for parsing event logs."""

    @classmethod
    def modify(cls, profile):
        profile.add_overlay(evt_log_types)
        profile.add_classes(dict(_SID=_SID))


class EVTScanner(scan.BaseScanner):
    checks = [('StringCheck', dict(needle="LfLe"))]

    def scan(self, offset, maxlen=None, context=None):
        for hit in super(EVTScanner, self).scan(offset, maxlen=maxlen):
            event_offset = hit - self.profile.get_obj_offset(
                "EVTRecordStruct", "Magic")

            event = self.profile.EVTRecordStruct(
                offset=event_offset, vm=self.address_space, context=context)

            # Eliminate crazy events (between 2001 and 2017):
            if (1500000000 > event.TimeGenerated > 1000000000 and
                    1500000000 > event.TimeWritten > 1000000000):
                yield event


class EvtLogs(registry.RegistryPlugin):
    """Extract Windows Event Logs (XP/2003 only)"""

    name = "evtlogs"
    mode = "mode_xp"

    def __init__(self, **kwargs):
        super(EvtLogs, self).__init__(**kwargs)
        self.profile = EVTObjectTypes(self.profile)
        self.context = dict(sid_cache={})

    def FindEVTFiles(self):
        """Search for event log files in memory.

        We search for processes called 'services.exe' with a vad to and open
        file ending with '.evt'.
        """
        ps_plugin = self.get_plugin("pslist", proc_regex="services.exe")

        for task in ps_plugin.filter_processes():
            for vad in task.RealVadRoot.traverse():
                try:
                    filename = vad.ControlArea.FilePointer.FileName
                    if utils.SmartUnicode(filename).lower().endswith(".evt"):
                        yield task, vad
                except AttributeError:
                    pass

    def ScanEvents(self, vad, address_space):
        scanner = EVTScanner(profile=self.profile, address_space=address_space,
                             session=self.session)
        for event in scanner.scan(offset=vad.Start, maxlen=vad.Length,
                                  context=self.context):
            yield event

    def PrecacheSids(self):
        """Search for known sids that we can cache."""
        sid_cache = self.context["sid_cache"]
        sid_cache.update(getsids.well_known_sids)

        # Search for all known user sids.
        for hive_offset in self.hive_offsets:
            hive_address_space = registry.HiveAddressSpace(
                base=self.kernel_address_space,
                hive_addr=hive_offset, profile=self.profile)

            reg = registry.Registry(
                profile=self.profile, address_space=hive_address_space)

            # We get the user names according to the name of the diretory where
            # their profile is. This is not very accurate - should we check the
            # SAM instead?
            profiles = reg.open_key(
                'Microsoft\\Windows NT\\CurrentVersion\\ProfileList')

            for profile in profiles.subkeys():
                path = profile.open_value("ProfileImagePath").DecodedData
                if path:
                    sid_cache[utils.SmartUnicode(profile.Name)] = (
                        utils.SmartUnicode(ntpath.basename(path)))

        # Search for all service sids.
        getservicesids = self.get_plugin("getservicesids")
        for sid, service_name in getservicesids.get_service_sids():
            sid_cache[sid] = "(Service: %s)" % service_name

    def render(self, renderer):
        if self.plugin_args.verbosity > 5:
            self.PrecacheSids()

        renderer.table_header([("TimeWritten", "timestamp", ""),
                               ("Filename", "filename", ""),
                               ("Computer", "computer", ""),
                               ("Sid", "sid", ""),
                               ("Source", "source", ""),
                               ("Event Id", "event_id", ""),
                               ("Event Type", "event_type", ""),
                               ("Message", "message", "")])

        for task, vad in self.FindEVTFiles():
            filename = ntpath.basename(
                utils.SmartUnicode(vad.ControlArea.FilePointer.FileName))

            for event in self.ScanEvents(vad, task.get_process_address_space()):
                args = ";".join(
                    repr(utils.SmartStr(x)) for x in event.Data)

                renderer.table_row(
                    event.TimeWritten,
                    filename,
                    event.Computer,
                    event.Sid,
                    event.Source,
                    event.EventID,
                    event.EventType,
                    args)
