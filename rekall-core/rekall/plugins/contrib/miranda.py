"""This is a plugin written as part of the DFRWS 2015 workshop:

Forensic Reverse Engineering with Rekall Workshop:
http://www.rekall-forensic.com/a/rekall-innovations.com/rekall-innovations/ForensicReverseEngineeringwithRekall-Solutions.pdf
"""

from rekall import scan

from rekall_lib import utils
from rekall.plugins.overlays import basic
from rekall.plugins.windows import common


TYPES = {
    "MESSAGE_RECORD": [0x50, {
        "Message": [0, ["Pointer", dict(
            target="UnicodeString"
            )]],
        "Sender": [8, ["Pointer", dict(
            target="UnicodeString"
            )]],

        "Timestamp": [48, ["UnixTimeStamp"]],

        "Prev": [64, ["Pointer", dict(
            target="MESSAGE_RECORD"
            )]],
        "Next": [72, ["Pointer", dict(
            target="MESSAGE_RECORD"
            )]],
        }],

    "CHANNEL_RECORD": [0x50, {
        "Protocol": [0x20, ["Pointer", dict(
            target="String"
            )]],
        "Label": [0x28, ["Pointer", dict(
            target="UnicodeString"
            )]],
        "Channel": [0x30, ["Pointer", dict(
            target="UnicodeString"
            )]],
        "Welcome": [0x40, ["Pointer", dict(
            target="UnicodeString"
            )]],
        "LastMessage": [0xc8, ["Pointer", dict(
            target="MESSAGE_RECORD"
            )]],

        "FirstMessage": [0xd0, ["Pointer", dict(
            target="MESSAGE_RECORD"
            )]],

        "FirstUser": [0xd8, ["Pointer", dict(
            target="USER_RECORD"
            )]],

        "CurrentUser": [0xe0, ["Pointer", dict(
            target="USER_RECORD"
            )]],

        "NextChannel": [0x108, ["Pointer", dict(
            target="CHANNEL_RECORD"
            )]],
        }],

    "CHAT_RECORD": [96, {
        "ChatName": [0x30, ["Pointer", dict(
            target="UnicodeString"
            )]],
        "Channel": [0x40, ["Pointer", dict(
            target="CHANNEL_RECORD"
            )]],
        }],

    "USER_RECORD": [0x28, {
        "Nick": [0x00, ["Pointer", dict(
            target="UnicodeString"
            )]],
        "NickID": [0x08, ["Pointer", dict(
            target="UnicodeString"
            )]],
        "NextUser": [0x20, ["Pointer", dict(
            target="USER_RECORD"
            )]],
        }],

    "CHATS": [48, {
        "Count": [0, ["unsigned int"]],
        "Chats": [0x8, ["Pointer", dict(
            target="Array",
            target_args=dict(
                target="Pointer",
                count=lambda x: x.Count,
                target_args=dict(
                    target="CHAT_RECORD"
                    )
                )
            )]],
        }]
    }


class MirandaProfile(basic.ProfileLLP64, basic.BasicClasses):
    """A basic profile for Miranda IM."""

    @classmethod
    def Initialize(cls, profile):
        super(MirandaProfile, cls).Initialize(profile)
        profile.add_overlay(TYPES)


class HeapScannerMixin(object):
    def scan(self):
        task = self.session.GetParameter("process_context")
        for vad in task.RealVadRoot.traverse():
            if vad.u.VadFlags.ProtectionEnum == "READWRITE":
                # Only scan the VAD region.
                for match in super(HeapScannerMixin, self).scan(
                        vad.Start, vad.Length):
                    yield match

class HeapScanner(HeapScannerMixin, scan.MultiStringScanner):
    pass


class HeapPointerScanner(HeapScannerMixin, scan.PointerScanner):
    pass


class Miranda(common.WindowsCommandPlugin):
    name = "miranda"

    def FindChannels(self):
        scanner = HeapScanner(
            session=self.session,
            needles=[b"\xba\xba\xba\xabIRC_1\x00"])

        irc_hits = []
        for hit, _ in scanner.scan():
            irc_hits.append(hit)

        scanner = HeapPointerScanner(
            session=self.session,
            profile=self.session.profile, pointers=[x+4 for x in irc_hits])

        for referrer in scanner.scan():
            if self.session.default_address_space.read(
                    referrer - 0x24, 4) == b"\xba\xba\xba\xab":
                yield self.miranda_profile.CHANNEL_RECORD(referrer - 0x20)

    def render(self, renderer):
        self.miranda_profile = MirandaProfile(session=self.session)
        with self.session.plugins.cc(proc_regex="miranda") as cc:
            cc.SwitchContext()

            for channel in self.FindChannels():
                # For each channel we start a new section.
                renderer.section("Channel {0} {1:#x}".format(
                    channel.Channel, channel))

                users = []
                for x in channel.FirstUser.walk_list("NextUser", True):
                    users.append(utils.SmartUnicode(x.Nick.deref()))

                renderer.table_header([("Users", "users", "120")])
                renderer.table_row(",".join(users))

                renderer.table_header([
                    ("Timestamp", "timestamp", "30"),
                    ("User", "user", "20"),
                    ("Message", "message", "80"),
                ])

                for message_record in channel.FirstMessage.walk_list("Next"):
                    renderer.table_row(
                        message_record.Timestamp,
                        message_record.Sender.deref(),
                        message_record.Message.deref())
