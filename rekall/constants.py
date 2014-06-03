# Rekall Memory Forensics
# Copyright (C) 2008 Volatile Systems
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
import time

VERSION = "1.0rc11"
SCAN_BLOCKSIZE = 1024 * 1024 * 10

PROFILE_REPOSITORIES = [
    "https://raw.githubusercontent.com/google/rekall-profiles/master",
    "http://profiles.rekall-forensic.com",
    ]


# The supported profile repository version we will use. This version needs to be
# consistent with the profile json file's data layout version. We automatically
# prepend this to the profile name to ensure we receive the correct version. If
# in future the json format will change in an incompatible way, we can still
# access old profiles without upgrading.
PROFILE_REPOSITORY_VERSION = "v1.0"


BANNER = """
----------------------------------------------------------------------------
The Rekall Memory Forensic framework %s.

"We can remember it for you wholesale!"

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License.


Type 'help' to get started.
----------------------------------------------------------------------------
""" % VERSION

QUOTES = [
    "Baby, you make me wish I had three hands.",
    "Consider that a divorce!",
    "Get your story straight.",
    "Sorry. Too perfect.",
    "Ever heard of Rekall? They sell those fake memories.",
    "Get your ass to Mars.",
    "When you hear a crunch, you're there. "
    "Now, pull it out. Be careful! That's my head, too.",
    "Don't bother searching. The bug's in your skull.",
    "No wonder you're having nightmares. You're always watching the news.",
    "Relax. You'll live longer.",
    "See you at the party, Richter!",
    "You are what you do. A man is defined by his actions, not his memory.",
    "I just had a terrible thought... what if this is a dream?",
    "Two weeks.",
    "Get ready for a surprise!",
    "You're in a Johnnycab.",
    "You are not you, you're me!",
    "We hope you enjoyed the ride!",
    "Hey, man, I got five kids to feed!",
    "I've been trying to tell you, someone has erased his memory.",
    "If I am not me, then who the hell am I?",
    ]

def GetQuote():
    return QUOTES[int(time.time()) % len(QUOTES)]
