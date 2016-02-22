#!/usr/bin/env python
# Rekall Memory Forensics
# Copyright 2016 Google Inc. All Rights Reserved.
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

"""Used to bootstrap the Mach-O profile using dwarfdump and Xcode.

This script will xcodebuild macho/main.c, which links against the structs in
Mach-O/loader.h. One of the artifacts of the build process is a dSYM bundle with
a DWARF stream that describes the structures used in loader.h.

This information is dumped using the dwarfdump command line utility and parsed
to produce a good-enough Mach-O profile, which Rekall can then use to parse
the resultant dSYM artifact properly and parse the DWARF stream using its
full-featured support.

This script should only ever be used for the purpose described above - ideally
this only has to be done once per profile repository.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

import json
import os
import re
import subprocess
import sys


def run_xcodebuild():
    """Build macho/main.c."""
    result = subprocess.call(["xcodebuild"], stdout=sys.stderr,
                             cwd=os.path.dirname(os.path.realpath(__file__)))
    if result != 0:
        raise OSError("xcodebuild failed.")


def find_dsym():
    """Find the binary with the DWARF stream we're interested in."""
    for root, dirs, _ in os.walk(os.path.dirname(os.path.realpath(__file__))):
        for dir_ in dirs:
            if dir_.lower() == "macho.dsym":
                return os.path.join(root, dir_, "Contents", "Resources",
                                    "DWARF", "macho")

    raise OSError("Couldn't find resulting dSYM.")


class DWARFDumpParser(object):
    """A rudimentary line-feed parser of dwarfdump output.

    See DWARFDumpParser.parse for a discussion of output.

    This implementation takes various shortcuts and only supports what's
    needed to generate a rudimentary Mach-O profile that can be used to
    bootstrap Rekall's more robust Mach-O support. Only struct, member and
    various typedef declarations are supported with no nesting. The only
    attributes that are processed are name, type, byte size and offset.

    Arguments:
        lines: Iterable of dwarfdump output, like a File object.
    """

    DWARF_STRUCT_DECL = re.compile(r"^(0x[a-fA-F0-9]+):\s*TAG_structure_type")
    DWARF_MEMBER_DECL = re.compile(r"^(0x[a-fA-F0-9]+):\s*TAG_member")
    DWARF_TYPEDEF_DECL = re.compile(
        r"^(0x[a-fA-F0-9]+):\s*TAG_(?:typedef|pointer_type|subroutine_type)")
    DWARF_BASETYPE_DECL = re.compile(r"^(0x[a-fA-F0-9]+):\s*TAG_base_type")

    DWARF_AT_NAME = re.compile(r"^\s*AT_name\(\s*\"([^\"]+)\"\s*\)")
    DWARF_AT_SIZE = re.compile(r"^\s*AT_byte_size\(\s*(0x[a-fA-F0-9]+)\s*\)")
    DWARF_AT_TYPE = re.compile(r"^\s*AT_type\( \{\s*(0x[a-fA-F0-9]+)\s*\} ")
    DWARF_AT_OFFSET = re.compile(
        r"^\s*AT_data_member_location\(\s*\+?([\d+]+)\s*\)")

    state_decl_dwarf_id = None
    current_state = None

    vtypes = None
    lines = None

    struct_name = None
    struct_size = None
    members = None
    member_name = None
    member_type = None
    member_offset = None

    typedefs = None

    def __init__(self, lines):
        self.vtypes = {}
        self.typedefs = {}
        self.basetypes = {}
        self.lines = lines
        self.current_state = self.state_init

    def reset(self):
        """Reset buffers for a new struct declaration."""
        self.reset_member()
        self.struct_name = None
        self.struct_size = None
        self.members = {}

    def reset_member(self):
        """Reset buffers for a new member declaration."""
        self.member_name = None
        self.member_type = None
        self.member_offset = None

    def parse(self):
        """Parse dwarfdump output and return Rekall vtypes.

        This takes a few shortcuts - for examplem pointer types aren't really
        understood and just become unsigned integeres. Unions are ignored, as
        are nested types. Any type the parser doesn't understand is interpreted
        as an unsigned integer, because if you just treat everything as an
        unsigned int, things work out, like, 95% of the time.

        Returns: A dict of vtypes, keyed on struct name. Contents are the
            Rekall vtype format.
        """
        self.reset()

        for line in self.lines:
            self.current_state(line)

        self.finalize_struct()

        for vtype in self.vtypes.itervalues():
            for member in vtype[1].itervalues():
                type_id = member[1]
                while not type_id in self.basetypes:
                    type_id = self.typedefs.get(type_id)
                    if type_id is None:
                        # Must've been typedefed through something we don't
                        # understand. Probably a union type or something.
                        # We just skip it - the bootstrap only needs enough
                        # information to get a DWARF stream out of a Mach-O.
                        break

                if type_id:
                    member[1] = [self.basetypes[type_id]]
                else:
                    member[1] = ["unsigned int"]  # Trust me, I'm an engineer.

        return self.vtypes

    def finalize_member(self):
        if self.member_name is not None:
            self.members[self.member_name] = [self.member_offset,
                                              self.member_type]

        self.reset_member()

    def finalize_struct(self):
        self.finalize_member()
        if self.struct_name is not None:
            self.vtypes[self.struct_name] = [self.struct_size, self.members]

        self.reset()

    def detect_new_state(self, line):
        """If the line is a new declaration, decide what the new state is.

        Returns:
            One of the self.state_* methods which is to become the new state
            handler.
        """
        match = self.DWARF_STRUCT_DECL.match(line)
        if match:
            self.state_decl_dwarf_id = int(match.group(1), 16)
            return self.state_struct

        match = self.DWARF_MEMBER_DECL.match(line)
        if match:
            self.state_decl_dwarf_id = int(match.group(1), 16)
            return self.state_member

        match = self.DWARF_TYPEDEF_DECL.match(line)
        if match:
            self.state_decl_dwarf_id = int(match.group(1), 16)
            return self.state_typedef

        match = self.DWARF_BASETYPE_DECL.match(line)
        if match:
            self.state_decl_dwarf_id = int(match.group(1), 16)
            return self.state_basetype

    def state_init(self, line):
        """Initial state - detects any decl and switches to that state."""
        new_state = self.detect_new_state(line)
        if new_state:
            self.current_state = new_state

    def state_struct(self, line):
        """State inside a struct declaration."""
        new_state = self.detect_new_state(line)
        if new_state:
            if new_state != self.state_member:
                self.finalize_struct()

            self.current_state = new_state
            return

        match = self.DWARF_AT_NAME.match(line)
        if match:
            self.struct_name = match.group(1)
            return

        match = self.DWARF_AT_SIZE.match(line)
        if match:
            self.struct_size = int(match.group(1), 16)
            return

    def state_member(self, line):
        """State inside a member declaration, inside a struct."""
        new_state = self.detect_new_state(line)
        if new_state:
            if new_state == self.state_member:
                self.finalize_member()
            else:
                self.finalize_struct()

            self.current_state = new_state
            return

        match = self.DWARF_AT_NAME.match(line)
        if match:
            self.member_name = match.group(1)
            return

        match = self.DWARF_AT_TYPE.match(line)
        if match:
            self.member_type = int(match.group(1), 16)
            return

        match = self.DWARF_AT_OFFSET.match(line)
        if match:
            self.member_offset = int(match.group(1))

    def state_typedef(self, line):
        """State inside a typedef-like declaration."""
        new_state = self.detect_new_state(line)
        if new_state:
            self.current_state = new_state
            return

        match = self.DWARF_AT_TYPE.match(line)
        if match:
            self.typedefs[self.state_decl_dwarf_id] = int(match.group(1), 16)
            self.current_state = self.state_init

    def state_basetype(self, line):
        """State inside a basetype declaration."""
        new_state = self.detect_new_state(line)
        if new_state:
            self.current_state = new_state
            return

        match = self.DWARF_AT_NAME.match(line)
        if match:
            self.basetypes[self.state_decl_dwarf_id] = match.group(1)
            self.current_state = self.state_init


def run_dwarfdump(path):
    """Run dwarfdump on 'path' and parse the output.

    Returns:
        Rekall vtypes for the file at 'path'.
    """
    lines = subprocess.check_output(["dwarfdump", path]).split("\n")
    parser = DWARFDumpParser(lines)

    return parser.parse()


def main():
    sys.stderr.write("Will xcodebuild the macho project.\n")
    run_xcodebuild()

    path = find_dsym()
    sys.stderr.write("dSYM dump at path %s\n" % path)

    vtypes = run_dwarfdump(path)
    sys.stderr.write("Dumping %d vtypes to stdout.\n" % len(vtypes))

    json.dump({"$STRUCTS": vtypes,
               "$METADATA": {"ProfileClass": "MachoProfile",
                             "Type": "Profile"}}, sys.stdout)


if __name__ == "__main__":
    main()
