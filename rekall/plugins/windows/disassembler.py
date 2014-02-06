# Rekall Memory Forensics
# Copyright (C) 2012 Michael Cohen <scudette@gmail.com>
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

"""Provides the primitives needed to disassemble code using distorm3."""

# This stuff is just here to make pyinstaller pick up on it. Due to the way
# distorm3 uses ctypes, pyinstaller misses the imports. Note that the following
# patch should also be applied to distorm3/__init__.py to support freezing:
#
#    # Guess the DLL filename and load the library.
#    if getattr(sys, "frozen", None):
#        _distorm_path = '.'
#    else:
#        _distorm_path = split(__file__)[0]
try:
    from ctypes import cdll

    cdll.LoadLibrary("distorm3.dll")
except Exception:
    pass

import distorm3
import re

from rekall import args
from rekall import kb
from rekall import plugin
from rekall import testlib


class Disassemble(plugin.Command):
    """Disassemble the given address space."""

    __name = "dis"

    @classmethod
    def args(cls, parser):
        super(Disassemble, cls).args(parser)
        parser.add_argument("offset", action=args.IntParser,
                            help="An offset to disassemble.")

        parser.add_argument("-a", "--address_space", default="K",
                            help="The address space to use.")

        parser.add_argument(
            "-l", "--length", default=50,
            help="The number of instructions (lines) to disassemble.")

    def __init__(self, offset=0, address_space=None, length=50, mode=None,
                 suppress_headers=False, target=None, **kwargs):
        """Dumps a disassembly of a location.

        Args:
          address_space: The address_space to read from.
          offset: The offset to read from.
          length: The number of instructions (lines) to disassemble.
          mode: The mode (32/64 bit)- if not set taken from profile.
          suppress_headers: If set we do not write headers.
          target: An ObjBase instance. If specified we do not need the offset
            and address_space.
        """
        super(Disassemble, self).__init__(**kwargs)
        if target is not None:
            address_space = target.obj_vm
            offset = target.offset

        load_as = self.session.plugins.load_as(session=self.session)
        self.address_space = load_as.ResolveAddressSpace(address_space)
        if not self.address_space:
            self.address_space = self.session.kernel_address_space

        self.offset = offset
        self.length = length
        self.suppress_headers = suppress_headers
        self.mode = mode or self.session.profile.metadata(
            "arch", "I386")

        if self.mode == "I386":
            self.distorm_mode = distorm3.Decode32Bits
        else:
            self.distorm_mode = distorm3.Decode64Bits

        if not self.session.address_resolver:
            self.session.address_resolver = kb.AddressResolver(self.session)

        self.resolver = self.session.address_resolver

    def disassemble(self, offset):
        """Disassemble the number of instructions required.

        Returns:
          A tuple of (Address, Opcode, Instructions).
        """
        data = self.address_space.read(offset, self.length * 10)
        iterable = distorm3.DecodeGenerator(
            int(offset), data, self.distorm_mode)

        for (offset, _size, instruction, hexdump) in iterable:
            yield offset, hexdump, instruction

    def format_address(self, operand):
        # Try to locate the symbol below it.
        offset, name = self.resolver.get_nearest_constant_by_address(
            operand)

        difference = operand - offset
        if name:
            if difference == 0:
                return name

            elif 0 < difference < 0x1000:
                return "%s + 0x%X" % (name, operand - offset)

    def format_indirect(self, operand):
        target = self.session.profile.Pointer(
            offset=operand, vm=self.address_space)

        # Try to locate the symbol below it.
        offset, name = self.resolver.get_nearest_constant_by_address(
            target.v())

        difference = target.v() - offset
        if not name:
            return ""

        if name.startswith("("):
            return "0x%X @ %s" % (target.v(), name)

        else:
            if difference == 0:
                return "[%s]" % name

            elif 0 < difference < 0x1000:
                return "0x%X [%s + 0x%X]" % (
                    target.v(), name, target.v() - offset)

            else:
                return "0x%X @ %s + 0x%X" % (
                    target.v(), name, target.v() - offset)

    def render(self, renderer):
        """Disassemble code at a given address.

        Disassembles code starting at address for a number of bytes
        given by the length parameter (default: 128).

        Note: This feature requires distorm, available at
            http://www.ragestorm.net/distorm/

        The mode is '32bit' or '64bit'. If not supplied, the disasm
        mode is taken from the profile.
        """
        renderer.table_header([('Address', "cmd_address", '[addrpad]'),
                               ('Op Codes', "opcode", '<20'),
                               ('Instruction', "instruction", '<40'),
                               ('Comment', "comment", "")],
                              suppress_headers=self.suppress_headers)

        offset = 0
        regex = re.compile("0x[0-9a-fA-F]+$")
        indirect_regex = re.compile(r"\[(0x[0-9a-fA-F]+)\]$")

        for i, (offset, hexdump, instruction) in enumerate(
            self.disassemble(self.offset)):
            if i >= self.length:
                break

            func_name = self.resolver.get_constant_by_address(offset)
            if func_name:
                renderer.format("------ %s ------\n" % func_name)

            comment = ""
            match = indirect_regex.search(instruction)
            if match:
                operand = int(match.group(1), 16)
                comment = self.format_indirect(operand) or ""

            else:
                match = regex.search(instruction)
                if match:
                    operand = int(match.group(0), 16)
                    comment = self.format_address(operand) or ""

            renderer.table_row(offset, hexdump, instruction, comment)

        # Continue from where we left off when the user calls us again with the
        # v() plugin.
        self.offset = offset


class TestDisassemble(testlib.SimpleTestCase):
    PARAMETERS = dict(
        commandline="dis %(func)s",
        func=0x805031be
        )
