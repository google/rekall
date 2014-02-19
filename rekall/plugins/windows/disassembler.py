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

from rekall import kb
from rekall import obj
from rekall import plugin
from rekall import testlib


class Disassemble(plugin.Command):
    """Disassemble the given address space."""

    __name = "dis"

    @classmethod
    def args(cls, parser):
        super(Disassemble, cls).args(parser)
        parser.add_argument(
            "offset",
            help="An offset to disassemble. This can also be the name of "
            "a symbol with an optional offset. For example: "
            "tcpip.sys!_TcpCovetNetBufferList@20.")

        parser.add_argument("-a", "--address_space", default="K",
                            help="The address space to use.")

        parser.add_argument(
            "-l", "--length", default=50,
            help="The number of instructions (lines) to disassemble.")

        parser.add_argument(
            "-e", "--end", default=None,
            help="The end address to disassemble up to.")

    def __init__(self, offset=0, address_space=None, length=50, end=None,
                 mode=None, suppress_headers=False, target=None, **kwargs):
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
        self.end = end
        self.suppress_headers = suppress_headers
        self.mode = mode or self.session.profile.metadata(
            "arch", "I386")

        if self.mode == "I386":
            self.distorm_mode = distorm3.Decode32Bits
        else:
            self.distorm_mode = distorm3.Decode64Bits

        self.resolver = self.session.address_resolver

    def disassemble(self, offset):
        """Disassemble the number of instructions required.

        Returns:
          A tuple of (Address, Opcode, Instructions).
        """
        # Allow the offset to be specified as a symbol name.
        if isinstance(offset, basestring):
            offset = self.resolver.get_address_by_name(offset)

        # Disassemble the data one buffer at the time.
        while 1:
            data = self.address_space.read(
                offset, self.session.GetParameter("buffer_size"))

            iterable = distorm3.DecodeGenerator(
                int(offset), data, self.distorm_mode)

            for i, (offset, size, instruction, hexdump) in enumerate(
                iterable):
                yield offset, size, hexdump, instruction

                # Exit condition can be specified by length.
                if self.length is not None and i >= self.length:
                    return

                # Exit condition can be specified by end address.
                if self.end and offset > self.end:
                    return

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

    def format_relative_address(self, address):
        address = obj.Pointer.integer_to_address(address)

        # Try to locate the symbol below it.
        offset, name = self.resolver.get_nearest_constant_by_address(
            address)
        difference = address - offset

        if name:
            if difference == 0:
                return "%s" % (name)

            elif 0 < difference < 0x1000:
                return "%s+0x%X" % (
                    name, address - offset)

        return ""

    def format_indirect(self, operand):
        target = self.session.profile.Object(
            "address", offset=operand, vm=self.address_space).v()

        target_name = self.format_relative_address(target)
        operand_name = self.format_relative_address(operand)

        if target_name:
            return "0x%X %s -> %s" % (target, operand_name, target_name)
        else:
            return "0x%X %s" % (target, operand_name)

    SIMPLE_REFERENCE = re.compile("0x[0-9a-fA-F]+$")
    INDIRECT_REFERENCE = re.compile(r"\[(0x[0-9a-fA-F]+)\]")
    RIP_REFERENCE = re.compile(r"\[RIP\+(0x[0-9a-fA-F]+)\]")
    def find_reference(self, offset, size, instruction):
        match = self.INDIRECT_REFERENCE.search(instruction)
        if match:
            operand = int(match.group(1), 16)
            return self.format_indirect(operand) or ""

        match = self.SIMPLE_REFERENCE.search(instruction)
        if match:
            operand = int(match.group(0), 16)
            return self.format_address(operand) or ""

        match = self.RIP_REFERENCE.search(instruction)
        if match:
            operand = int(match.group(1), 16)
            if size % 2:
                align = 1
            else:
                align = 2

            return self.format_indirect(offset + operand - align) or ""

        return ""

    def render(self, renderer):
        """Disassemble code at a given address.

        Disassembles code starting at address for a number of bytes
        given by the length parameter (default: 128).

        Note: This feature requires distorm, available at
            http://www.ragestorm.net/distorm/

        The mode is '32bit' or '64bit'. If not supplied, the disasm
        mode is taken from the profile.
        """
        renderer.table_header(
            [('Address', "cmd_address", '[addrpad]'),
             ('Rel', "relative_address", '>4'),
             ('Op Codes', "opcode", '<20'),
             ('Instruction', "instruction", '<30'),
             ('Comment', "comment", "")],
            suppress_headers=self.suppress_headers)

        offset = 0
        last_function = 0
        self.last_function_name = ""

        for offset, size, hexdump, instruction in self.disassemble(
            self.offset):
            _, func_name = self.resolver.get_nearest_constant_by_address(
                offset)
            if func_name and func_name != self.last_function_name:
                renderer.format("------ %s ------\n" % func_name)
                last_function = offset
                self.last_function_name = func_name

            comment = self.find_reference(offset, size, instruction)
            relative = "%X" % (offset - last_function)
            if offset - last_function > 0x1000:
                relative = ""

            renderer.table_row(
                offset, relative, hexdump, instruction, comment)

            self.session.report_progress(
                "Disassembled %s: 0x%X", self.last_function_name, offset)

        # Continue from where we left off when the user calls us again with the
        # v() plugin.
        self.offset = offset


class TestDisassemble(testlib.SimpleTestCase):
    PARAMETERS = dict(
        commandline="dis %(func)s",
        func=0x805031be
        )
