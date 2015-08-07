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

"""
Provides the primitives needed to disassemble code using capstone,
unless it's not available on the system, then the code falls back to
using diStorm3.
"""

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

try:
    import capstone
except Exception:
    pass

# For now we still always use distorm3.
import distorm3

import re
import binascii

from rekall import plugin
from rekall import obj
from rekall import testlib

class Disassembler(object):

    __abstract = True

    def __init__(self, mode):
        self.mode = mode

    def disasm(self, data, offset):
        """ Starts disassembly of data """

    def decode(self, insn):
        """ Decodes the current instruction """


class Capstone(Disassembler):

    def __init__(self, mode):
        super(Capstone, self).__init__(mode)

        if self.mode == "I386":
            self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        elif self.mode == "AMD64":
            self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        elif self.mode == "MIPS":
            self.cs = capstone.Cs(capstone.CS_ARCH_MIPS, capstone.CS_MODE_32 +
                                  capstone.CS_MODE_BIG_ENDIAN)
        else:
            raise NotImplementedError(
                "No disassembler available for this arch.")

    def disasm(self, data, offset):
        return self.cs.disasm(data, int(offset))

    def decode(self, insn):
        instruction = Instruction(
            "%s %s" % (insn.mnemonic, insn.op_str))
        hexdump = unicode(binascii.hexlify(insn.bytes))

        return insn.address, insn.size, instruction, hexdump

class Distorm3(Disassembler):

    def __init__(self, mode):
        super(Distorm3, self).__init__(mode)

        if self.mode == "I386":
            self.distorm_mode = distorm3.Decode32Bits
        elif self.mode == "AMD64":
            self.distorm_mode = distorm3.Decode64Bits
        else:
            raise NotImplementedError(
                "No disassembler available for this arch.")

    def disasm(self, data, offset):
        return distorm3.DecodeGenerator(
            int(offset), data, self.distorm_mode)

    def decode(self, insn):
        (offset, size, instruction, hexdump) = insn
        instruction = Instruction(instruction)
        hexdump = unicode(hexdump)

        return offset, size, instruction, hexdump

class DisasmFactory(object):

    @classmethod
    def get(cls, mode):
        return Distorm3(mode)
        try:
            return Capstone(mode)

        except Exception:
            pass

        return Distorm3(mode)



class Instruction(unicode):
    """A Decoded instruction."""


class Disassemble(plugin.Command):
    """Disassemble the given offset."""

    __name = "dis"

    @classmethod
    def args(cls, parser):
        super(Disassemble, cls).args(parser)
        parser.add_argument(
            "offset", type="SymbolAddress",
            help="An offset to disassemble. This can also be the name of "
            "a symbol with an optional offset. For example: "
            "tcpip!TcpCovetNetBufferList.")

        parser.add_argument("-a", "--address_space", default=None,
                            help="The address space to use.")

        parser.add_argument(
            "-l", "--length", type="IntParser",
            help="The number of instructions (lines) to disassemble.")

        parser.add_argument(
            "-e", "--end", default=None, type="IntParser",
            help="The end address to disassemble up to.")

        parser.add_argument(
            "--mode", default="auto", choices=["auto", "I386", "AMD64", "MIPS"],
            type="Choices",
            help="Disassemble Mode (AMD64 or I386). Defaults to profile arch.")

        parser.add_argument(
            "--suppress_headers", default=False, type="Boolean",
            help="If set we do not write table headers.")

        parser.add_argument(
            "--branch", default=False, type="Boolean",
            help="If set we follow all branches to cover all code.")

    def __init__(self, offset=0, address_space=None, length=None, end=None,
                 mode="auto", suppress_headers=False, branch=False,
                 **kwargs):
        super(Disassemble, self).__init__(**kwargs)

        load_as = self.session.plugins.load_as(session=self.session)
        self.address_space = load_as.ResolveAddressSpace(address_space)
        resolver = self.session.address_resolver
        if resolver:
            offset = resolver.get_address_by_name(offset)

        # Normalize the offset to an address.
        offset = obj.Pointer.integer_to_address(offset)

        self.offset = offset
        self.length = length
        self.end = end

        # All the visited addresses (for branch analysis).
        self._visited = set()
        self._visited_count = 0

        self.follow_branches = branch
        self.suppress_headers = suppress_headers
        if mode == "auto":
            mode = self.session.profile.metadata("arch") or "I386"

        self.dis = DisasmFactory.get(mode)

    def disassemble(self, offset, depth=0):
        """Disassemble the number of instructions required.

        Yields:
          A tuple of (Address, Opcode, Instructions).
        """
        # Disassemble the data one page at the time.
        while 1:
            # The start of the disassembler buffer.
            buffer_offset = obj.Pointer.integer_to_address(offset)

            # By default read 2 pages.
            data = self.address_space.read(buffer_offset, 0x2000)

            for insn in self.dis.disasm(data, int(offset)):
                offset, size, instruction, hexdump = self.dis.decode(insn)

                if offset in self._visited:
                    return

                yield depth, offset, size, hexdump, instruction

                self._visited_count += 1
                if self.follow_branches:
                    self._visited.add(offset)

                # If the user asked for full branch analysis we follow all
                # branches. This gives us full code coverage for a function - we
                # just disassemble until the function exists from all branches.
                if self.follow_branches:
                    # A return stops this branch.
                    if instruction.startswith("RET"):
                        return

                    m = self.BRANCH_REFERENCE.match(instruction)
                    if m:
                        # Start disassembling the branch. When the branch is
                        # exhausted we resume disassembling the continued
                        # branch.
                        for x in self.disassemble(
                                int(m.group(2), 16), depth=depth+1):
                            yield x

                        # A JMP stops disassembling this branch.
                        if instruction.startswith("JMP"):
                            return

                # Exit condition can be specified by length.
                if (self.length is not None and
                        self._visited_count > self.length):
                    return

                # Exit condition can be specified by end address.
                if self.end and offset > self.end:
                    return

                # If we disassemble past one page, we read another two
                # pages. This guarantees that we have enough data for full
                # instructions.
                if offset - buffer_offset > 0x1000:
                    break

    def format_indirect(self, operand):
        target = self.session.profile.Object(
            "address", offset=operand, vm=self.address_space).v()

        resolver = self.session.address_resolver
        target_name = resolver.format_address(target)
        operand_name = resolver.format_address(operand)

        if target_name:
            return "0x%x %s -> %s" % (target, operand_name, target_name)
        else:
            return "0x%x %s" % (target, operand_name)

    BRANCH_REFERENCE = re.compile("(J|B)[^ ]{1,2} (0x[^ ]+)")
    SIMPLE_REFERENCE = re.compile("0x[0-9a-fA-F]+$")
    INDIRECT_REFERENCE = re.compile(r"\[(0x[0-9a-fA-F]+)\]")
    RIP_REFERENCE = re.compile(r"\[RIP([+-]0x[0-9a-fA-F]+)\]")
    def find_reference(self, offset, size, instruction):
        match = self.RIP_REFERENCE.search(instruction)
        if match:
            operand = int(match.group(1), 16)
            return self.format_indirect(offset + size + operand) or ""

        match = self.INDIRECT_REFERENCE.search(instruction)
        if match:
            operand = int(match.group(1), 16)
            return self.format_indirect(operand) or ""

        match = self.SIMPLE_REFERENCE.search(instruction)
        if match:
            operand = int(match.group(0), 16)
            resolver = self.session.address_resolver

            return resolver.format_address(operand) or ""

        return ""

    def render(self, renderer):
        """Disassemble code at a given address.

        Disassembles code starting at address for a number of bytes
        given by the length parameter (default: 128).

        Note: This feature requires capstone, available at
            http://www.capstone-engine.org/

        or distorm, available at
            http://www.ragestorm.net/distorm/

        The mode is '32bit' or '64bit'. If not supplied, the disasm
        mode is taken from the profile.
        """
        # If length nor end are specified only disassemble one pager output.
        if self.end is None and self.length is None:
            self.length = self.session.GetParameter("paging_limit") - 5

        # If we are doing branch analysis we can not suspend this plugin. We
        # must do everything all the time.
        if self.follow_branches:
            self.length = self.end = None

        renderer.table_header(
            [dict(type="TreeNode", name="Address", cname="cmd_address",
                  child=dict(style="address")),
             ('Rel', "relative_address", '[addr]'),
             ('Op Codes', "opcode", '<20'),
             ('Instruction', "instruction", '<30'),
             ('Comment', "comment", "")],
            suppress_headers=self.suppress_headers)

        offset = 0
        self._visited.clear()
        self._visited_count = 0

        for depth, offset, size, hexdump, instruction in self.disassemble(
                self.offset):
            relative = None
            comment = ""

            resolver = self.session.address_resolver
            if resolver:
                (f_offset, f_name) = resolver.get_nearest_constant_by_address(
                    offset)

                self.session.report_progress(
                    "Disassembled %s: 0x%x", f_name, offset)

                if offset - f_offset == 0:
                    renderer.table_row("------ %s ------\n" % f_name,
                                       annotation=True)

                comment = self.find_reference(offset, size, instruction)
                if offset - f_offset < 0x1000:
                    relative = offset - f_offset

            renderer.table_row(
                offset, relative, hexdump,
                instruction, Instruction(comment), depth=depth)

        # Continue from where we left off when the user calls us again with the
        # v() plugin.
        self.offset = offset


class TestDisassemble(testlib.SimpleTestCase):
    PARAMETERS = dict(
        # We want to test symbol discovery via export table detection so turn it
        # on.
        commandline=("dis -l %(length)s %(func)s "
                     "--name_resolution_strategies Export"),
        func=0x805031be,
        length=20
        )
