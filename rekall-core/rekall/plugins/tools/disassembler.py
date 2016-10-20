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
Provides the primitives needed to disassemble code using capstone.
"""

import binascii
import capstone
import re
import struct

from capstone import x86_const
from rekall import addrspace
from rekall import plugin
from rekall import obj
from rekall import utils
from rekall import testlib


class Disassembler(object):
    __abstract = True

    def __init__(self, mode, session=None, address_space=None):
        self.mode = mode
        self.session = session
        self.address_space = (
            address_space or
            addrspace.BaseAddressSpace.classes["DummyAddressSpace"](
                session=session))

    def disassemble(self, data, offset):
        """ Starts disassembly of data """

    def is_return(self):
        return False

    def is_branch(self):
        return False

    def target(self):
        return None


class Instruction(object):
    """A Decoded instruction."""
    __abstract = True


class CapstoneInstruction(Instruction):
    """A capstone decoded instruction."""

    # We need to build reverse maps to properly interpret capston
    # instructions.
    INSTRUCTIONS = {}
    REGISTERS = {}
    OP = {}

    @classmethod
    def _init_class(cls):
        for constant in dir(x86_const):
            components = constant.split("_")
            value = getattr(x86_const, constant)
            if components[0] == "X86":
                if components[1] == "INS":
                    cls.INSTRUCTIONS[value] = components[2]
                elif components[1] == "REG":
                    cls.REGISTERS[value] = components[2]
                elif components[1] == "OP":
                    cls.OP[value] = components[2]

        cls.REGISTERS[0] = None

    def __init__(self, insn, session=None, address_space=None):
        self.address_space = address_space
        self.insn = insn
        self.address = insn.address
        self.size = insn.size
        self.mnemonic = insn.mnemonic
        self._comment = ""
        self._operands = None  # Cache the operands.
        self.session = session
        self.resolver = session.address_resolver
        if not self.REGISTERS:
            self._init_class()

    @utils.safe_property
    def operands(self):
        if self._operands is not None:
            return self._operands

        result = []
        # For invalid instructions there are no operands
        if self.insn.id == 0:
            return result

        for op in self.insn.operands:
            operand = dict(type=self.OP[op.type], size=op.size)
            if operand["type"] == "REG":
                operand["reg"] = self.REGISTERS[op.reg]

            elif operand["type"] == "MEM":
                # This is of the form: [base_reg + disp + index_reg * scale]
                mem = op.mem
                operand["base"] = self.REGISTERS[mem.base]
                operand["disp"] = mem.disp
                operand["index"] = self.REGISTERS[mem.index]
                operand["scale"] = mem.scale

                if operand["base"] == "RIP":
                    target = self.insn.address + mem.disp + self.insn.size
                    operand["address"] = target
                    operand["target"] = self._read_target(target, operand)

                    self._comment = self.format_indirect(target, op.size)

                # Simple indirect address.
                if not operand["base"] and not operand["index"]:
                    operand["address"] = mem.disp
                    operand["target"] = self._read_target(mem.disp, operand)
                    self._comment = self.format_indirect(mem.disp, op.size)

            elif operand["type"] == "IMM":
                operand["target"] = operand["address"] = op.imm.real
                self._comment = ", ".join(self.resolver.format_address(
                    op.imm.real))

            result.append(operand)

        # Cache for next time.
        self._operands = result
        return result

    def _read_target(self, target, operand):
        data = self.address_space.read(target, operand["size"])
        if operand["size"] == 8:
            return struct.unpack("<Q", data)[0]

        if operand["size"] == 4:
            return struct.unpack("<I", data)[0]

    def GetCanonical(self):
        """Returns the canonical model of the instruction."""
        result = dict(mnemonic=self.INSTRUCTIONS[self.insn.id],
                      str="%s %s" % (self.insn.mnemonic, self.insn.op_str),
                      operands=self.operands)

        result["comment"] = self._comment
        return result

    @utils.safe_property
    def comment(self):
        return self.GetCanonical()["comment"]

    @utils.safe_property
    def op_str(self):
        return self.GetCanonical()["str"]

    @utils.safe_property
    def text(self):
        canonical = self.GetCanonical()
        if canonical["comment"]:
            return "%s (%s)" % (canonical["str"], canonical["comment"])
        return canonical["str"]

    @utils.safe_property
    def hexbytes(self):
        return unicode(binascii.hexlify(self.insn.bytes))

    def format_indirect(self, operand, size):
        if size == 1:
            type = "byte"
        elif size == 2:
            type = "unsigned short"
        elif size == 4:
            type = "unsigned int"
        else:
            type = "address"

        target = self.session.profile.Object(
            type, offset=operand, vm=self.address_space).v()

        target_name = ", ".join(self.resolver.format_address(target))
        operand_name = ", ".join(self.resolver.format_address(operand))

        if target_name:
            return "0x%x %s -> %s" % (target, operand_name, target_name)
        else:
            return "0x%x %s" % (target, operand_name)

    def is_return(self):
        return self.mnemonic.startswith("ret")

    # https://en.wikibooks.org/wiki/X86_Assembly/Control_Flow
    def is_branch(self):
        """Is this instruction a branch?

        e.g. JNE JE JG JLE JL JGE JMP JA JAE JB JBE JO JNO JZ JNZ JS JNS
        """
        return self.mnemonic.startswith("j")

    @utils.safe_property
    def target(self):
        if self.mnemonic[0] == "j":
            operand = self.operands[0]
            if operand["type"] in ("IMM", "MEM"):
                return operand.get("address")

            # We can not determine the target of REG jumps without the
            # registers.

    def match_rule(self, rule, context):
        """Match the rule against this instruction."""
        # Speed optimization. Most of the time the rule matches the mnemonic.
        mnemonic = rule.get("mnemonic")
        if mnemonic and mnemonic != self.INSTRUCTIONS[self.insn.id]:
            return False

        return self._MatchRule(rule, self.GetCanonical(), context)

    def _MatchRule(self, rule, instruction, context):
        if isinstance(rule, dict):
            for k, v in rule.iteritems():
                expected = instruction.get(k)
                if not self._MatchRule(v, expected, context):
                    return False
            return True

        if isinstance(rule, (list, tuple)):
            for subrule, subinst in zip(rule, instruction):
                if subrule and not self._MatchRule(subrule, subinst, context):
                    return False

            return True

        if isinstance(rule, basestring):
            # Rules starting with $ are capture variables.
            if rule[0] == "$":
                context[rule] = instruction
                return True

            # Rules starting with ~ are regular expressions.
            if isinstance(instruction, basestring) and rule[0] == "~":
                return re.match(rule[1:], instruction)

        return rule == instruction


class Capstone(Disassembler):
    def __init__(self, mode, **kwargs):
        super(Capstone, self).__init__(mode, **kwargs)

        if self.mode == "I386":
            self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        elif self.mode == "AMD64":
            self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        elif self.mode == "MIPS":
            self.cs = capstone.Cs(capstone.CS_ARCH_MIPS, capstone.CS_MODE_32 +
                                  capstone.CS_MODE_BIG_ENDIAN)
        # This is not really supported yet.
        elif self.mode == "ARM":
            self.cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        else:
            raise NotImplementedError(
                "No disassembler available for this arch.")

        self.cs.detail = True
        self.cs.skipdata_setup = ("db", None, None)
        self.cs.skipdata = True

    def disassemble(self, data, offset):
        for insn in self.cs.disasm(data, int(offset)):
            yield CapstoneInstruction(insn, session=self.session,
                                      address_space=self.address_space)


class Disassemble(plugin.TypedProfileCommand, plugin.Command):
    """Disassemble the given offset."""

    __name = "dis"

    __args = [
        dict(name="offset", type="SymbolAddress", positional=True,
             help="An offset to disassemble. This can also be the name of "
             "a symbol with an optional offset. For example: "
             "tcpip!TcpCovetNetBufferList."),

        dict(name="address_space", type="AddressSpace",
             help="The address space to use."),

        dict(name="length", type="IntParser",
             help="The number of instructions (lines) to disassemble."),

        dict(name="end", type="IntParser",
             help="The end address to disassemble up to."),

        dict(name="mode", default=None,
             choices=["I386", "AMD64", "MIPS"], type="Choices",
             help="Disassemble Mode (AMD64 or I386). Defaults to 'auto'."),

        dict(name="branch", default=False, type="Boolean",
             help="If set we follow all branches to cover all code."),

        dict(name="canonical", default=False, type="Boolean",
             help="If set emit canonical instructions. These can be used to "
             "develop signatures."),
    ]

    table_header = [
        dict(type="TreeNode", name="address",
             width=20, child=dict(style="address")),
        dict(name="rel", style="address", width=5),
        dict(name="opcode", width=20),
        dict(name="instruction", width=40),
        dict(name="comment"),
    ]

    def __init__(self, *args, **kwargs):
        super(Disassemble, self).__init__(*args, **kwargs)

        # If length is not specified only disassemble one pager of output.
        self.length = self.plugin_args.length
        if self.length is None:
            self.length = self.session.GetParameter("paging_limit", 50)

        # If end is specified, keep going until we hit the end.
        if self.plugin_args.end is not None:
            self.length = 2**62

        # If we are doing branch analysis we can not suspend this plugin. We
        # must do everything all the time.
        if self.plugin_args.branch:
            self.length = 2**62

        # All the visited addresses (for branch analysis).
        self._visited = set()

        self.offset = self.plugin_args.offset

    def disassemble(self, offset, depth=0):
        """Disassemble the number of instructions required.

        Yields:
          A tuple of (Address, Opcode, Instructions).
        """
        # Disassemble the data one page at the time.
        func = Function(offset=offset, vm=self.plugin_args.address_space,
                        session=self.session, mode=self.plugin_args.mode)

        for instruction in func.disassemble(self.length):
            offset = instruction.address

            if offset in self._visited:
                return

            # Exit condition can be specified by length.
            if (self.length is not None and
                    len(self._visited) > self.length):
                return

            # Exit condition can be specified by end address.
            if self.plugin_args.end and offset > self.plugin_args.end:
                return

            # Yield this data.
            yield depth, instruction

            # If the user asked for full branch analysis we follow all
            # branches. This gives us full code coverage for a function - we
            # just disassemble until the function exists from all branches.
            if self.plugin_args.branch:
                self._visited.add(offset)

                # A return stops this branch.
                if instruction.is_return():
                    return

                target = instruction.target
                if target:
                    # Start disassembling the branch. When the branch is
                    # exhausted we resume disassembling the continued
                    # branch.
                    for x in self.disassemble(target, depth=depth+1):
                        yield x

                    # A JMP stops disassembling this branch. This happens with
                    # tail end optimization where a JMP would meet a RET which
                    # unwinds past the JMP.
                    if instruction.mnemonic.startswith("jmp"):
                        return

    def render_canonical(self, renderer):
        """Renders a canonical description of each instruction.

        Canonical descriptions are machine readable representations of the
        instruction which can be used to write disassembler signatures.
        """
        # If length nor end are specified only disassemble one pager output.
        if self.plugin_args.end is None and self.plugin_args.length is None:
            self.length = self.session.GetParameter("paging_limit") - 5

        renderer.table_header([
            ('Instruction', "instruction", ''),
        ], suppress_headers=True)

        for _, instruction in self.disassemble(self.offset):
            renderer.table_row(instruction.GetCanonical())

    def render(self, renderer, **options):
        """Disassemble code at a given address.

        Disassembles code starting at address for a number of bytes
        given by the length parameter (default: 128).

        Note: This feature requires capstone, available at
            http://www.capstone-engine.org/

        The mode is '32bit' or '64bit'. If not supplied, the disassembler
        mode is taken from the profile.
        """
        if self.plugin_args.canonical:
            return self.render_canonical(renderer, **options)

        return super(Disassemble, self).render(renderer, **options)

    def collect(self):
        self._visited.clear()

        offset = None
        for depth, instruction in self.disassemble(self.offset):
            offset = instruction.address

            relative = None
            resolver = self.session.address_resolver
            if resolver:
                (f_offset, f_names) = resolver.get_nearest_constant_by_address(
                    offset)

                f_name = ", ".join(f_names)
                self.session.report_progress(
                    "Disassembled %s: 0x%x", f_name, offset)

                if offset - f_offset == 0:
                    yield dict(
                        address="------ %s ------\n" % f_name,
                        annotation=True)

                if offset - f_offset < 0x1000:
                    relative = offset - f_offset

            yield dict(address=instruction.address,
                       rel=relative,
                       opcode=instruction.hexbytes,
                       instruction=instruction.op_str,
                       comment=instruction.comment, depth=depth)

        # Continue from where we left off when the user calls us again with the
        # v() plugin.
        self.offset = offset


class TestDisassemble(testlib.SimpleTestCase):
    PARAMETERS = dict(
        # We want to test symbol discovery via export table detection so turn it
        # on.
        commandline=("dis --length %(length)s %(func)s "
                     "--name_resolution_strategies Export"),
        func=0x805031be,
        length=20
        )


class Function(obj.BaseAddressComparisonMixIn, obj.BaseObject):
    """A base object representing code snippets."""

    def __init__(self, mode=None, args=None, **kwargs):
        super(Function, self).__init__(**kwargs)
        self.args = args
        if mode is None:
            mode = self.obj_context.get("mode")

        if mode is None:
            # Autodetect disassembling mode
            highest_usermode_address = self.obj_session.GetParameter(
                "highest_usermode_address")

            # We are disassembling user space.
            if self.obj_offset < highest_usermode_address:
                mode = self.obj_session.GetParameter(
                    "process_context").address_mode

        # fall back to the kernel's mode.
        if not mode:
            mode = self.obj_session.profile.metadata("arch") or "I386"

        self.dis = Capstone(mode, address_space=self.obj_vm,
                            session=self.obj_session)
        self.mode = mode

    def __int__(self):
        return self.obj_offset

    def __hash__(self):
        return self.obj_offset + hash(self.obj_vm)

    def __unicode__(self):
        if self.mode == "AMD64":
            format_string = "%0#14x  %s"
        else:
            format_string = "%0#10x  %s"

        result = []
        for instruction in self.disassemble():
            result.append(format_string % (
                instruction.address, instruction.text))

        return "\n".join(result)

    def __iter__(self):
        return iter(self.disassemble())

    def __getitem__(self, item):
        for i, x in enumerate(self.disassemble()):
            if i == item:
                return x

    def Rewind(self, length=0, align=True):
        """Returns another function which starts before this function.

        If align is specified, we increase the length repeatedly until the
        new function disassebles exactly to the same offset of this
        function.
        """
        while 1:
            offset = self.obj_offset - length
            result = self.obj_profile.Function(vm=self.obj_vm, offset=offset)
            if not align:
                return result

            for instruction in result.disassemble(instructions=length):
                # An exact match.
                if instruction.address == self.obj_offset:
                    return result

                # We overshot ourselves, try again.
                if instruction.address > self.obj_offset:
                    length += 1
                    break

    def disassemble(self, instructions=10):
        """Generate some instructions."""
        count = 0
        buffer_offset = offset = self.obj_offset
        while 1:
            # By default read 2 pages.
            data = self.obj_vm.read(buffer_offset, 0x2000)

            for instruction in self.dis.disassemble(data, buffer_offset):
                offset = instruction.address

                # If we disassemble past one page, we read another two
                # pages. This guarantees that we have enough data for full
                # instructions.
                if offset - buffer_offset > 0x1000:
                    buffer_offset = offset
                    break

                yield instruction
                count += 1

                if count > instructions:
                    return

            buffer_offset = offset


# Register the Function class in all profiles.
obj.Profile.COMMON_CLASSES["Function"] = Function
