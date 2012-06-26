# Volatility
# Copyright (C) 2012 Michael Cohen <scudette@gmail.com>
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

"""This module provides the primitives needed to disassemble code using distorm3."""
import distorm3

from volatility import obj
from volatility import plugin


class Instruction(obj.BaseObject):
    """An object which represents a single assembly instruction."""

    def __init__(self, instruction_set=None, **kwargs):
        """Decode a single instruction from the current point.

        Args:
          instruction_set: "32bit" or "64bit" or taken from the
             profile.metadata("memroy_model")
        """


class Disassemble(plugin.Command):
    """Disassemble the given address space."""

    __name = "dis"

    def __init__(self, address_space=None, offset=None, length=80, mode=None,
                 **kwargs):
        super(Disassemble, self).__init__(**kwargs)
        self.address_space = address_space
        self.offset = offset
        self.length = length
        self.mode = mode or self.session.profile.metadata("memory_model", "32bit")
        if self.mode == "32bit":
            self.distorm_mode = distorm3.Decode32Bits
        else:
            self.distorm_mode = distorm3.Decode64Bits

    def render(self, renderer):
        """Disassemble code at a given address.

        Disassembles code starting at address for a number of bytes
        given by the length parameter (default: 128).

        Note: This feature requires distorm, available at
            http://www.ragestorm.net/distorm/

        The mode is '32bit' or '64bit'. If not supplied, the disasm
        mode is taken from the profile.
        """
        data = self.address_space.zread(self.offset, self.length)
        iterable = distorm3.DecodeGenerator(self.offset, data, self.distorm_mode)

        renderer.table_header([('Address', '[addrpad]'),
                               ('Op Codes', '<20'),
                               ('Instruction', '<40')])
        for (offset, _size, instruction, hexdump) in iterable:
            renderer.table_row(offset, hexdump, instruction)

