# Volatility
#
# Authors:
# Copyright (C) 2012 Michael Cohen <scudette@users.sourceforge.net>
# Mike Auty <mike.auty@gmail.com>
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

""" This file defines some basic types which might be useful for many
OS's
"""
import copy
import datetime
import logging
import re
import socket
import struct

from volatility import obj
from volatility import constants
from volatility import timefmt
from volatility import utils
from volatility.plugins.overlays import native_types


class String(obj.StringProxyMixIn, obj.NativeType):
    """Class for dealing with Null terminated C Strings.

    Note that these strings are _not_ text strings - they are effectively bytes
    arrays and therefore are not encoded in any particular unicode encoding.
    """
    def __init__(self, length = 1024, term="\x00", **kwargs):
        """Constructor.

        Args:
           length: The maximum length of the string.

           terminator: The terminator for this string. If None, there will be no
              checking for null terminations (Pure character array).
        """
        super(String, self).__init__(**kwargs)

        ## Allow length to be a callable:
        if callable(length):
            length = length(self.obj_parent)

        self.term = term
        self.length = int(length)

    def startswith(self, other):
        return str(self).startswith(other)

    def v(self, vm=None):
        vm = vm or self.obj_vm
        data = vm.zread(self.obj_offset, self.length)
        if self.term is not None:
            left, sep, _ = data.partition(self.term)
            data = left + sep

        return data

    def proxied(self, name):
        """ Return an object to be proxied """
        return self.v()

    def __str__(self):
        # Remove any null termination chars.
        return self.v().rstrip("\x00")

    def __unicode__(self):
        return self.v().decode("utf8", "replace").split("\x00")[0] or u""

    def __add__(self, other):
        """Set up mappings for concat"""
        return str(self) + other

    def __radd__(self, other):
        """Set up mappings for reverse concat"""
        return other + str(self)

    def __eq__(self, other):
        return unicode(self) == utils.SmartUnicode(other)

    def size(self):
        """This is equivalent to strlen()."""
        # The length is really determined by the terminator here.
        return len(self.v())


class UnicodeString(String):
    """A class for dealing with encoded text strings.

    Text strings are always encoded in some way in memory. The specific way of
    encoding them is called the "encoding" - for example usually (but not
    always) in windows the encoding is called "utf16", while on linux its
    usually "utf8".

    By default we take the encoding from the profile constant
    "default_text_encoding".
    """
    def __init__(self, encoding=None, **kwargs):
        super(UnicodeString, self).__init__(**kwargs)
        self.encoding = encoding or self.obj_profile.get_constant(
            'default_text_encoding')


    def v(self, vm=None):
        vm = vm or self.obj_vm

        data = vm.read(self.obj_offset, self.length)

        # Try to interpret it as a unicode encoded string.
        data = data.decode(self.encoding, "ignore")

        # Now null terminate if needed.
        if self.term is not None:
            left, sep, _ = data.partition(self.term)
            data = left + sep

        return data

    def __unicode__(self):
        return self.v().split("\x00")[0] or u""

    def __str__(self):
        """This function returns an encoded string in utf8."""
        return super(UnicodeString, self).__str__().encode("utf8")

    def size(self):
        # This will only work if the encoding and decoding are equivalent.
        return len(self.v().encode(self.encoding, 'ignore'))


class Flags(obj.NativeType):
    """ This object decodes each flag into a string """
    ## This dictionary maps a string mask name to an integer mask.
    maskmap = None

    def __init__(self, bitmap = None, maskmap = None, target = "unsigned long",
                 **kwargs):
        super(Flags, self).__init__(**kwargs)
        self.maskmap = maskmap or {}
        if bitmap:
            for k, v in bitmap.items():
                self.maskmap[k] = 1 << v

        self.target = target
        self.target_obj = self.obj_profile.Object(
            target, offset=self.obj_offset, vm=self.obj_vm,
            context=self.obj_context)

    def v(self, vm=None):
        return self.target_obj.v(vm=vm)

    def __str__(self):
        result = []
        value = self.v()
        for k, v in sorted(self.maskmap.items()):
            if value & v:
                result.append(k)

        return ', '.join(result)

    def __repr__(self):
        abridged = str(self)
        if len(abridged) > 10:
            abridged = abridged[:40] + " ..."

        return "%s (%s)" % (super(Flags, self).__repr__(), abridged)

    def __getattr__(self, attr):
        mask = self.maskmap.get(attr)
        if not mask:
            return obj.NoneObject("Mask {0} not known".format(attr))

        return self.v() & mask


class Enumeration(obj.NativeType):
    """Enumeration class for handling multiple possible meanings for a single value"""

    def __init__(self, choices = None, target = "unsigned long", value=None,
                 default = None, **kwargs):
        super(Enumeration, self).__init__(**kwargs)
        self.choices = choices or {}
        self.default = default
        if callable(value):
            value = value(self.obj_parent)

        self.value = value
        if value is None:
            self.target = target
            self.target_obj = self.obj_profile.Object(
                target, offset=self.obj_offset, vm=self.obj_vm, context=self.obj_context)

    def v(self, vm=None):
        if self.value is None:
            return self.target_obj.v(vm=vm)

        return self.value

    def write(self, data):
        return self.target_obj.write(data)

    def __str__(self):
        value = self.v()
        return self.choices.get(value, self.default) or str(value)

    def __eq__(self, other):
        if isinstance(other, int):
            return self.v() == other

        # Search the choices.
        for k, v in self.choices.iteritems():
            if v == other:
                return self.v() == k

    def __repr__(self):
        return "%s (%s)" % (super(Enumeration, self).__repr__(),
                            self.__str__())


class IpAddress(obj.NativeType):
    """Provides proper output for IpAddress objects"""

    def __init__(self, **kwargs):
        super(IpAddress, self).__init__(**kwargs)

        # IpAddress is always a 32 bit int.
        self.format_string = "<I"

    def v(self, vm=None):
        value = super(IpAddress, self).v(vm=vm)
        return socket.inet_ntoa(struct.pack("<I", value))

class Ipv6Address(obj.NativeType):
    """Provides proper output for Ipv6Address objects"""
    def __init__(self, **kwargs):
        super(Ipv6Address, self).__init__(**kwargs)
        # IpAddress is always a 32 bit int.
        self.format_string = "16s"

    def v(self):
        return utils.inet_ntop(socket.AF_INET6, obj.NativeType.v(self))


class _LIST_ENTRY(obj.CType):
    """ Adds iterators for _LIST_ENTRY types """

    def dereference_as(self, type, member, vm=None):
        """Recasts the list entry as a member in a type, and return the type.

        Args:
           type: The name of this CType type.
           member: The name of the member of this CType.
           address_space: An optional address space to switch during
              deferencing.
        """
        offset = self.obj_profile.get_obj_offset(type, member)

        item = self.obj_profile.Object(
            theType=type, offset=self.obj_offset - offset,
            vm=vm or self.obj_vm, parent=self.obj_parent,
            name=type, context=self.obj_context)

        return item

    def find_all_lists(self, seen):
        """Follows all the list entries starting from lst.

        We basically convert the list to a tree and recursively search it for
        new nodes. From each node we follow the Flink and then the Blink. When
        we see a node we already have, we backtrack. This allows us to find
        nodes which do not satisfy the relation (Due to smear):

        x.Flink.Blink = x
        """
        if not self.is_valid():
            return
        elif self in seen:
            return

        seen.append(self)
        Flink = self.Flink.dereference()
        Flink.find_all_lists(seen)

        Blink = self.Blink.dereference()
        Blink.find_all_lists(seen)

    def list_of_type(self, type, member):
        result = []
        self.find_all_lists(result)

        # We traverse all the _LIST_ENTRYs we can find, and cast them all back
        # to the required member.
        for lst in result:
            # Skip ourselves in this (list_of_type is usually invoked on a list
            # head).
            if lst.obj_offset == self.obj_offset:
                continue

            task = lst.dereference_as(type, member)
            if task:
                # Only yield valid objects (In case of dangling links).
                yield task

    def reflect(self, vm=None):
        """Reflect this list element by following its Flink and Blink.

        This is basically the same as Flink.Blink except that it also checks
        Blink.Flink. It also ensures that Flink and Blink are dereferences to
        the correct type in case the vtypes do not specify them as pointers.

        Returns:
          the result of Flink.Blink.
        """
        result1 = self.Flink.dereference_as(self.obj_type, vm=vm).Blink.dereference_as(
            self.obj_type)

        if not result1:
            return obj.NoneObject("Flink not valid.")

        result2 = self.Blink.dereference_as(self.obj_type, vm=vm).Flink.dereference_as(
            self.obj_type)

        if result1 != result2:
            return obj.NoneObject("Flink and Blink not consistent.")

        return result1

    def __nonzero__(self):
        ## List entries are valid when both Flinks and Blink are valid
        return bool(self.Flink) or bool(self.Blink)

    def __iter__(self):
        return self.list_of_type(self.obj_parent.obj_type, self.obj_name)


class UnixTimeStamp(obj.NativeType):
    """A unix timestamp (seconds since the epoch)."""
    is_utc = True

    def __init__(self, **kwargs):
        super(UnixTimeStamp, self).__init__(format_string = "I", **kwargs)

    def __nonzero__(self):
        return self.v() != 0

    def __str__(self):
        if not self:
            return "-"

        dt = self.as_datetime()
        if dt != None:
            return str(timefmt.display_datetime(dt))

        return "-"

    def as_datetime(self):
        try:
            dt = datetime.datetime.utcfromtimestamp(self.v())
            if self.is_utc:
                # Only do dt.replace when dealing with UTC
                dt = dt.replace(tzinfo = timefmt.UTC())
        except ValueError, e:
            return obj.NoneObject("Datetime conversion failure: " + str(e))
        return dt


class WinTimeStamp(UnixTimeStamp):
    """Class for handling Windows Time Stamps"""

    def __init__(self, is_utc = False, **kwargs):
        self.is_utc = is_utc
        obj.NativeType.__init__(self, format_string = "q", **kwargs)

    def __repr__(self):
        return "%s (%s)" % (super(WinTimeStamp, self).__repr__(),
                            str(self))

    def windows_to_unix_time(self, windows_time):
        """
        Converts Windows 64-bit time to UNIX time

        @type  windows_time:  Integer
        @param windows_time:  Windows time to convert (64-bit number)

        @rtype  Integer
        @return  UNIX time
        """
        if(windows_time == 0):
            unix_time = 0
        else:
            unix_time = windows_time / 10000000
            unix_time = unix_time - 11644473600

        if unix_time < 0:
            unix_time = 0

        return unix_time

    def as_windows_timestamp(self):
        return super(WinTimeStamp, self).v(self)

    def v(self, vm=None):
        value = self.as_windows_timestamp()
        return self.windows_to_unix_time(value)


class IndexedArray(obj.Array):
    """An array which can be addressed via constant names."""

    def __init__(self, index_table=None, **kwargs):
        super(IndexedArray, self).__init__(**kwargs)
        self.index_table = index_table or {}
        self.count = len(index_table)

    def __getitem__(self, item):
        # Still support numeric indexes
        if isinstance(item, (int, long)):
            index = item

            # Try to name the object appropriately.
            for k, v in self.index_table.items():
                if v == item:
                    item = k
                    break

        elif item in self.index_table:
            index = self.index_table[item]
        else:
            raise KeyError("Unknown index %s" % item)

        result = super(IndexedArray, self).__getitem__(index)
        result.obj_name = str(item)

        return result


class Function(obj.BaseObject):
    """A volatility object representing code snippets."""

    def __int__(self):
        return self.obj_offset


# If distorm3 is available we can do a few more things.
try:
    import distorm3

    class Function(Function):

        def __init__(self, mode=None, **kwargs):
            super(Function, self).__init__(**kwargs)

            if mode is None:
                self.mode = self.obj_profile.metadata("memory_model")

            if self.mode == "32bit":
                self.distorm_mode = distorm3.Decode32Bits
            else:
                self.distorm_mode = distorm3.Decode64Bits

        def __str__(self):
            result = []
            for data in self.Disassemble():
                result.append("0x%08X %20s %s" % data)

            return "\n".join(result)

        def Search(self, expressions, instruction_limit=100):
            """Search forward for a sequence matching the expressions.

            Args:
              expressions: A list of regular expressions which must all match
                the instruction.
              instruction_limit: The number of instructions to search ahead.

            Returns:
              Another Function object at the matched position or None.
            """
            terms = []
            for e in expressions:
                if isinstance(e, basestring):
                    e = re.compile(e)
                terms.append(e)

            instructions = []
            for offset, _, instruction in self.Disassemble(instruction_limit):
                instructions.append((offset, instruction))

            for i in range(len(instructions)):
                for j in range(len(terms)):
                    print expressions[j], instructions[i][1]
                    if not terms[j].match(instructions[i + j][1]):
                        break
                else:
                    return self.obj_profile.Object(
                        "Function", vm=self.obj_vm, offset=instructions[i][0])

        def __getitem__(self, item):
            for i, x in enumerate(self.Disassemble):
                if i == item:
                    return x

        def Disassemble(self, instructions=10):
            """Generate some instructions."""
            overlap = 0x100
            data = ''
            offset = self.obj_offset
            count = 0

            while True:
                if offset - self.obj_offset > len(data) - 40:
                    data = self.obj_vm.zread(offset, overlap)

                iterator = distorm3.DecodeGenerator(offset, data, self.distorm_mode)
                for (offset, _size, instruction, hexdump) in iterator:
                    yield offset, hexdump, instruction
                    count += 1
                    if count >= instructions:
                        return

except ImportError:
    pass




# We define two kinds of basic profiles, a 32 bit one and a 64 bit one
class Profile32Bits(obj.Profile):
    """Basic profile for 32 bit systems."""
    _md_memory_model = '32bit'

    def __init__(self, **kwargs):
        super(Profile32Bits, self).__init__(**kwargs)
        self.add_classes(native_types.generic_native_types)
        self.add_classes(native_types.x86_native_types)
        self.add_constants(PoolAlignment=8, MAX_FAST_REF=7)


class Profile64Bits(obj.Profile):
    """Basic profile for 64 bit systems."""
    _md_memory_model = '64bit'

    def __init__(self, **kwargs):
        super(Profile64Bits, self).__init__(**kwargs)
        self.add_classes(native_types.generic_native_types)
        self.add_classes(native_types.x64_native_types)
        self.add_constants(PoolAlignment=16, MAX_FAST_REF=15)


class BasicWindowsClasses(obj.Profile):
    """Basic profile which introduces the basic classes."""

    def __init__(self, **kwargs):
        super(BasicWindowsClasses, self).__init__(**kwargs)
        self.add_classes({
            'String': String,
            'UnicodeString': UnicodeString,
            'Flags': Flags,
            'Enumeration': Enumeration,
            'IpAddress': IpAddress,
            'Ipv6Address': Ipv6Address,
            '_LIST_ENTRY': _LIST_ENTRY,
            'LIST_ENTRY32': _LIST_ENTRY,
            'LIST_ENTRY64': _LIST_ENTRY,
            'WinTimeStamp': WinTimeStamp, # WinFileTime.
            'UnixTimeStamp': UnixTimeStamp,
            "IndexedArray": IndexedArray,
            'Function': Function,
            })

        self.add_constants(default_text_encoding="utf-16-le")
