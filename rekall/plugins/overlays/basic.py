# Rekall Memory Forensics
#
# Copyright 2013 Google Inc. All Rights Reserved.
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
import datetime
import distorm3
import pytz
import re
import socket
import struct

from rekall import config
from rekall import obj
from rekall import utils
from rekall.plugins.overlays import native_types


config.DeclareOption(
    "--timezone", default="UTC", group="Interface",
    help="Timezone to output all times (e.g. Australia/Sydney).")




class String(obj.StringProxyMixIn, obj.NativeType):
    """Class for dealing with Null terminated C Strings.

    Note that these strings are _not_ text strings - they are effectively bytes
    arrays and therefore are not encoded in any particular unicode encoding.
    """
    def __init__(self, length=1024, term="\x00", **kwargs):
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
        data = vm.read(self.obj_offset, self.length)
        if self.term is not None:
            left, sep, _ = data.partition(self.term)
            data = left + sep

        return data

    def write(self, data):
        return self.obj_vm.write(self.obj_offset, data)

    def proxied(self):
        """ Return an object to be proxied """
        return self.v()

    def __str__(self):
        # Remove any null termination chars.
        return self.v().rstrip("\x00")

    def __unicode__(self):
        return self.v().decode("utf8", "replace").split("\x00")[0] or u""

    def __getitem__(self, *args):
        return unicode(self).__getitem__(*args)

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


class Signature(String):
    """A string forming a signature."""
    def __init__(self, value=None, **kwargs):
        super(Signature, self).__init__(length=len(value), term=None,
                                        **kwargs)
        self.signature = value

    def is_valid(self):
        return self.v() == self.signature


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

    def __repr__(self):
        value = str(self)
        elide = ""
        if len(value) > 50:
            elide = "..."
            value = value[:50]

        return "%s (%s%s)" % (super(UnicodeString, self).__repr__(),
                              value, elide)

    def size(self):
        return len(self.v()) * 2
        # This will only work if the encoding and decoding are equivalent.
        # return len(self.v().encode(self.encoding, 'ignore'))

    def write(self, data):
        return self.obj_vm.write(
            self.obj_offset, data.encode(self.encoding, "ignore"))


class Flags(obj.NativeType):
    """ This object decodes each flag into a string """
    ## This dictionary maps a string mask name to an integer mask.
    maskmap = None

    def __init__(self, bitmap=None, maskmap=None,
                 target="unsigned long", target_args=None, **kwargs):
        super(Flags, self).__init__(**kwargs)
        self.maskmap = maskmap or {}
        if bitmap:
            for k, v in bitmap.items():
                self.maskmap[k] = 1 << v

        self.target = target
        self.target_obj = self.obj_profile.Object(
            target, offset=self.obj_offset, vm=self.obj_vm,
            context=self.obj_context, **(target_args or {}))

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
    """Enumeration class for handling multiple meanings for a single value"""

    def __init__(self, choices=None, enum_name=None,
                 target="unsigned long", target_args=None, value=None,
                 default=None, **kwargs):
        """Construct an enumeration instance.

        The enumeration is constructed over the top of a target (which is
        assumed to produce an integer value). The value of the target is then
        looked up in the choices. Note that the enumeration is treated as an
        integer.

        Args:
          choices: A dict of int values (keys) and names (values).

          enum_name: If provided, the choices dict is retrieved from the
            profile's constant area. This avoids the profile generator from
            having to make copies of the enum choices for each field which uses
            the same enum.

          target: The target type which we overlay on.

          value: Usually the value is parsed from the address space, but if the
            value parameter is provided, we initialize from this value.

          default: If the underlying integer does not appear in the choices
            dict, we use this default value.
        """
        super(Enumeration, self).__init__(**kwargs)

        if enum_name:
            choices = self.obj_profile.get_enum(enum_name) or {}

        if callable(choices):
            choices = choices(self.obj_parent)
        elif not choices:
            choices = {}

        # Force the keys to be integers to trap misuse.
        self.choices = dict((int(x), y) for x, y in choices.items())
        self.default = default
        if callable(value):
            value = value(self.obj_parent)

        self.value = value
        if value is None:
            self.target = target
            self.target_obj = self.obj_profile.Object(
                target, offset=self.obj_offset,
                vm=self.obj_vm, context=self.obj_context,
                **(target_args or {}))

    def size(self):
        return self.target_obj.size()

    def v(self, vm=None):
        if self.value is None:
            return self.target_obj.v(vm=vm)

        return self.value

    def write(self, data):
        return self.target_obj.write(data)

    def __str__(self):
        value = self.v()
        return self.choices.get(value, self.default) or (
            "UNKNOWN (%s)" % str(value))

    def __eq__(self, other):
        if isinstance(other, (int, long)):
            return self.v() == other

        # Search the choices.
        for k, v in self.choices.iteritems():
            if v == other:
                return self.v() == k

    def __repr__(self):
        return "%s (%s)" % (super(Enumeration, self).__repr__(),
                            self.__str__())


class Ipv4Address(obj.NativeType):
    """Provides proper output for Ipv4Address objects"""

    def __init__(self, **kwargs):
        super(Ipv4Address, self).__init__(**kwargs)

        # Ipv4Address is always a 32 bit int.
        self.format_string = "<I"

    def v(self, vm=None):
        value = super(Ipv4Address, self).v(vm=vm)
        return socket.inet_ntoa(struct.pack("<I", value))


class Ipv6Address(obj.NativeType):
    """Provides proper output for Ipv6Address objects"""
    def __init__(self, **kwargs):
        super(Ipv6Address, self).__init__(**kwargs)
        # Ipv4Address is always a 128 bit int.
        self.format_string = "16s"

    def v(self, vm=None):
        return utils.inet_ntop(socket.AF_INET6, obj.NativeType.v(self))


class MacAddress(obj.NativeType):
    """A MAC address."""
    def __init__(self, **kwargs):
        super(MacAddress, self).__init__(**kwargs)
        # Ipv4Address is always a 128 bit int.
        self.format_string = "6s"

    def v(self, vm=None):
        return ":".join(
            ["{0:02X}".format(ord(y)) for y in super(MacAddress, self).v()])


class ListMixIn(object):
    """A helper for following lists."""
    _forward = "Flink"
    _backward = "Blink"

    def dereference_as(self, type, member, vm=None):
        """Recasts the list entry as a member in a type, and return the type.

        Args:
           type: The name of this Struct type.
           member: The name of the member of this Struct.
           address_space: An optional address space to switch during
              deferencing.
        """
        offset = self.obj_profile.get_obj_offset(type, member)

        item = self.obj_profile.Object(
            type_name=type, offset=self.obj_offset - offset,
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
        Flink = self.m(self._forward).dereference()
        Flink.find_all_lists(seen)

        Blink = self.m(self._backward).dereference()
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
        result1 = self.m(self._forward).dereference_as(
            self.obj_type, vm=vm).m(self._backward).dereference_as(
            self.obj_type)

        if not result1:
            return obj.NoneObject("Flink not valid.")

        result2 = self.Blink.dereference_as(self.obj_type, vm=vm).m(
            self._forward).dereference_as(self.obj_type)

        if result1 != result2:
            return obj.NoneObject("Flink and Blink not consistent.")

        return result1

    def __nonzero__(self):
        ## List entries are valid when both Flinks and Blink are valid
        return bool(self.m(self._forward)) or bool(self.m(self._backward))

    def __iter__(self):
        return self.list_of_type(self.obj_parent.obj_type, self.obj_name)


class _LIST_ENTRY(ListMixIn, obj.Struct):
    """ Adds iterators for _LIST_ENTRY types """



class UnixTimeStamp(obj.NativeType):
    """A unix timestamp (seconds since the epoch)."""

    def __init__(self, format_string="I", **kwargs):
        super(UnixTimeStamp, self).__init__(
            format_string=format_string, **kwargs)

    def __nonzero__(self):
        return self.v() != 0

    def display_datetime(self, dt, custom_tz=None):
        """Returns a string from a datetime according to the display
        TZ (or a custom one"""
        timeformat = "%Y-%m-%d %H:%M:%S%z"

        # Control our behaviour according to the session preferences.
        session = self.obj_profile.session

        # Default to display in UTC.
        try:
            timezone_name = "UTC"
            if custom_tz:
                timezone_name = custom_tz
            elif session and session.GetParameter("timezone"):
                timezone_name = session.GetParameter("timezone")

            timezone = pytz.timezone(timezone_name)
        except pytz.UnknownTimeZoneError:
            # Cant undestand the timezone - use UTC
            timezone = pytz.UTC

        local_datetime = timezone.normalize(dt.astimezone(timezone))

        return local_datetime.strftime(timeformat)

    def __add__(self, other):
        if isinstance(other, (float, int, long)):
            return UnixTimeStamp(
                value=self.v() + other, profile=self.obj_profile)

        raise NotImplementedError

    def __str__(self):
        if not self:
            return "-"

        dt = self.as_datetime()
        if dt:
            return self.display_datetime(dt)

        return "-"

    def __repr__(self):
        return "%s (%s)" % (super(UnixTimeStamp, self).__repr__(),
                            str(self))

    def as_datetime(self):
        try:
            # Return a data time object in UTC.
            dt = datetime.datetime.utcfromtimestamp(
                self.v()).replace(tzinfo=pytz.UTC)
        except ValueError, e:
            return obj.NoneObject("Datetime conversion failure: " + str(e))

        return dt


class timeval(UnixTimeStamp, obj.Struct):

    def v(self, vm=None):
        return float(self.m("tv_sec")) + self.m("tv_usec")/1e6



class WinFileTime(UnixTimeStamp):
    """Class for handling Windows Time Stamps"""

    def __init__(self, is_utc=False, **kwargs):
        super(WinFileTime, self).__init__(format_string="q", **kwargs)
        self.is_utc = is_utc

    def as_windows_timestamp(self):
        return super(WinFileTime, self).v()

    def v(self, vm=None):
        value = self.as_windows_timestamp()

        unix_time = value / 10000000 - 11644473600
        if unix_time < 0:
            unix_time = 0

        return unix_time


class ThreadCreateTimeStamp(WinFileTime):
    """Handles ThreadCreateTimeStamps which are bit shifted WinFileTimes"""

    def as_windows_timestamp(self):
        return super(ThreadCreateTimeStamp, self).as_windows_timestamp() >> 3


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


class Function(obj.BaseAddressComparisonMixIn, obj.BaseObject):
    """An object representing code snippets."""

    def __init__(self, mode=None, args=None, **kwargs):
        super(Function, self).__init__(**kwargs)
        self.args = args
        if mode is None:
            self.mode = self.obj_profile.metadata("arch")

        if self.mode == "I386":
            self.distorm_mode = distorm3.Decode32Bits
        elif self.mode == "AMD64":
            self.distorm_mode = distorm3.Decode64Bits
        else:
            raise RuntimeError("Invalid mode %s" % self.mode)

    def __int__(self):
        return self.obj_offset

    def __hash__(self):
        return self.obj_offset + hash(self.obj_vm)

    def __str__(self):
        result = []
        for data in self.Disassemble():
            result.append("0x%08X %20s %s" % data)

        return "\n".join(result)

    def _call_or_unc_jmp(self, op):
        """Determine if an instruction is a call or an
        unconditional jump

        @param op: a distorm3 Op object
        """
        return (
            (op.flowControl == 'FC_CALL' and op.mnemonic == "CALL") or
            (op.flowControl == 'FC_UNC_BRANCH' and op.mnemonic == "JMP"))

    def DetectJumps(self, size=1000):
        """A generator for operations that look like jumps.

        Disassemble a block of data and yield possible
        calls to imported functions. We're looking for
        instructions such as these:

        x86:
        CALL DWORD [0x1000400]
        JMP  DWORD [0x1000400]

        x64:
        CALL QWORD [RIP+0x989d]

        On x86, the 0x1000400 address is an entry in the
        IAT or call table. It stores a DWORD which is the
        location of the API function being called.

        On x64, the 0x989d is a relative offset from the
        current instruction (RIP).

        Yields:
          A tuple of source, destination Function objects which are the
          targets for jumps.
        """
        for op in self.Decompose(size=size):
            iat_loc = None

            if self.mode == 'I386':
                if (self._call_or_unc_jmp(op) and
                    op.operands[0].type == 'AbsoluteMemoryAddress'):
                    iat_loc = (op.operands[0].disp & 0xffffffff)
            else:
                if (self._call_or_unc_jmp(op) and
                    'FLAG_RIP_RELATIVE' in op.flags and
                    op.operands[0].type == 'AbsoluteMemory'):
                    iat_loc = op.address + op.size + op.operands[0].disp

            if iat_loc:
                # This is the address being called
                func_pointer = self.obj_profile.Pointer(
                    target="Function", offset=iat_loc, vm=self.obj_vm,
                    name="Function")

                yield op.address, iat_loc, func_pointer

    def Decompose(self, instructions=10, size=None):
        """A generator for instructions of this object.

        How much to decompose is can be specified either by the total number
        of instructions or the total size to decompose.

        Args:
          instructions: Stop after reaching this many instructions. The
            parameter is ignored when size is specified.

          size: Stop after decoding this much data. If specified we ignore
            the instructions parameter.
        """
        overlap = 0x1000
        data = ''
        offset = self.obj_offset
        count = 0

        while 1:
            data = self.obj_vm.read(offset, overlap)

            # This could happen if we hit an unmapped page - we just
            # abort.
            if not data:
                return

            for op in distorm3.Decompose(offset, data, self.distorm_mode):
                if op.address - offset > len(data) - 40:
                    break

                if not op.valid:
                    continue

                # Exit if we read as much as was required.
                if size is not None and op.address - self.obj_offset > size:
                    return

                yield op

                if size is None and count > instructions:
                    return

                count += 1

            offset = op.address

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

            for offset, _, _ in result.Disassemble(instructions=length):
                # An exact match.
                if offset == self.obj_offset:
                    return result

                # We overshot ourselves, try again.
                if offset > self.obj_offset:
                    length += 1
                    break

    def Disassemble(self, instructions=10):
        """Generate some instructions."""
        overlap = 0x100
        data = ''
        offset = self.obj_offset
        count = 0

        while True:
            if offset - self.obj_offset > len(data) - 40:
                data = self.obj_vm.read(offset, overlap)

            iterator = distorm3.DecodeGenerator(
                offset, data, self.distorm_mode)
            for (offset, _size, instruction, hexdump) in iterator:
                yield offset, hexdump, instruction
                count += 1
                if count >= instructions:
                    return


# We define three kinds of basic profiles, a 32 bit one and two 64 bit ones.
class Profile32Bits(obj.Profile):
    """Basic profile for 32 bit systems."""
    METADATA = dict(
        arch="I386",
        data_model="ILP32"
        )

    @classmethod
    def Initialize(cls, profile):
        super(Profile32Bits, cls).Initialize(profile)
        profile.add_classes(native_types.ILP32)
        profile.add_constants(PoolAlignment=8, MAX_FAST_REF=7,
                              MaxPointer=2**32-1)


class ProfileLLP64(obj.Profile):
    """Basic profile for 64 bit Windows systems."""
    METADATA = dict(
        arch="AMD64",
        data_model="LLP64"
        )

    @classmethod
    def Initialize(cls, profile):
        super(ProfileLLP64, cls).Initialize(profile)
        profile.add_classes(native_types.LLP64)
        profile.add_constants(PoolAlignment=16, MAX_FAST_REF=15,
                              MaxPointer=2**48-1)

class ProfileLP64(obj.Profile):
    """Basic profile for 64 bit Linux systems."""
    METADATA = dict(
        arch="AMD64",
        data_model="LP64"
        )

    @classmethod
    def Initialize(cls, profile):
        super(ProfileLP64, cls).Initialize(profile)
        profile.add_classes(native_types.LP64)


common_overlay = {
    'LIST_ENTRY32' : [0x8, {
            'Flink' : [0x0, ['pointer', ['LIST_ENTRY32']]],
            'Blink' : [0x4, ['pointer', ['LIST_ENTRY32']]],
            }],
    'LIST_ENTRY64' : [0x10, {
            'Flink' : [0x0, ['pointer', ['LIST_ENTRY64']]],
            'Blink' : [0x8, ['pointer', ['LIST_ENTRY64']]],
            }]}


class BasicClasses(obj.Profile):
    """Basic profile which introduces the basic classes."""

    @classmethod
    def Initialize(cls, profile):
        super(BasicClasses, cls).Initialize(profile)

        profile.add_classes({
            'String': String,
            "Signature": Signature,
            'UnicodeString': UnicodeString,
            'Flags': Flags,
            'Enumeration': Enumeration,
            'Ipv4Address': Ipv4Address,
            'Ipv6Address': Ipv6Address,
            'MacAddress': MacAddress,
            '_LIST_ENTRY': _LIST_ENTRY,
            'LIST_ENTRY32': _LIST_ENTRY,
            'LIST_ENTRY64': _LIST_ENTRY,
            'WinFileTime': WinFileTime,
            'ThreadCreateTimeStamp': ThreadCreateTimeStamp,
            'UnixTimeStamp': UnixTimeStamp, 'timeval': timeval,
            "IndexedArray": IndexedArray,
            'Function': Function,
            })
        profile.add_constants(default_text_encoding="utf-16-le")
        profile.add_overlay(common_overlay)


def container_of(ptr, type, member):
    """cast a member of a structure out to the containing structure.

    http://lxr.free-electrons.com/source/include/linux/kernel.h?v=3.7#L677
    """
    offset = ptr.v() - ptr.obj_profile.get_obj_offset(type, member)
    return ptr.obj_profile.Object(type, offset=offset, vm=ptr.obj_vm)


