# Volatility
# Copyright (C) 2007,2008 Volatile Systems
#
# Copyright (C) 2005,2006 4tphi Research
# Author: {npetroni,awalters}@4tphi.net (Nick Petroni and AAron Walters)
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

__author__ = ("Michael Cohen <scudette@gmail.com> based on original code "
              "by AAron Walters and Brendan Dolan-Gavitt with contributions "
              "by Mike Auty")

"""
The Volatility object system.

"""
import logging
import sys
import re
import operator
import struct

import copy
from volatility import addrspace
from volatility import registry


class classproperty(property):
    """A property that can be called on classes."""
    def __get__(self, cls, owner):
        return self.fget(owner)


## Curry is now a standard python feature
import functools

Curry = functools.partial

import traceback

def get_bt_string(_e = None):
    return ''.join(traceback.format_stack()[:-2])

class FormatSpec(object):
    def __init__(self, string = '', **kwargs):
        self.fill = ''
        self.align = ''
        self.sign = ''
        self.altform = False
        self.minwidth = -1
        self.precision = -1
        self.formtype = ''

        if string != '':
            self.from_string(string)

        # Ensure we parse the remaining arguments after the string to that they override
        self.from_specs(**kwargs)

    def from_specs(self, fill = None, align = None, sign = None, altform = None,
                   minwidth = None, precision = None, formtype = None):
        ## Allow setting individual elements using kwargs
        if fill is not None:
            self.fill = fill
        if align is not None:
            self.align = align
        if sign is not None:
            self.sign = sign
        if altform is not None:
            self.altform = altform
        if minwidth is not None:
            self.minwidth = minwidth
        if precision is not None:
            self.precision = precision
        if formtype is not None:
            self.formtype = formtype

    def from_string(self, formatspec):
        # Format specifier regular expression
        regexp = "\A(.[<>=^]|[<>=^])?([-+ ]|\(\))?(#?)(0?)(\d*)(\.\d+)?(.)?\Z"

        match = re.search(regexp, formatspec)

        if match is None:
            raise ValueError("Invalid format specification")

        if match.group(1):
            fillalign = match.group(1)
            if len(fillalign) > 1:
                self.fill = fillalign[0]
                self.align = fillalign[1]
            elif fillalign:
                self.align = fillalign

        if match.group(2):
            self.sign = match.group(2)
        if match.group(3):
            self.altform = len(match.group(3)) > 0
        if len(match.group(4)):
            if self.fill == "":
                self.fill = "0"
                if self.align == "":
                    self.align = "="
        if match.group(5):
            self.minwidth = int(match.group(5))
        if match.group(6):
            self.precision = int(match.group(6)[1:])
        if match.group(7):
            self.formtype = match.group(7)

    def to_string(self):
        formatspec = self.fill + self.align + self.sign
        if self.sign == '(':
            formatspec += ')'
        if self.altform:
            formatspec += '#'
        if self.minwidth >= 0:
            formatspec += str(self.minwidth)
        if self.precision >= 0:
            formatspec += '.' + str(self.precision)
        formatspec += self.formtype

        return formatspec

    def __str__(self):
        return self.to_string()

class NoneObject(object):
    """ A magical object which is like None but swallows bad
    dereferences, __getattr__, iterators etc to return itself.

    Instantiate with the reason for the error.
    """
    def __init__(self, reason = '', strict = False):
        # Often None objects are instantiated on purpose so its not really that
        # important to see their reason.
        logging.log(logging.DEBUG / 2, "None object instantiated: %s", reason)
        self.reason = reason
        self.strict = strict
        if strict:
            self.bt = get_bt_string()

    def __str__(self):
        ## If we are strict we blow up here
        if self.strict:
            logging.error("{0}\n{1}".format(self.reason, self.bt))
        else:
            logging.warning("{0}".format(self.reason))

        return ""

    def __repr__(self):
        return "<%s>" % self.reason

    def write(self, data):
        """Write procedure only ever returns False"""
        return False

    ## Behave like an empty set
    def __iter__(self):
        return iter([])

    def __len__(self):
        return 0

    def __format__(self, formatspec):
        formatspec = formatspec.lower().replace("x", "s")
        spec = FormatSpec(string = formatspec, fill = "-", align = ">")
        return format('-', str(spec))

    def __getattr__(self, attr):
        # By returning self for any unknown attribute
        # and ensuring the self is callable, we cover both properties and methods
        # Override NotImplemented functions in object with self
        return self

    def __bool__(self):
        return False

    def __nonzero__(self):
        return False

    def __eq__(self, other):
        return (other is None)

    def __ne__(self, other):
        return not self.__eq__(other)

    ## Make us subscriptable obj[j]
    def __getitem__(self, item):
        return self

    def __call__(self, *arg, **kwargs):
        return self

    def __int__(self):
        return -1

    # These must be defined explicitly,
    # due to the way new style objects bypass __getattr__ for speed
    # See http://docs.python.org/reference/datamodel.html#new-style-special-lookup
    __add__ = __call__
    __sub__ = __call__
    __mul__ = __call__
    __floordiv__ = __call__
    __mod__ = __call__
    __divmod__ = __call__
    __pow__ = __call__
    __lshift__ = __call__
    __rshift__ = __call__
    __and__ = __call__
    __xor__ = __call__
    __or__ = __call__

    __radd__ = __call__
    __rsub__ = __call__
    __rmul__ = __call__
    __rfloordiv__ = __call__
    __rmod__ = __call__
    __rdivmod__ = __call__
    __rpow__ = __call__
    __rlshift__ = __call__
    __rrshift__ = __call__
    __rand__ = __call__
    __rxor__ = __call__
    __ror__ = __call__


class Error(Exception):
    """All object related exceptions come from this one."""


class InvalidOffsetError(Error):
    """Simple placeholder to identify invalid offsets"""

class ProfileError(Error):
    """Errors in setting the profile."""


class BaseObject(object):

    obj_parent = NoneObject("No parent")
    obj_name = NoneObject("No name")

    # We have **kwargs here, but it's unclear if it's a good idea
    # Benefit is objects will never fail with duff parameters
    # Downside is typos won't show up and be difficult to diagnose
    def __init__(self, theType=None, offset=0, vm=None, profile = None,
                 parent = None, name = '', type_name=None, **kwargs):
        """Constructor for Base object.

        Args:

          theType: The name of the type of this object (how is this different
             from the class name?

          offset: The offset within the address space to this object exists.

          vm: The address space this object uses to read itself from.

          profile: The profile this object may use to dereference other
          elements.

          parent: The object which created this object.

          name: The name of this object.

          type_name: The name of this type. This name will override the class
            name and could mean something more meaningful (e.g. NativeType is not
            meaningful).

          kwargs: Arbitrary args this object may accept - these can be passed in
             the vtype language definition.
        """
        if kwargs:
            logging.error("Unknown keyword args {0}".format(kwargs))

        self.obj_type = type_name or theType

        # 64 bit addresses are always sign extended, so we need to clear the top
        # bits.
        self.obj_offset = int(offset) & 0xffffffffffff
        self.obj_vm = vm
        self.obj_parent = parent
        self.obj_name = name
        self.obj_profile = profile

        if not self.obj_vm.is_valid_address(self.obj_offset):
            raise InvalidOffsetError("Invalid Address 0x{0:08X}, instantiating {1}".format(
                offset, self.obj_name))

    @property
    def parents(self):
        """Returns all the parents of this object."""
        obj = self
        while obj.obj_parent:
            obj = obj.obj_parent
            yield obj

    def proxied(self, attr):
        return None

    def newattr(self, attr, value):
        """Sets a new attribute after the object has been created"""
        return BaseObject.__setattr__(self, attr, value)

    def write(self, value):
        """Function for writing the object back to disk"""
        pass

    def __getattr__(self, attr):
        """ This is only useful for proper methods (not ones that
        start with __ )
        """
        ## Search for the attribute of the proxied object
        proxied = self.proxied(attr)
        # Don't do a __nonzero__ check on proxied or things like '' will fail
        if proxied is None:
            raise AttributeError("Unable to resolve attribute {0} on {1}".format(attr, self.obj_name))

        return getattr(proxied, attr)

    def __setattr__(self, attr, value):
        try:
            object.__setattr__(self, attr, value)
        except AttributeError:
            pass

    def __nonzero__(self):
        """ This method is called when we test the truth value of an
        Object. In volatility we consider an object to have True truth
        value only when its a valid object. Its possible for example
        to have a Pointer object which is not valid - this will have a
        truth value of False.

        You should be testing for validity like this:
        if X:
           # object is valid

        Do not test for validity like this:

        if int(X) == 0:

        or if X is None: .....

        the later form is not going to work when X is a NoneObject.
        """
        result = self.obj_vm.is_valid_address(self.obj_offset)
        return result

    def __eq__(self, other):
        return self.v() == other or ((self.__class__ == other.__class__) and
                                     (self.obj_offset == other.obj_offset) and (self.obj_vm == other.obj_vm))

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        # This needs to be the same as the object we proxy so that we can mix
        # with native types in sets and dicts. For example:
        # pids = set([1,2,3])
        # if task.UniqueProcessId in pids: ....
        return hash(self.v())

    def m(self, memname):
        raise AttributeError("No member {0}".format(memname))

    def is_valid(self):
        return self.obj_vm.is_valid_address(self.obj_offset)

    def dereference(self, vm=None):
        return NoneObject("Can't dereference {0}".format(self.obj_name), self.obj_profile)

    def dereference_as(self, derefType, vm=None, **kwargs):
        vm = vm or self.obj_vm

        return self.obj_profile.Object(theType=derefType, offset=self.v(), vm=vm,
                                       parent=self.obj_parent, name=self.obj_name, **kwargs)

    def cast(self, castString, **kwargs):
        return self.obj_profile.Object(theType=castString, offset=self.obj_offset,
                                       vm=self.obj_vm, **kwargs)

    def v(self, vm=None):
        """ Do the actual reading and decoding of this member
        """
        return NoneObject("No value for {0}".format(self.obj_name), self.obj_profile)

    def __format__(self, formatspec):
        return format(self.v(), formatspec)

    def __str__(self):
        return str(self.v())

    def __repr__(self):
        return "[{0} {1}] @ 0x{2:08X}".format(self.__class__.__name__, self.obj_name,
                                              self.obj_offset)

    def __dir__(self):
        """Hide any members with _."""
        result = self.__dict__.keys() + dir(self.__class__)

        return result


def CreateMixIn(mixin):
    def make_method(name):
        def method(self, *args, **kw):
            proxied = self.proxied(name)
            try:
                ## Try to coerce the other in case its also a proxied
                ## class
                args = list(args)
                args[0] = args[0].proxied(name)
            except (AttributeError, IndexError):
                pass

            try:
                method = getattr(operator, name)
                args = [proxied] + args
            except AttributeError:
                method = getattr(proxied, name)

            return method(*args, **kw)

        return method

    for name in mixin._specials:
        setattr(mixin, name, make_method(name))

class NumericProxyMixIn(object):
    """ This MixIn implements the numeric protocol """
    _specials = [
        ## Number protocols
        '__add__', '__sub__', '__mul__', '__floordiv__', '__mod__', '__divmod__',
        '__pow__', '__lshift__', '__rshift__', '__and__', '__xor__', '__or__', '__div__',
        '__truediv__', '__radd__', '__rsub__', '__rmul__', '__rdiv__', '__rtruediv__',
        '__rfloordiv__', '__rmod__', '__rdivmod__', '__rpow__', '__rlshift__',
        '__rrshift__', '__rand__', '__rxor__', '__ror__', '__neg__', '__pos__',
        '__abs__', '__invert__', '__int__', '__long__', '__float__', '__oct__',
        '__hex__',

        ## Comparisons
        '__lt__', '__le__', '__eq__', '__ne__', '__ge__', '__gt__', '__index__',

        ## Formatting
        '__format__',
        ]


class StringProxyMixIn(object):
    """This MixIn implements proxying for strings."""
    _specials = [
        ## Comparisons
        '__lt__', '__le__', '__eq__', '__ne__', '__ge__', '__gt__', '__index__',

        ## Formatting
        '__format__',
        ]


CreateMixIn(NumericProxyMixIn)
CreateMixIn(StringProxyMixIn)


class NativeType(BaseObject, NumericProxyMixIn):
    def __init__(self, format_string = None, **kwargs):
        super(NativeType, self).__init__(**kwargs)
        self.format_string = format_string

    def write(self, data):
        """Writes the data back into the address space"""
        output = struct.pack(self.format_string, data)
        return self.obj_vm.write(self.obj_offset, output)

    def proxied(self, attr):
        return self.v()

    def size(self):
        return struct.calcsize(self.format_string)

    def v(self, vm=None):
        data = self.obj_vm.zread(self.obj_offset, self.size())
        if not data:
            return NoneObject("Unable to read {0} bytes from {1}".format(
                    self.size(), self.obj_offset))

        (val,) = struct.unpack(self.format_string, data)

        return val

    def cdecl(self):
        return self.obj_name

    def __repr__(self):
        try:
            return " [{0}:{1}]: 0x{2:08X}".format(self.obj_type, self.obj_name,
                                                  self.v())
        except ValueError:
            return " [{0}:{1}]: {2}".format(self.obj_type, self.obj_name,
                                            repr(self.v()))


class BitField(NativeType):
    """ A class splitting an integer into a bunch of bit. """
    def __init__(self, profile=None, start_bit = 0, end_bit = 32, native_type = None,
                 **kwargs):
        if native_type is None:
            native_type = "address"

        # Defaults to profile-endian address, but can be overridden by native_type
        kwargs.update(profile.vtypes[native_type][1])
        NativeType.__init__(self, profile=profile, **kwargs)
        self.start_bit = start_bit
        self.end_bit = end_bit
        self.native_type = native_type # Store this for proper caching

    def v(self, vm=None):
        i = NativeType.v(self, vm=vm)
        return (i & ((1 << self.end_bit) - 1)) >> self.start_bit

    def write(self, data):
        data = data << self.start_bit
        return NativeType.write(self, data)

    def __nonzero__(self):
        return bool(self.v())


class Pointer(NativeType):

    def __init__(self, theType=None, target=None, target_args=None, **kwargs):
        # The format string comes from the address field:
        super(Pointer, self).__init__(theType=theType, **kwargs)

        self.format_string = self.obj_profile.vtypes["address"][1]["format_string"]

        self.kwargs = kwargs
        kwargs = kwargs.copy()
        kwargs.update(target_args or {})

        if isinstance(target, basestring):
            self.target = Curry(self.obj_profile.Object, theType=target, **kwargs)
        elif callable(target):
            self.target = target
        else:
            self.target = Curry(self.obj_profile.Object, theType=self.obj_type, **kwargs)

        self.target_size = 0

    def v(self):
        # 64 bit addresses are always sign extended so we need to clear the top bits.
        return 0xffffffffffff & super(Pointer, self).v()

    def __eq__(self, other):
        try:
            return (0xffffffffffff & int(other)) == self.v()
        except TypeError:
            return False

    def is_valid(self):
        """ Returns if what we are pointing to is valid """
        return self.obj_vm.is_valid_address(self.v())

    def dereference(self, vm=None):
        offset = self.v()

        # Casts into the correct AS:
        vm = vm or self.obj_vm

        if vm.is_valid_address(offset):
            result = self.target(offset = offset,
                                 vm = vm, profile = self.obj_profile,
                                 parent = self.obj_parent,
                                 name = self.obj_name)
            return result
        else:
            return NoneObject("Pointer {0} invalid".format(self.obj_name))

    def __dir__(self):
        return dir(self.dereference())

    def cdecl(self):
        return "Pointer {0}".format(self.v())

    def __nonzero__(self):
        """This method is used in comparison operations.

        This ideas here is to make it possible to easily write a condition such as:

        while ptr:
           ...
           ptr += 1

        Pointers are considered non-zero if they are invalid (i.e. what they
        point to is not mapped in. This is very subtle and might be the wrong
        choice. Note that if the kernel actually maps the zero page in (which
        can happen in some situations), then a null pointer is actually valid.
        """
        return bool(self.is_valid())

    def __add__(self, other):
        """Return a new pointer advanced by this many positions.

        Note that as usual for pointer arithmetic, the pointer moves by steps of
        the size of the target.
        """
        # Find out our target size for pointer arithmetics.
        self.target_size = (self.target_size or
                            self.target(vm=addrspace.DummyAddressSpace()).size())

        kwargs = self.kwargs
        kwargs['offset'] = self.obj_offset + int(other) * self.target_size
        kwargs['target'] = self.target

        try:
            return Pointer(**kwargs)
        except InvalidOffsetError, e:
            return NoneObject(e)

    def __sub__(self, other):
        return self.__add__(-other)

    def __iadd__(self, other):
        # Increment our own offset.
        self.target_size = (self.target_size or
                            self.target(vm=addrspace.DummyAddressSpace()).size())
        self.obj_offset += self.target_size * other

    def __repr__(self):
        target = self.dereference()
        return "<{0} {3} to [0x{2:08X}] ({1})>".format(
            target.__class__.__name__, self.obj_name or '', self.v(),
            self.__class__.__name__)

    def __getattr__(self, attr):
        ## We just dereference ourself
        result = self.dereference()

        return getattr(result, attr)

    def dereference_as(self, derefType, vm=None, **kwargs):
        """Dereference ourselves into another type, or address space."""
        vm = vm or self.obj_vm

        return self.obj_profile.Object(theType=derefType, offset=self.v(), vm=vm,
                                       parent=self.obj_parent, **kwargs)


class Void(Pointer):
    def __init__(self, **kwargs):
        kwargs['theType'] = 'unsigned long'
        super(Void, self).__init__(**kwargs)

    def size(self):
        logging.warning("Void objects have no size! Are you doing pointer arithmetic "
                        "on a pointer to void?")
        return 1

    def cdecl(self):
        return "0x{0:08X}".format(self.v())

    def __repr__(self):
        return "Void[{0} {1}] (0x{2:08X})".format(
            self.__class__.__name__, self.obj_name or '', self.v())

    def __nonzero__(self):
        return bool(self.dereference())


class Array(BaseObject):
    """ An array of objects of the same size """

    target_size = 0

    def __init__(self, count = 100000, target = None, target_args=None,
                 **kwargs):
        """Instantiate an array of like items.

        Args:
          count: How many items belong to the array (not strictly enforced -
            i.e. it is possible to read past the end). By default the array is
            unbound.

          target: A callable which will be instantiated on each point. The size
            of the object returned by this should be the same for all members of
            the array. Alternatively target can be the name of the element as a
            string (same as targetType: e.g. "_IMAGE_EXPORT_DIRECTORY")
        """
        super(Array, self).__init__(**kwargs)

        if callable(count):
            count = count(self.obj_parent)

        self.count = int(count)

        if isinstance(target, basestring):
            self.targetType = target

        target_args = target_args or {}
        if not target:
            raise AttributeError("Array must use a target parameter")

        self.target = Curry(self.obj_profile.Object, target, **target_args)

        # Dereference the first element.
        self.current = self[0]
        self.target_size = self.current.size()

        if self.target_size == 0:
            ## It is an error to have a zero sized element
            logging.debug("Array with 0 sized members???")

    def size(self):
        return self.count * self.target_size

    def __iter__(self):
        ## This method is better than the __iter__/next method as it
        ## is reentrant
        for position in range(0, self.count):

            ## We don't want to stop on a NoneObject.  Its
            ## entirely possible that this array contains a bunch of
            ## pointers and some of them may not be valid (or paged
            ## in). This should not stop us though we just return the
            ## invalid pointers to our callers.  It's up to the callers
            ## to do what they want with the array.
            if (self.current == None):
                return

            yield self[position]

    def __repr__(self):
        return "<Array {0} x {1} @ 0x{2:08X}>".format(
            self.count, self.targetType, self.obj_offset)

    def __str__(self):
        result = [repr(self)]
        for i, x in enumerate(self):
            result.append("0x%04X %r" % (i, x))

            if len(result) > 10:
                result.append("... More entries hidden")
                break

        return "\n".join(result)

    def __eq__(self, other):
        if self.count != len(other):
            return False

        for i in range(self.count):
            if not self[i] == other[i]:
                return False

        return True

    def __getitem__(self, pos):
        ## Check for slice object
        if isinstance(pos, slice):
            start, stop, step = pos.indices(self.count)
            return [self[i] for i in xrange(start, stop, step)]

        ## Check if the offset is valid
        offset = self.obj_offset + pos * self.target_size

        try:
            return self.target(offset=offset, vm=self.obj_vm, parent=self,
                               profile=self.obj_profile,
                               name = "{0} @ {1}".format(self.obj_name, pos))
        except InvalidOffsetError:
            return NoneObject("Invalid offset %s" % offset)


class CType(BaseObject):
    """ A CType is an object which represents a c struct """
    def __init__(self, members = None, struct_size = 0, **kwargs):
        """ This must be instantiated with a dict of members. The keys
        are the offsets, the values are Curried Object classes that
        will be instantiated when accessed.
        """
        super(CType, self).__init__(**kwargs)

        if not members:
            # Warn rather than raise an error, since some types (_HARDWARE_PTE,
            # for example) are generated without members
            logging.debug("No members specified for CType %s named %s",
                          self.obj_type, self.obj_name)
            members = {}

        self.members = members
        self.struct_size = struct_size
        self.__initialized = True

    def __int__(self):
        """Return our offset as an integer.

        This allows us to interchange CTypes and offsets.
        """
        return self.obj_offset

    def preamble_size(self):
        """The number of bytes before the object which are part of the object.

        Some objects are preceeded with data before obj_offset which is still
        considered part of the object. Note that in that case the size of the
        object includes the preamble_size - hence

        object_end = obj_offset + obj.size() - obj.preamble_size()
        """
        return 0

    def size(self):
        return self.struct_size

    def __repr__(self):
        return "[{0} {1}] @ 0x{2:08X}".format(self.obj_type, self.obj_name or '',
                                              self.obj_offset)
    def __str__(self):
        result = self.__repr__() + "\n"
        width_name = 0

        fields = []
        # Print all the fields sorted by offset within the struct.
        for k, (offset, _) in self.members.items():
            width_name = max(width_name, len(k))
            obj = self.m(k)
            fields.append((obj.obj_offset - self.obj_offset,
                           k, repr(obj)))

        fields.sort()

        format_string = "0x%04X %" + str(width_name) + "s %s"
        return result + "\n".join(
            ["  0x%02X %s%s %s" % (offset, k, " " * (width_name - len(k)), v)
             for offset,k,v in fields])

    def v(self, vm=None):
        """ When a struct is evaluated we just return our offset.
        """
        return self.obj_offset

    def m(self, attr):
        if attr in self.members:
            # Allow the element to be a callable rather than a list - this is
            # useful for aliasing member names
            element = self.members[attr]
            if callable(element):
                return element(self)

            offset, cls = element
        elif attr.find('__') > 0 and attr[attr.find('__'):] in self.members:
            offset, cls = self.members[attr[attr.find('__'):]]
        else:
            ## hmm - tough choice - should we raise or should we not
            #return NoneObject("Struct {0} has no member {1}".format(self.obj_name, attr))
            raise AttributeError("Struct {0} has no member {1}".format(self.obj_name, attr))

        if callable(offset):
            ## If offset is specified as a callable its an absolute
            ## offset
            offset = int(offset(self))
        else:
            ## Otherwise its relative to the start of our struct
            offset = int(offset) + int(self.obj_offset)

        try:
            result = cls(offset = offset, vm = self.obj_vm, parent = self, name = attr,
                         profile = self.obj_profile)
        except Error, e:
            result = NoneObject(str(e))

        return result

    def __getattr__(self, attr):
        return self.m(attr)

    def __dir__(self):
        """This is useful for tab completion in an ipython volshell."""
        result = self.members.keys() + super(CType, self).__dir__()

        return result

    def __eq__(self, other):
        try:
            return type(self) == type(other) and int(self) == int(other)
        except (TypeError, ValueError):
            return False

    def __lt__(self, other):
        try:
            return self.obj_offset < int(other)
        except (TypeError, ValueError):
            return False

    def __le__(self, other):
        return self < other and self == other

    def __gt__(self, other):
        return not self < other and not self == other

    def __ge__(self, other):
        return not self < other


## Profiles are the interface for creating/interpreting
## objects

class Profile(object):
    """ A profile is a collection of types relating to a certain
    system. We parse the abstract_types and join them with
    native_types to make everything work together.
    """
    _md_os = 'undefined'
    _md_major = 0
    _md_minor = 0
    _md_build = 0
    _md_memory_model = None

    # This is the dict which holds the overlays to be applied to the vtypes when
    # compiling into types.
    overlay = None

    # These are the vtypes - they are just a dictionary describing the types
    # using the "vtype" language. This dictionary will be compiled into
    # executable code and placed into self.types.
    vtypes = None

    # This hold the executable code compiled from the vtypes above.
    types = None

    # This flag indicates if the profile needs to be recompiled on demand.
    _ready = False

    # This is the base class for all profiles.
    __metaclass__ = registry.MetaclassRegistry
    __abstract = True

    # This is a dict of constants
    constants = None

    # This is a record of all the modification classes that were applied to this
    # profile.
    applied_modifications = None

    def __init__(self, session=None, **kwargs):
        if kwargs:
            logging.error("Unknown keyword args {0}".format(kwargs))
        self.session = session
        self.overlayDict = {}
        self.overlays = []
        self.vtypes = {}
        self.constants = {}
        self.applied_modifications = set()

        class dummy(object):
            profile = self
            name = 'dummy'
            def is_valid_address(self, _offset):
                return True

            def read(self, _offset, _value):
                return ""

        # A dummy address space used internally.
        self._dummy = dummy()

        # We initially populate this with objects in this module that will be used everywhere
        self.object_classes = {'BitField': BitField,
                               'Pointer': Pointer,
                               'Void': Void,
                               'Array': Array,
                               'NativeType': NativeType,
                               'CType': CType}

    def copy(self):
        """Makes a copy of this profile."""
        result = self.__class__(session=self.session)
        result.vtypes = copy.deepcopy(self.vtypes)
        result.overlays = copy.deepcopy(self.overlays)
        result.object_classes = copy.deepcopy(self.object_classes)

        return result

    @classmethod
    def metadata(cls, name, default=None):
        """Obtain metadata about this profile."""
        prefix = '_md_'
        return getattr(cls, prefix + name, default)

    def has_type(self, theType):
        return theType in self.object_classes or theType in self.vtypes

    def add_classes(self, classes_dict):
        """Add the classes in the dict to our object classes mapping."""
        self._ready = False
        self.object_classes.update(classes_dict)

    def add_constants(self, **kwargs):
        """Add the kwargs as constants for this profile."""
        self.constants.update(kwargs)

    def add_types(self, abstract_types):
        self._ready = False
        abstract_types = copy.deepcopy(abstract_types)

        ## we merge the abstract_types with self.vtypes and then recompile
        ## the whole thing again. This is essential because
        ## definitions may have changed as a result of this call, and
        ## we store curried objects (which might keep their previous
        ## definitions).
        for k, v in abstract_types.items():
            if isinstance(v, list):
                self.vtypes[k] = v
            else:
                original = self.vtypes.get(k, [0, {}])
                original[1].update(v[1])
                if v[0]:
                    original[0] = v[0]

                self.vtypes[k] = original

    def compile(self):
        """ Compiles the vtypes, overlays, object_classes, etc into a types dictionary."""
        self.types = {}

        # Marge all the overlays in order
        for overlay in self.overlays:
            self._merge_overlay(overlay)

        for name in self.vtypes.keys():
            if isinstance(self.vtypes[name][0], str):
                self.types[name] = self.list_to_type(name, self.vtypes[name], self.vtypes)
            else:
                self.types[name] = self.convert_members(
                name, self.vtypes, copy.deepcopy(self.overlayDict))

        # We are ready to go now.
        self._ready = True

    # pylint: disable-msg=R0911
    def list_to_type(self, name, typeList, vtypes = None):
        """ Parses a specification list and returns a VType object.

        This function is a bit complex because we support lots of
        different list types for backwards compatibility.
        """
        ## This supports plugin memory objects:
        try:
            kwargs = typeList[1]

            if type(kwargs) == dict:
                ## We have a list of the form [ ClassName, dict(.. args ..) ]
                return Curry(self.Object, theType = typeList[0], name = name,
                             type_name = name, **kwargs)
        except (TypeError, IndexError), _e:
            pass

        ## This is of the form [ 'void' ]
        if typeList[0] == 'void':
            return Curry(Void, profile=self, name = name)

        ## This is of the form [ 'pointer' , [ 'foobar' ]]
        if typeList[0] == 'pointer' or typeList[0] == 'pointer64':
            try:
                target = typeList[1]
            except IndexError:
                raise RuntimeError("Syntax Error in pointer type defintion for name "
                                   "{0}".format(name))

            return Curry(Pointer, name = name,
                         target = self.list_to_type(name, target, vtypes))

        ## This is an array: [ 'array', count, ['foobar'] ]
        if typeList[0] == 'array':
            return Curry(Array, name = name, count = typeList[1],
                         target = self.list_to_type(name, typeList[2], vtypes))

        ## This is a list which refers to a type which is already defined
        if typeList[0] in self.types:
            return Curry(self.types[typeList[0]], name = name)

        ## Does it refer to a type which will be defined in future? in
        ## this case we just curry the Object function to provide
        ## it on demand. This allows us to define structures
        ## recursively.
        try:
            tlargs = typeList[1]
        except IndexError:
            tlargs = {}

        obj_name = typeList[0]
        if type(tlargs) == dict:
            return Curry(self.Object, theType = obj_name, name = name, **tlargs)

        # This is of the form ['class_name', ['arg1', 'arg2']]
        if typeList[0] in self.object_classes:
            return Curry(self.object_classes[typeList[0]], *typeList[1:])

        ## If we get here we have no idea what this list is
        #raise RuntimeError("Error in parsing list {0}".format(typeList))
        logging.warning("Unable to find a type for {0}, assuming int".format(typeList[0]))
        return Curry(self.types['int'], name = name)

    def _get_dummy_obj(self, name):
        """Make a dummy object on top of the dummy address space."""
        # Make the object on the dummy AS.
        tmp = self.Object(theType = name, offset = 0, vm = self._dummy)
        return tmp

    def get_obj_offset(self, name, member):
        """ Returns a members offset within the struct """
        tmp = self._get_dummy_obj(name)
        offset, _cls = tmp.members[member]

        return offset

    def get_obj_size(self, name):
        """Returns the size of a struct"""
        tmp = self._get_dummy_obj(name)
        return tmp.size()

    def obj_has_member(self, name, member):
        """Returns whether an object has a certain member"""
        tmp = self._get_dummy_obj(name)
        return hasattr(tmp, member)

    def add_overlay(self, overlay):
        """Add an overlay to the current overlay stack."""
        self._ready = False
        self.overlays.append(copy.deepcopy(overlay))

    def _merge_overlay(self, overlay):
        """Applies an overlay to the profile's vtypes"""
        for k, v in overlay.items():
            if k in self.vtypes:
                self.vtypes[k] = self._apply_overlay(self.vtypes[k], v)
            else:
                # The vtype does not have anything to overlay, we just create a
                # new definition.
                self.vtypes[k] = v
                logging.debug("Overlay structure {0} not present in vtypes".format(k))

    def _apply_overlay(self, type_member, overlay):
        """ Update the overlay with the missing information from type.

        Basically if overlay has None in any slot it gets applied from vtype.
        """
        # A None in the overlay allows the vtype to bubble up.
        if overlay is None:
            return type_member

        if type(type_member) == dict:
            for k, v in type_member.items():
                if k not in overlay:
                    overlay[k] = v
                else:
                    overlay[k] = self._apply_overlay(v, overlay[k])

        elif callable(overlay):
            return overlay

        elif type(overlay) == list:
            if len(overlay) != len(type_member):
                return overlay

            for i in range(len(overlay)):
                if overlay[i] == None:
                    overlay[i] = type_member[i]
                else:
                    overlay[i] = self._apply_overlay(type_member[i], overlay[i])

        return overlay

    def convert_members(self, cname, vtypes, overlay):
        """ Convert the member named by cname from the c description
        provided by vtypes into a list of members that can be used
        for later parsing.

        cname is the name of the struct.

        We expect vtypes[cname] to be a list of the following format

        [ Size of struct, members_dict ]

        members_dict is a dict of all members (fields) in this
        struct. The key is the member name, and the value is a list of
        this form:

        [ offset_from_start_of_struct, specification_list ]

        The specification list has the form specified by self.list_to_type() above.

        We return a list of CTypeMember objects.
        """
        expression = vtypes[cname]
        ctype = self._apply_overlay(expression, overlay.get(cname))

        members = {}
        size = ctype[0]
        for k, v in ctype[1].items():
            if callable(v):
                members[k] = v
            elif v[0] == None:
                import pdb; pdb.set_trace()
                logging.warning("{0} has no offset in object {1}. Check that vtypes "
                                "has a concrete definition for it.".format(k, cname))
            else:
                members[k] = (v[0], self.list_to_type(k, v[1], vtypes))

        ## Allow the plugins to over ride the class constructor here
        if self.object_classes and cname in self.object_classes:
            cls = self.object_classes[cname]
        else:
            cls = CType

        return Curry(cls, theType = cname, members = members, struct_size = size)

    def get_constant(self, constant):
        # Compile on demand
        if not self._ready: self.compile()
        result = self.constants.get(constant)
        if result is None:
            result = NoneObject("Constant %s does not exist in profile." % constant)
            logging.error("Constant %s does not exist in profile.", constant)

        return result

    def Object(self, theType=None, offset=0, vm=None, name = None, **kwargs):
        """ A function which instantiates the object named in theType (as
        a string) from the type in profile passing optional args of
        kwargs.
        """
        # Compile on demand
        if not self._ready: self.compile()

        name = name or theType
        offset = int(offset)

        try:
            kwargs['profile'] = self

            if theType in self.types:
                result = self.types[theType](offset = offset, vm = vm, name = name,
                                             **kwargs)
                return result

            if theType in self.object_classes:
                result = self.object_classes[theType](theType = theType,
                                                      offset = offset,
                                                      vm = vm,
                                                      name = name,
                                                      **kwargs)
                return result

        except InvalidOffsetError, e:
            ## If we cant instantiate the object here, we just error out:
            return NoneObject("Invalid Address 0x{0:08X}, instantiating {1}".format(
                    offset, name))

        ## If we get here we have no idea what the type is supposed to be?
        ## This is a serious error.
        import pdb; pdb.set_trace()
        logging.warning("Cant find object {0} in profile {1}?".format(theType, self))


class ProfileModification(object):
    """A profile modification adds new types to an existing profile.

    A ProfileModification must be invoked explicitely. We have these as plugins
    so its easier to find a modification by name. A typical invokation looks
    like:

    class myPlugin(plugin.Command):
      def __init__(self, **kwargs):
         super(myPlugin, self).__init__(**kwargs)

         # Update the profile with the "VolRegistrySupport" implementation.
         self.profile = obj.ProfileModification.classes['VolRegistrySupport'](self.profile)

    Note that this plugin must explicitely apply the correct modification. This
    allows the plugin to choose from a number of different implementations. For
    example, in the above say we have one implementation (i.e. overlays, object
    classes etc) called VolRegistrySupport and another called
    ScudetteRegistrySupport, we can choose between them.

    Now suppose that ScudetteRegistrySupport introduces an advanced class with
    extra methods:

    class _CM_KEY_INDEX(obj.CType):
       .....
       def SpecialMethod(...):
          ....

    The plugin relies on using this specific implementation (i.e. if we loaded
    the other profile modification, this myPlugin will fail because it will
    attempt to call an undefined method!  Essentially by explicitely loading the
    modification, the plugin declares that it relies on the
    ScudetteRegistrySupport implementation, but does not preclude having another
    implementation.
    """
    def __new__(cls, profile):
        if cls.__name__ in profile.applied_modifications:
            return profile

        # Return a copy of the profile.
        result = profile.copy()
        cls.modify(result)
        result.applied_modifications.add(cls.__name__)

        return result

    @classmethod
    def modify(cls, profile):
        """This class should modify the profile appropritately.

        The profile will be a copy of the original profile and will be returns
        to the class caller.

        Args:
           A profile to be modified.
        """
