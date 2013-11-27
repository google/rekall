# Volatility
# Copyright (C) 2007,2008 Volatile Systems
#
# Copyright (C) 2005,2006 4tphi Research
# Author: {npetroni,awalters}@4tphi.net (Nick Petroni and AAron Walters)
# Author: Michael Cohen scudette@gmail.com.
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
import inspect
import logging
import sys
import re
import operator
import struct

import copy
from volatility import addrspace
from volatility import registry
from volatility import utils

import traceback


class Curry(object):
    def __init__(self, curry_target, *args, **kwargs):
        self._target = curry_target
        self._kwargs = kwargs
        self._args = args
        self.__doc__ = getattr(self._target, "__init__", self._target).__doc__

    def __call__(self, *args, **kwargs):
        # Merge the kwargs with the new kwargs
        new_kwargs = self._kwargs.copy()
        new_kwargs.update(kwargs)
        return self._target(*(self._args + args), **new_kwargs)

    def _default_arguments(self):
        """Return a list of default args for the target."""
        args, _, _, defaults = inspect.getargspec(self._target)
        if defaults:
            return args[-len(defaults):]

        return []

    def __getattr__(self, attr):
        return getattr(self._target, attr)


# This is marginally faster but is harder to debug since the Curry callables are
# opaque.
# import functools
# Curry = functools.partial


def get_bt_string(_e = None):
    return ''.join(traceback.format_stack()[:-2])


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

    # Override these methods too.
    dereference_as = __call__
    __getitem__ = __call__


class Error(Exception):
    """All object related exceptions come from this one."""


class ProfileError(Error):
    """Errors in setting the profile."""


class BaseObject(object):

    obj_parent = NoneObject("No parent")
    obj_name = NoneObject("No name")

    # This is set when the object is completed initialization.
    _initialized = False

    # We have **kwargs here, but it's unclear if it's a good idea
    # Benefit is objects will never fail with duff parameters
    # Downside is typos won't show up and be difficult to diagnose
    def __init__(self, theType=None, offset=0, vm=None, profile=None,
                 parent=None, name='', context=None, **kwargs):
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

          context: An opaque dict which is passed to all objects created from
            this object. This dict may contain context specific information
            which each derived instance can use.

          kwargs: Arbitrary args this object may accept - these can be passed in
             the vtype language definition.
        """
        if kwargs:
            logging.error("Unknown keyword args {0} for {1}".format(
                    kwargs, self.__class__.__name__))

        self.obj_type = theType

        # 64 bit addresses are always sign extended, so we need to clear the top
        # bits.
        self.obj_offset = Pointer.integer_to_address(int(offset or 0))
        self.obj_vm = vm
        self.obj_parent = parent
        self.obj_name = name
        self.obj_profile = profile
        self.obj_context = context or {}

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
            raise AttributeError(
                "Unable to resolve attribute {0} on {1}".format(
                    attr, self.obj_name))

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
        return NoneObject("No member {0}".format(memname))

    def is_valid(self):
        return self.obj_vm.is_valid_address(self.obj_offset)

    def deref(self, vm=None):
        """An alias for dereference - less to type."""
        return self.dereference(vm=vm)

    def dereference(self, vm=None):
        return NoneObject("Can't dereference {0}".format(self.obj_name), self.obj_profile)

    def dereference_as(self, target=None, vm=None, **kwargs):
        vm = vm or self.obj_vm

        return self.obj_profile.Object(theType=target, offset=self.v(), vm=vm,
                                       parent=self.obj_parent, name=self.obj_name,
                                       context=self.obj_context, **kwargs)

    def reference(self):
        """Produces a pointer to this object.

        This is the same as the C & operator and is the opposite of deref().
        """
        return self.obj_profile.Pointer(value=self.obj_offset, vm=self.obj_vm,
                                        target=self.obj_type)

    def cast(self, type=None, **kwargs):
        return self.obj_profile.Object(theType=type, offset=self.obj_offset,
                                       vm=self.obj_vm, parent=self.obj_parent,
                                       context=self.obj_context, **kwargs)

    def v(self, vm=None):
        """ Do the actual reading and decoding of this member
        """
        return NoneObject("No value for {0}".format(self.obj_name), self.obj_profile)

    def __str__(self):
        return str(self.v())

    def __unicode__(self):
        return self.__str__().decode("utf8", "ignore")

    def __repr__(self):
        return "[{0} {1}] @ 0x{2:08X}".format(self.__class__.__name__, self.obj_name,
                                              self.obj_offset)

    def __dir__(self):
        """Hide any members with _."""
        result = self.__dict__.keys() + dir(self.__class__)

        return result

    def __format__(self, formatspec):
        if not formatspec:
            formatspec = "s"

        if formatspec[-1] in "xdXD":
            return format(int(self), formatspec)

        return object.__format__(self, formatspec)


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
        ]


class StringProxyMixIn(object):
    """This MixIn implements proxying for strings."""
    _specials = [
        ## Comparisons
        '__lt__', '__le__', '__eq__', '__ne__', '__ge__', '__gt__', '__index__',
        ]


CreateMixIn(NumericProxyMixIn)
CreateMixIn(StringProxyMixIn)


class NativeType(BaseObject, NumericProxyMixIn):
    def __init__(self, value=None, format_string = None, **kwargs):
        super(NativeType, self).__init__(**kwargs)
        self.format_string = format_string
        self.value = value

    def write(self, data):
        """Writes the data back into the address space"""
        output = struct.pack(self.format_string, data)
        return self.obj_vm.write(self.obj_offset, output)

    def proxied(self, attr):
        return self.v()

    def __radd__(self, other):
        return self.v() + long(other)

    def size(self):
        return struct.calcsize(self.format_string)

    def v(self, vm=None):
        if self.value is not None:
            return self.value

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


class Bool(NativeType):
    def __str__(self):
        """Format boolean values nicely."""
        return str(bool(self))


class BitField(NativeType):
    """ A class splitting an integer into a bunch of bit. """
    def __init__(self, start_bit = 0, end_bit = 32, native_type = None,
                 **kwargs):
        super(BitField, self).__init__(**kwargs)

        self._proxy = self.obj_profile.Object(
            native_type or "address", offset=self.obj_offset, vm=self.obj_vm,
            context=self.obj_context)

        self.start_bit = start_bit
        self.end_bit = end_bit

    def size(self):
        return self._proxy.size()

    def v(self, vm=None):
        i = self._proxy.v(vm=vm)
        return (i & ((1 << self.end_bit) - 1)) >> self.start_bit

    def write(self, data):
        # To write we need to read the proxy, set the bits and then write the
        # proxy again.
        return False

    # The __nonzero__ attribute is reserved for validity checks.
    def __nonzero__(self):
        # This is an error since this attribute is used for validity checking.
        logging.warning("Bitfield %s called with __nonzero__.", self.obj_name)
        return super(BitField, self).__nonzero__()


class Pointer(NativeType):
    """A pointer reads an 'address' object from the address space."""

    def __init__(self, target=None, target_args=None, value=None, **kwargs):
        """Constructor.

        Args:
           target: The name of the target object (A string). We use the profile
             to instantiate it.
           target_args: The target will receive these as kwargs.
        """
        super(Pointer, self).__init__(**kwargs)

        if value is not None:
            self.obj_offset = None

        # We parse the address using the profile since address is a different
        # size on different platforms.
        self._proxy = self.obj_profile.Object(
            "address", offset=self.obj_offset, value=value,
            vm=self.obj_vm, context=self.obj_context)

        # We just hold on to these so we can construct the objects later.
        self.target = target
        self.target_args = target_args or {}
        self.target_size = 0
        self.kwargs = kwargs
        self._initialized = True

    def size(self):
        return self._proxy.size()

    def v(self, vm=None):
        # 64 bit addresses are always sign extended so we need to clear the top
        # bits.
        return Pointer.integer_to_address(self._proxy.v(vm=vm))

    def m(self, attr):
        return self.deref().m(attr)

    def write(self, data):
        return self._proxy.write(data)

    def __eq__(self, other):
        try:
            # Must use __int__() because int(other) when other is a string will
            # convert it to an integer.
            return Pointer.integer_to_address(other.__int__()) == self.v()
        except (ValueError, AttributeError):
            return False

    def is_valid(self):
        """ Returns if what we are pointing to is valid """
        return self.obj_vm.is_valid_address(self.v())

    def __getitem__(self, item):
        return self.dereference()[item]

    def __setattr__(self, attr, value):
        if (attr in self.__dict__ or hasattr(self.__class__, attr) or
            not self._initialized):
            return super(Pointer, self).__setattr__(attr, value)

        getattr(self.dereference(), attr).write(value)

    def dereference(self, vm=None):
        offset = self.v()

        # Casts into the correct AS:
        vm = vm or self.obj_vm

        if vm.is_valid_address(offset):
            kwargs = copy.deepcopy(self.target_args)
            kwargs.update(dict(offset = offset,
                               vm = vm, profile = self.obj_profile,
                               parent = self.obj_parent,
                               name=self.obj_name))

            if isinstance(self.target, basestring):
                result = self.obj_profile.Object(
                    theType=self.target,
                    context=self.obj_context, **kwargs)

            elif callable(self.target):
                result = self.target(**kwargs)
            else:
                # Target not valid, return void.
                result = Void(**kwargs)

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
                            self.obj_profile.Object(self.target).size())

        offset = self.obj_offset + int(other) * self.target_size
        if not self.obj_vm.is_valid_address(offset):
            return NoneObject("Invalid offset")

        return self.__class__(target=self.target, target_args=self.target_args,
                              offset=offset, vm=self.obj_vm,
                              parent=self.obj_parent,
                              context=self.obj_context, profile=self.obj_profile)

    def __sub__(self, other):
        return self.__add__(-other)

    def __iadd__(self, other):
        # Increment our own offset.
        self.target_size = (self.target_size or self.target().size())
        self.obj_offset += self.target_size * other

    def __repr__(self):
        return "<{0} {3} to [0x{2:08X}] ({1})>".format(
            self.target, self.obj_name or '', self.v(),
            self.__class__.__name__)

    def __str__(self):
        return "Pointer to %s" % self.deref()

    def __getattr__(self, attr):
        ## We just dereference ourself
        result = self.dereference()

        return getattr(result, attr)

    def __iter__(self):
        """Delegate the iterator to the target."""
        return iter(self.dereference())

    def dereference_as(self, target=None, vm=None, target_args={}):
        """Dereference ourselves into another type, or address space."""
        vm = vm or self.obj_vm

        return self.obj_profile.Object(
            theType=target or self.target, offset=self.v(), vm=vm,
            parent=self.obj_parent, context=self.obj_context,
            **target_args)

    @staticmethod
    def integer_to_address(value):
        """Addresses only use 48 bits."""
        return 0xffffffffffff & int(value)


class Void(Pointer):
    def __init__(self, **kwargs):
        kwargs['theType'] = 'unsigned long'
        super(Void, self).__init__(**kwargs)

    def v(self):
        return self.obj_offset

    def dereference(self, vm=None):
        return NoneObject("Void reference")

    def size(self):
        logging.warning("Void objects have no size! Are you doing pointer "
                        "arithmetic on a pointer to void?")
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
                 target_size = None, **kwargs):
        """Instantiate an array of like items.

        Args:
          count: How many items belong to the array (not strictly enforced -
            i.e. it is possible to read past the end). By default the array is
            unbound.

          target: The name of the element to be instantiated on each point. The size
            of the object returned by this should be the same for all members of
            the array (i.e. all elements should be the same size).
        """
        super(Array, self).__init__(**kwargs)

        # Allow the count to be callable.
        if callable(count):
            count = count(self.obj_parent)

        if callable(target_size):
            target_size = target_size(self.obj_parent)

        self.count = int(count)

        if not target:
            raise AttributeError("Array must use a target parameter")

        self.target = target
        self.target_args = target_args or {}
        self.target_size = target_size or self.obj_profile.get_obj_size(
            target)

        self._initialized = True

    def size(self):
        """The size of the entire array."""
        return self.target_size * self.count

    def __iter__(self):
        # If the array is invalid we do not iterate.
        if self.obj_vm.is_valid_address(self.obj_offset):
            for position in range(0, self.count):
                # We don't want to stop on a NoneObject.  Its
                # entirely possible that this array contains a bunch of
                # pointers and some of them may not be valid (or paged
                # in). This should not stop us though we just return the
                # invalid pointers to our callers.  It's up to the callers
                # to do what they want with the array.

                yield self[position]

    def __repr__(self):
        return "<{3} {0} x {1} @ 0x{2:08X}>".format(
            self.count, self.target, self.obj_offset, self.__class__.__name__)

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

        offset = self.target_size * pos + self.obj_offset
        if not self.obj_vm.is_valid_address(offset):
            return NoneObject("Invalid offset %s" % offset)

        return self.obj_profile.Object(
            self.target, offset=offset, vm=self.obj_vm,
            parent=self, profile=self.obj_profile,
            name="{0}[{1}] ".format(self.obj_name, pos),
            context=self.obj_context, **self.target_args)

    def __setitem__(self, item, value):
        if isinstance(item, int):
            self[item].write(value)
        else:
            super(Array, self).__setitem__(item, value)

    def __len__(self):
        return self.count


class ListArray(Array):
    """An array of structs which do not all have the same size."""

    def __init__(self, maximum_size=1024, maximum_offset=None, **kwargs):
        """Constructor.

        Args:
          maximum_size: The maximum size of the array in bytes.
        """
        super(ListArray, self).__init__(**kwargs)
        if callable(maximum_size):
            maximum_size = int(maximum_size(self.obj_parent))

        if callable(maximum_offset):
            maximum_offset = int(maximum_offset(self.obj_parent))

        self.maximum_offset = maximum_offset or (self.obj_offset + maximum_size)

    def __iter__(self):
        offset = self.obj_offset
        count = 0
        while offset < self.maximum_offset and count < self.count:
            if not self.obj_vm.is_valid_address(offset):
                return

            item = self.obj_profile.Object(
                self.target, offset=offset, vm=self.obj_vm, parent=self,
                profile=self.obj_profile, context=self.obj_context,
                name="{0}[{1}] ".format(self.obj_name, count),
                **self.target_args)

            item_size = item.size()
            if item_size <= 0:
                break

            offset += item_size
            count += 1

            yield item

    def __getitem__(self, pos):
        for index, item in enumerate(self):
            if index == int(pos):
                return item

        return NoneObject("Pos seems to be outside the array maximum_size.")


class BaseAddressComparisonMixIn(object):
    """A mixin which provides the normal comparison operators for its base offset."""
    def __comparator__(self, other, method):
        # 64 bit addresses are always sign extended so we need to clear the top
        # bits.
        try:
            return method(Pointer.integer_to_address(self.__int__()),
                          Pointer.integer_to_address(other.__int__()))
        except AttributeError:
            return False

    def __eq__(self, other):
        return self.__comparator__(other, operator.__eq__)

    def __lt__(self, other):
        return self.__comparator__(other, operator.__lt__)

    def __gt__(self, other):
        return self.__comparator__(other, operator.__gt__)

    def __le__(self, other):
        return self.__comparator__(other, operator.__le__)

    def __ge__(self, other):
        return self.__comparator__(other, operator.__ge__)

    def __ne__(self, other):
        return self.__comparator__(other, operator.__ne__)


class Struct(BaseAddressComparisonMixIn, BaseObject):
    """ A Struct is an object which represents a c struct

    Structs have members at various fixed relative offsets from our own base
    offset.
    """
    def __init__(self, members = None, struct_size = 0, **kwargs):
        """ This must be instantiated with a dict of members. The keys
        are the offsets, the values are Curried Object classes that
        will be instantiated when accessed.

        Args:
           members: A dict of callables to use for retrieving each member. (Key
             is member name, value is a callable). Normally these are populated
             by the profile system

           struct_size: The size of this struct if known (Can be None).
        """
        super(Struct, self).__init__(**kwargs)

        if not members:
            # Warn rather than raise an error, since some types (_HARDWARE_PTE,
            # for example) are generated without members
            logging.debug("No members specified for Struct %s named %s",
                          self.obj_type, self.obj_name)
            members = {}

        self.members = members
        self.struct_size = struct_size
        self._initialized = True

    def __hash__(self):
        return self.obj_offset + hash(self.obj_vm)

    def __int__(self):
        """Return our offset as an integer.

        This allows us to interchange Struct and offsets.
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
        if callable(self.struct_size):
            return self.struct_size(self)

        return self.struct_size

    def __repr__(self):
        return "[{0} {1}] @ 0x{2:08X}".format(self.obj_type, self.obj_name or '',
                                              self.obj_offset)
    def __str__(self):
        result = self.__repr__() + "\n"
        width_name = 0

        fields = []
        # Print all the fields sorted by offset within the struct.
        for k in self.members:
            width_name = max(width_name, len(k))
            obj = self.m(k)
            fields.append((getattr(obj, "obj_offset", self.obj_offset) - self.obj_offset,
                           k, repr(obj)))

        fields.sort()

        format_string = "0x%04X %" + str(width_name) + "s %s"
        return result + "\n".join(
            ["  0x%02X %s%s %s" % (offset, k, " " * (width_name - len(k)), v)
             for offset,k,v in fields]) + "\n"

    def __unicode__(self, encoding=None):
        return self.__str__()

    def v(self, vm=None):
        """ When a struct is evaluated we just return our offset.
        """
        return self.obj_offset

    def m(self, attr):
        """Fetch the member named by attr.

        NOTE: When the member does not exist in this struct, we return a
        NoneObject instance. This allows one to write code such as:

        struct.m("Field1") or struct.m("Field2") struct.m("Field2")

        To access a field which has been renamed in different OS versions.
        """
        # Allow subfields to be gotten via this function.
        if "." in attr:
            result = self
            for sub_attr in attr.split("."):
                result = result.m(sub_attr)
            return result

        if attr in self.members:
            # Allow the element to be a callable rather than a list - this is
            # useful for aliasing member names
            element = self.members[attr]
            if callable(element):
                return element(self)

            offset, cls = element
        else:
            return NoneObject(u"Struct {0} has no member {1}".format(
                    self.obj_name, attr))

        if callable(offset):
            ## If offset is specified as a callable its an absolute
            ## offset
            offset = int(offset(self))
        else:
            ## Otherwise its relative to the start of our struct
            offset = int(offset) + int(self.obj_offset)

        try:
            result = cls(offset=offset, vm=self.obj_vm, parent=self, name=attr,
                         profile=self.obj_profile, context=self.obj_context)
        except Error, e:
            result = NoneObject(str(e))

        return result

    def __getattr__(self, attr):
        # We raise when directly accessing a member to catch invalid access
        # errors. NOTE: This is different from the m() method which returns a
        # NoneObject for invalid members.
        if attr not in self.members:
            raise AttributeError("Type {0} has no member {1}".format(
                    self.obj_type, attr))

        return self.m(attr)

    def __setattr__(self, attr, value):
        """Change underlying members"""
        # Special magic to allow initialization this test allows attributes to
        # be set in the __init__ method.
        if (attr in self.__dict__ or hasattr(self.__class__, attr) or
            not self._initialized):
            return super(Struct, self).__setattr__(attr, value)

        else:
            member = self.m(attr)
            if not hasattr(member, 'write') or not member.write(value):
                raise ValueError("Error writing value to member " + attr)

            return

        # If you hit this, consider using obj.newattr('attr', value)
        raise ValueError("Attribute " + attr + " was set after object initialization")

    def __dir__(self):
        """This is useful for tab completion in an ipython volshell."""
        result = self.members.keys() + super(Struct, self).__dir__()

        return result

    def walk_list(self, list_member, include_current=True):
        """Walk a single linked list in this struct.

        The current object can be optionally yielded as the first element.

        Args:
          list_member: The member name which points to the next item in the
          list.
        """
        if include_current:
            yield self

        seen = set()
        seen.add(self.obj_offset)

        item = self
        while True:
            item = item.m(list_member).deref()
            if not item or item.obj_offset in seen:
                break

            seen.add(item.obj_offset)
            yield item


## Profiles are the interface for creating/interpreting
## objects

class Profile(object):
    """ A profile is a collection of types relating to a certain
    system. We parse the abstract_types and join them with
    native_types to make everything work together.
    """
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

    # An empty type descriptor.
    EMPTY_DESCRIPTOR = [0, {}]

    def __init__(self, session=None, **kwargs):
        if kwargs:
            logging.error("Unknown keyword args {0}".format(kwargs))
        self.session = session
        self.overlayDict = {}
        self.overlays = []
        self.vtypes = {}
        self.constants = {}
        self.constant_addresses = {}
        self.applied_modifications = []
        self.applied_modifications.append(self.__class__.__name__)

        # This is the local cache of compiled expressions.
        self.flush_cache()

        class dummy(object):
            profile = self
            name = 'dummy'
            def is_valid_address(self, _offset):
                return True

            def read(self, _offset, _value):
                return ""

            def zread(self, offset, length):
                return "\x00" * length

        # A dummy address space used internally.
        self._dummy = dummy()

        # We initially populate this with objects in this module that will be
        # used everywhere
        self.object_classes = {'BitField': BitField,
                               'Pointer': Pointer,
                               'Void': Void,
                               'void': Void,
                               'Array': Array,
                               'ListArray': ListArray,
                               'NativeType': NativeType,
                               'Struct': Struct}

    def flush_cache(self):
        self.types = {}

    def copy(self):
        """Makes a copy of this profile."""
        result = self.__class__(session=self.session)
        result.vtypes = copy.deepcopy(self.vtypes)
        result.overlays = copy.deepcopy(self.overlays)
        result.applied_modifications = self.applied_modifications[:]

        # Object classes are shallow dicts.
        result.object_classes = self.object_classes.copy()

        return result

    @classmethod
    def metadata(cls, name, default=None):
        """Obtain metadata about this profile."""
        prefix = '_md_'

        return getattr(cls, prefix + name, default)

    @classmethod
    def metadatas(cls, *args):
        """Obtain metadata about this profile."""
        prefix = '_md_'

        return tuple([getattr(cls, prefix + x, None) for x in args])

    def has_type(self, theType):
        # Compile on demand
        self.compile_type(theType)

        return theType in self.object_classes or theType in self.vtypes

    def add_classes(self, classes_dict=None, **kwargs):
        """Add the classes in the dict to our object classes mapping."""
        self.flush_cache()

        if classes_dict:
            self.object_classes.update(classes_dict)

        self.object_classes.update(kwargs)

    def add_constants(self, constants_are_addresses=False, **kwargs):
        """Add the kwargs as constants for this profile."""
        self.flush_cache()

        for k, v in kwargs.iteritems():
            self.constants[k] = v
            if constants_are_addresses:
                # We need to interpret the value as a pointer.
                self.constant_addresses[Pointer.integer_to_address(v)] = k

    def add_types(self, abstract_types):
        self.flush_cache()

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

    def compile_type(self, type_name):
        """Compile the specific type and ensure it exists in the type cache."""
        if type_name in self.types:
            return

        type_descriptor = copy.deepcopy(
            self.vtypes.get(type_name, self.EMPTY_DESCRIPTOR))

        for overlay in self.overlays:
            type_overlay = copy.deepcopy(overlay.get(type_name))
            type_descriptor = self._apply_type_overlay(
                type_descriptor, type_overlay)

        # An overlay which specifies a string as a definition is simply an
        # alias for another struct.
        if isinstance(type_descriptor, str):
            self.compile_type(type_descriptor)
            self.types[type_name] = self.types[type_descriptor]
            return

        elif type_descriptor == self.EMPTY_DESCRIPTOR:
            # Mark that this is a pure object - not described by a vtype.
            self.types[type_name] = None

        else:
            # Now type_overlay will have all the overlays applied on it.
            members = {}
            size, field_descrition = type_descriptor

            for k, v in field_descrition.items():
                if callable(v):
                    members[k] = v
                elif v[0] == None:
                    logging.warning(
                        "{0} has no offset in object {1}. Check that vtypes "
                        "has a concrete definition for it.".format(k, type_name))
                else:
                    members[k] = (v[0], self.list_to_type(k, v[1]))

            ## Allow the class plugins to override the class constructor here
            cls = self.object_classes.get(type_name, Struct)

            self.types[type_name] =  Curry(
                cls, theType=type_name, members=members, struct_size=size)

    def legacy_field_descriptor(self, typeList):
        """Converts the list expression into a target, target_args notation.

        Legacy vtypes use lists to specify the objects. This function is used to
        convert from the legacy format to the more accurate modern
        format. Hopefully the legacy format can be deprecated at some point.

        Args:
           typeList: A list of types. e.g. ['pointer64', ['_HMAP_TABLE']]

        Returns:
           A target, target_args tuple. Target is the class name which should be
           instantiated, while target_args is a dict of args to be passed to
           this class.
           e.g. 'Pointer',  {target="_HMAP_TABLE"}
        """
        ## This is of the form [ '_HMAP_TABLE' ] - First element is the target
        ## name, with no args.
        if len(typeList) == 1:
            target = typeList[0]
            target_args = {}

        ## This is of the form [ 'pointer' , [ 'foobar' ]]
        ## Target is the first item, args is the second item.
        elif typeList[0] == 'pointer' or typeList[0] == 'pointer64':
            target = "Pointer"
            target_args = self.legacy_field_descriptor(typeList[1])

        ## This is an array: [ 'array', count, ['foobar'] ]
        elif typeList[0] == 'array':
            target = "Array"
            target_args = self.legacy_field_descriptor(typeList[2])
            target_args['count'] = typeList[1]

        elif len(typeList) > 2:
            logging.error("Invalid typeList %s" % (typeList,))

        else:
            target = typeList[0]
            target_args = typeList[1]

        return dict(target=target, target_args=target_args)

    def list_to_type(self, name, typeList):
        """Parses a specification list and returns a VType object.

        This function is a bit complex because we support lots of
        different list types for backwards compatibility.

        This is the core function which effectively parses the VType language.
        """
        # Convert legacy typeList expressions to the modern format.
        target_spec = self.legacy_field_descriptor(typeList)

        # The modern format uses a target, target_args notation.
        target = target_spec['target']
        target_args = target_spec['target_args']

        ## This is currently the recommended way to specify a type:
        ## e.g. [ 'Pointer', {target="int"}]
        if isinstance(target_args, dict):
            return Curry(self.Object, theType=target, name=name,
                         **target_args)

        # This is of the deprecated form ['class_name', ['arg1', 'arg2']].
        # Since the object framework moved to purely keyword args these are
        # meaningless. Issue a deprecation warning.
        elif type(target_args) == list:
            logging.warning(
                "Deprecated vtype expression %s for member %s, assuming int",
                typeList, name)

        else:
            ## If we get here we have no idea what this list is
            logging.warning("Unable to find a type for %s, assuming int",
                            typeList)

        return Curry(self.Object, theType='int', name = name)

    def _get_dummy_obj(self, name):
        """Make a dummy object on top of the dummy address space."""
        self.compile_type(name)

        # Make the object on the dummy AS.
        tmp = self.Object(theType = name, offset = 0, vm = self._dummy)
        return tmp

    def get_obj_offset(self, name, member):
        """ Returns a member's offset within the struct.

        Note that this can be wrong if the offset is a callable.
        """
        tmp = self._get_dummy_obj(name)
        if tmp is None:
            raise AttributeError("Object %s not known" % name)

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
        self.flush_cache()
        self.overlays.append(copy.deepcopy(overlay))

    def _apply_type_overlay(self, type_member, overlay):
        """Update the overlay with the missing information from type.

        If overlay has None in any slot it gets applied from vtype.

        Args:
         type_member: A descriptor for a single type struct. This is always of
           the following form:

           [StructSize, {
             field_name_1: [.... Field descriptor ...],
             field_name_2: [.... Field descriptor ...],
            }]

         overlay: An overlay descriptor for the same type described by
           type_member or a callable which will be used to instantiate the
           required type.
        """
        # A None in the overlay allows the vtype to bubble up.
        if overlay is None:
            return type_member

        if type_member is None:
            return overlay

        # this allows the overlay to just specify a class directly to be
        # instantiated for a particular type.
        if callable(overlay):
            return overlay

        # A base string means its an alias of another type.
        if isinstance(overlay, basestring):
            return overlay

        # Check the overlay and type descriptor for sanity.
        if len(overlay) != 2 or not isinstance(overlay[1], dict):
            raise RuntimeError("Overlay error: Invalid overlay %s" % overlay)

        if len(type_member) != 2 or not isinstance(type_member[1], dict):
            raise RuntimeError("VType error: Invalid type descriptor %s" %
                               type_member)

        # Allow the overlay to override the struct size.
        if overlay[0] is None:
            overlay[0] = type_member[0]

        # The field overlay describes each field in the struct.
        field_overlay = overlay[1]

        # Now go over all the fields in the type_member and copy them into the
        # overlay.
        for k, v in type_member[1].items():
            if k not in field_overlay:
                field_overlay[k] = v
            else:
                field_overlay[k] = self._apply_field_overlay(v, field_overlay[k])

        return overlay

    def _apply_field_overlay(self, field_member, field_overlay):
        """Update the field overlay with the missing information from type.

        If the overlay has None in any slot it gets applied from vtype.

        Args:
          field_member: A field descriptor. This can be of the modern form:

              [Offset, [TargetName, dict(arg1=value1, arg2=value2)]]

              The second part is termed the field descriptor. If the overlay
              specifies a field descriptor it will completely replace the
              vtype's descriptor.

              Alternatively we also support the legacy form:
              [TargetName, [values]]


              Note that if the Target name differs we deem the entire field to
              be overlayed and replace the entire definition with the overlayed
              one.

          field_overlay: Can be a field descriptor as above, or a callable - in
             which case this field member will be called when the field is
             accessed.
        """
        # A None in the overlay allows the vtype to bubble up.
        if field_overlay is None:
            return field_member

        # this allows the overlay to just specify a class directly to be
        # instantiated for a particular type.
        if callable(field_overlay):
            return field_overlay

        # Check the overlay and type descriptor for sanity.
        if len(field_overlay) != 2 or not isinstance(field_overlay[1], list):
            raise RuntimeError("Overlay error: Invalid overlay %s" % field_overlay)

        if len(field_member) != 2 or not isinstance(field_member[1], list):
            raise RuntimeError("VType error: Invalid field type descriptor %s" %
                               field_member)

        offset, field_descrition = field_member
        if field_overlay[0] is None:
            field_overlay[0] = offset

        if field_overlay[1] is None:
            field_overlay[1] = field_descrition

        return field_overlay

    def get_constant(self, constant):
        self.compile_type(constant)

        result = self.constants.get(constant)
        if result is None:
            result = NoneObject("Constant %s does not exist in profile." % constant)

        return result

    def get_constant_object(self, constant, target=None, target_args={}, **kwargs):
        """A help function for retrieving pointers from the symbol table."""
        self.compile_type(constant)

        kwargs.update(target_args)
        offset = self.get_constant(constant)
        if not offset:
            return offset

        result = self.Object(target, profile=self, offset=offset, **kwargs)
        return result

    def get_constant_by_address(self, address):
        return self.constant_addresses.get(Pointer.integer_to_address(address))

    def __dir__(self):
        """Support tab completion."""
        return sorted(set(self.__dict__.keys() +
                          self.vtypes.keys() +
                          self.object_classes.keys()))

    def __getattr__(self, attr):
        """Make it easier to instantiate individual members.

        This method makes it possible to use the form:

        self.profile._EPROCESS(vm=self.kernel_address_space, offset=X)

        Which is easier to type and works well with attribute completion
        (provided by __dir__).
        """
        self.compile_type(attr)

        if self.types[attr] is None and attr not in self.object_classes:
            raise AttributeError("No such vtype")

        return Curry(self.Object, attr)

    def Object(self, theType=None, offset=None, vm=None, name=None, parent=None,
               context=None, **kwargs):
        """ A function which instantiates the object named in theType (as
        a string) from the type in profile passing optional args of
        kwargs.

        Args:
          theType: The name of the Struct to instantiate (e.g. _EPROCESS).

          vm: The address space to instantiate the object onto. If not provided
            we use a dummy null padded address space.

          offset: The location in the address space where the object is
            instantiated.

          name: An optional name for the object.

          context: An opaque dict which is passed to all objects created from
            this object.

          parent: The object can maintain a reference to its parent object.
        """
        name = name or theType

        if offset is None:
            offset = 0
            if vm is None:
                vm = addrspace.BaseAddressSpace.classes["DummyAddressSpace"](
                    size=self.get_obj_size(name))

        else:
            offset = int(offset)
            if vm is None:
                if self.session and self.session.default_address_space:
                    vm = self.session.kernel_address_space
                else:
                    vm = self._dummy

            if not vm.is_valid_address(offset):
                # If we can not instantiate the object here, we just error out:
                return NoneObject(
                    "Invalid Address 0x{0:08X}, instantiating {1}".format(
                        offset, name))

        kwargs['profile'] = self

        # Compile the type on demand.
        self.compile_type(theType)

        # If the cache contains a None, this member is not represented by a
        # vtype (it might be a pure object class or a constant).
        if self.types[theType] is not None:
            result = self.types[theType](offset=offset, vm=vm, name=name,
                                         parent=parent, context=context, **kwargs)
            return result

        elif theType in self.object_classes:
            result = self.object_classes[theType](theType=theType,
                                                  offset=offset,
                                                  vm=vm,
                                                  name=name,
                                                  parent=parent,
                                                  context=context,
                                                  **kwargs)

            if isinstance(result, Struct):
                # This should not normally happen.
                logging.error("Instantiating a Struct class without an overlay. "
                              "Please ensure an overlay is defined.")

            return result

        else:
            # If we get here we have no idea what the type is supposed to be?
            logging.info("Cant find object {0} in profile {1}?".format(
                    theType, self))


PROFILE_CACHE = utils.FastStore()


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

    class _CM_KEY_INDEX(obj.Struct):
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

        # See if the profile is already cached. NOTE: This assumes that profiles
        # do not store any instance specific data - so any profile instance
        # which came from the same modifications is equivalent.

        # If any of these change we can not use the same profile instance:
        # session object, current modification, previous modifications.
        key = "%r:%s:%s" % (profile.session, cls.__name__, profile.applied_modifications)
        try:
            result = PROFILE_CACHE.Get(key)
        except KeyError:
            # Return a copy of the profile.
            result = profile.copy()
            res = cls.modify(result)
            result = res or result

            result.applied_modifications.append(cls.__name__)

            PROFILE_CACHE.Put(key, result)

        return result

    @classmethod
    def modify(cls, profile):
        """This class should modify the profile appropritately.

        The profile will be a copy of the original profile and will be returned
        to the class caller.

        Args:
           A profile to be modified.
        """
