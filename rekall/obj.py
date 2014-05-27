# Rekall Memory Forensics
# Copyright (C) 2007,2008 Volatile Systems
# Copyright 2013 Google Inc. All Rights Reserved.
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

"""
The Rekall Memory Forensics object system.

"""
__author__ = ("Michael Cohen <scudette@gmail.com> based on original code "
              "by AAron Walters and Brendan Dolan-Gavitt with contributions "
              "by Mike Auty")

import atexit
import inspect
import json
import logging
import pdb
import operator
import os
import struct
import copy

from rekall import addrspace
from rekall import registry
from rekall import utils

import traceback


class ProfileLog(object):
    # Point this environment variable into a filename we will use to store
    # profiling results.
    ENVIRONMENT_VAR = "DEBUG_PROFILE"

    class JSONEncoder(json.JSONEncoder):
        def default(self, obj):  # pylint: disable=method-hidden
            if isinstance(obj, set):
                return sorted(obj)

            return json.JSONEncoder.default(self, obj)

        @staticmethod
        def as_set(obj):
            for k in obj:
                if isinstance(obj[k], list):
                    obj[k] = set(obj[k])

            return obj

    def __init__(self):
        self.data = {}
        self.filename = os.environ.get(self.ENVIRONMENT_VAR)
        if self.filename:
            # Ensure we update the object access log when we exit.
            atexit.register(self._DumpData)

    def _MergeData(self, data):
        for profile, structs in data.items():
            if profile not in self.data:
                self.data[profile] = data[profile]
            else:
                for c_struct, fields in structs.items():
                    if c_struct not in self.data[profile]:
                        self.data[profile][c_struct] = fields
                    else:
                        self.data[profile][c_struct].update(fields)

    def _DumpData(self):
        try:
            with utils.FileLock(open(self.filename, "rb")) as fd:
                self._MergeData(json.loads(
                        fd.read(), object_hook=self.JSONEncoder.as_set))

                with open(self.filename, "wb") as fd:
                    fd.write(json.dumps(self.data, cls=self.JSONEncoder))

        except (IOError, ValueError):
            pass

        logging.info("Updating object access database %s", self.filename)
        with open(self.filename, "wb") as fd:
            fd.write(json.dumps(self.data, cls=self.JSONEncoder))

    def LogFieldAccess(self, profile, obj_type, field_name):
        # Do nothing unless the environment is set.
        if self.is_active():
            profile = self.data.setdefault(profile, {})
            fields = profile.setdefault(obj_type, set())
            if field_name:
                fields.add(field_name)

    def LogConstant(self, profile, name):
        self.LogFieldAccess(profile, "Constants", name)

    @staticmethod
    def is_active():
        return bool(os.environ.get(ProfileLog.ENVIRONMENT_VAR))


# This is used to store Struct member access when the DEBUG_PROFILE environment
# variable is set.
ACCESS_LOG = ProfileLog()


class Curry(object):
    def __init__(self, curry_target, *args, **kwargs):
        self._target = curry_target
        self._kwargs = kwargs
        self._args = args
        self._default_arguments = kwargs.pop("default_arguments", [])
        self.__doc__ = self._target.__doc__

    def __call__(self, *args, **kwargs):
        # Merge the kwargs with the new kwargs
        new_kwargs = self._kwargs.copy()
        new_kwargs.update(kwargs)
        return self._target(*(self._args + args), **new_kwargs)

    def get_default_arguments(self):
        """Return a list of default args for the target."""
        if self._default_arguments is not None:
            return self._default_arguments

        args, _, _, defaults = inspect.getargspec(self._target)
        if defaults:
            return args[-len(defaults):]

        return []

    def __getattr__(self, attr):
        return getattr(self._target, attr)


class NoneObject(object):
    """ A magical object which is like None but swallows bad
    dereferences, __getattr__, iterators etc to return itself.

    Instantiate with the reason for the error.
    """
    def __init__(self, reason="None Object", *args, **kwargs):
        # Often None objects are instantiated on purpose so its not really that
        # important to see their reason.
        if kwargs.get("log"):
            logging.log(logging.WARN, reason)
        self.reason = reason
        self.strict = kwargs.get("strict")
        self.args = args
        if self.strict:
            self.bt = ''.join(traceback.format_stack()[:-2])

    def __str__(self):
        return unicode(self).encode('utf-8')

    def __unicode__(self):
        ## If we are strict we blow up here
        if self.strict:
            if "%" in self.reason:
                reason = self.reason % self.args
            else:
                reason = self.reason.format(*self.args)
            logging.error("{0}\n{1}".format(reason, self.bt))

        return "-"

    def __repr__(self):
        if "%" in self.reason:
            reason = self.reason % self.args
        else:
            reason = self.reason.format(*self.args)

        return "<%s>" % reason

    def __format__(self, _):
        """We suppress output for all format operators."""
        return ""

    def write(self, _):
        """Write procedure only ever returns False"""
        return False

    ## Behave like an empty set
    def __iter__(self):
        return iter([])

    def __len__(self):
        return 0

    def __getattr__(self, attr):
        # By returning self for any unknown attribute and ensuring the self is
        # callable, we cover both properties and methods Override NotImplemented
        # functions in object with self
        return self

    def __bool__(self):
        return False

    def __nonzero__(self):
        return False

    # Comparisons.
    def __eq__(self, other):
        return other is None

    def __ne__(self, other):
        return other is not None

    def __gt__(self, _):
        return False

    __lt__ = __gt__
    __le__ = __gt__
    __ge__ = __gt__

    ## Make us subscriptable obj[j]
    def __getitem__(self, item):
        return self

    def __call__(self, *arg, **kwargs):
        return self

    def __int__(self):
        return -1

    __add__ = __call__
    __sub__ = __call__
    __mul__ = __call__
    __floordiv__ = __call__
    __mod__ = __call__
    __div__ = __call__
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

    def __getstate__(self):
        return dict(
            type="NoneObject",
            reason=self.reason
            )


class Error(Exception):
    """All object related exceptions come from this one."""


class ProfileError(Error):
    """Errors in setting the profile."""


class BaseObject(object):

    obj_parent = NoneObject("No parent")
    obj_name = NoneObject("No name")

    # BaseObject implementations may take arbitrary **kwargs. The usual
    # programming pattern is to define the keywords each class takes explicitely
    # as as a generic **kwargs parameter. Then call the baseclass and pass the
    # kwargs down. Any **kwargs which arrive here are not handled, and represent
    # an error in the vtype specifications.
    def __init__(self, type_name=None, offset=0, vm=None, profile=None,
                 parent=None, name='', context=None, session=None, **kwargs):
        """Constructor for Base object.

        Args:
          type_name: The name of the type of this object. This different
             from the class name, since the same class may implement many types
             (e.g. Struct implements every instance in the vtype definition).

          offset: The offset within the address space to this object exists.

          vm: The address space this object uses to read itself from.

          profile: The profile this object may use to dereference other
           types.

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

        self.obj_type = type_name

        # 64 bit addresses are always sign extended, so we need to clear the top
        # bits.
        self.obj_offset = Pointer.integer_to_address(int(offset or 0))
        self.obj_vm = vm
        self.obj_parent = parent
        self.obj_name = name
        self.obj_profile = profile
        self.obj_context = context or {}
        self.obj_session = session

    def __getstate__(self):
        return dict(
            type="BaseObject",
            offset=self.obj_offset,
            name=self.obj_name,
            type_name=self.obj_type,
            vm=self.obj_vm,
            )

    @property
    def obj_end(self):
        return self.obj_offset + self.size()

    @property
    def parents(self):
        """Returns all the parents of this object."""
        obj = self
        while obj.obj_parent:
            obj = obj.obj_parent
            yield obj

    def proxied(self):
        return None

    def write(self, value):
        """Function for writing the object back to disk"""
        pass

    def __nonzero__(self):
        """This method is called when we test the truth value of an Object.

        In rekall we consider an object to have True truth value only when it is
        a valid object. Its possible for example to have a Pointer object which
        is not valid - this will have a truth value of False.

        You should be testing for validity like this:
        if X:
           # object is valid

        Do not test for validity like this:

        if int(X) == 0:

        or

        if X is None:
          .....

        the later form is not going to work when X is a NoneObject.
        """
        result = self.obj_vm.is_valid_address(self.obj_offset)
        return result

    def __eq__(self, other):
        return self.v() == other or (
            (self.__class__ == other.__class__) and
            (self.obj_offset == other.obj_offset) and
            (self.obj_vm == other.obj_vm))

    def __ne__(self, other):
        return not self.__eq__(other)

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
        _ = vm
        return NoneObject("Can't dereference {0}".format(
                self.obj_name), self.obj_profile)

    def reference(self):
        """Produces a pointer to this object.

        This is the same as the C & operator and is the opposite of deref().
        """
        return self.obj_profile.Pointer(value=self.obj_offset, vm=self.obj_vm,
                                        target=self.obj_type)

    def cast(self, type_name=None, vm=None, **kwargs):
        return self.obj_profile.Object(
            type_name=type_name or self.obj_type, offset=self.obj_offset,
            vm=vm or self.obj_vm, parent=self.obj_parent,
            context=self.obj_context, **kwargs)

    def v(self, vm=None):
        """ Do the actual reading and decoding of this member

        When vm is specified, we are asked to evaluate this object is another
        address space than the one it was created on. Derived classes should
        allow for this.
        """
        _ = vm
        return NoneObject("No value for {0}".format(
                self.obj_name), self.obj_profile)

    def __str__(self):
        return utils.SmartStr(self)

    def __unicode__(self):
        return utils.SmartUnicode(self.v())

    def __repr__(self):
        return "[{0} {1}] @ 0x{2:08X}".format(
            self.__class__.__name__, self.obj_name,
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
            proxied = self.proxied()
            try:
                ## Try to coerce the other in case its also a proxied
                ## class
                args = list(args)
                args[0] = args[0].proxied()
            except (AttributeError, IndexError):
                pass

            try:
                method = getattr(operator, name)
                args = [proxied] + args
            except AttributeError:
                method = getattr(proxied, name)

            return method(*args, **kw)

        return method

    for name in mixin._specials:  # pylint: disable=protected-access
        setattr(mixin, name, make_method(name))

class NumericProxyMixIn(object):
    """ This MixIn implements the numeric protocol """
    _specials = [
        ## Number protocols
        '__add__', '__sub__', '__mul__',
        '__floordiv__', '__mod__', '__divmod__',
        '__pow__', '__lshift__', '__rshift__',
        '__and__', '__xor__', '__or__', '__div__',
        '__truediv__', '__radd__', '__rsub__',
        '__rmul__', '__rdiv__', '__rtruediv__',
        '__rfloordiv__', '__rmod__', '__rdivmod__',
        '__rpow__', '__rlshift__',
        '__rrshift__', '__rand__', '__rxor__', '__ror__',
        '__neg__', '__pos__',
        '__abs__', '__invert__', '__int__', '__long__',
        '__float__', '__oct__', '__hex__',

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
    def __init__(self, value=None, format_string=None, **kwargs):
        super(NativeType, self).__init__(**kwargs)
        self.format_string = format_string
        self.value = value

    def write(self, data):
        """Writes the data back into the address space"""
        output = struct.pack(self.format_string, int(data))
        return self.obj_vm.write(self.obj_offset, output)

    def proxied(self):
        return self.v()

    def __radd__(self, other):
        return long(other) + self.v()

    def __rsub__(self, other):
        return long(other) - self.v()

    def size(self):
        return struct.calcsize(self.format_string)

    def v(self, vm=None):
        if self.value is not None:
            return self.value

        data = self.obj_vm.read(self.obj_offset, self.size())
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

    def __getstate__(self):
        state = super(NativeType, self).__getstate__()
        state["type"] = "NativeType"
        state["value"] = self.v()

        return state


class Bool(NativeType):
    def __unicode__(self):
        """Format boolean values nicely."""
        return unicode(bool(self))


class BitField(NativeType):
    """ A class splitting an integer into a bunch of bit. """
    def __init__(self, start_bit=0, end_bit=32, target=None,
                 native_type=None, **kwargs):
        super(BitField, self).__init__(**kwargs)

        # TODO: Fully deprecate this parameter.
        if native_type:
            target = native_type

        self._proxy = self.obj_profile.Object(
            target or "address", offset=self.obj_offset, vm=self.obj_vm,
            context=self.obj_context)

        self.target = target
        self.start_bit = start_bit
        self.end_bit = end_bit

    def size(self):
        return self._proxy.size()

    def v(self, vm=None):
        i = self._proxy.v()
        return (i & ((1 << self.end_bit) - 1)) >> self.start_bit

    def write(self, data):
        # To write we need to read the proxy, set the bits and then write the
        # proxy again.
        return False

    def __nonzero__(self):
        return self != 0


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

    def size(self):
        return self._proxy.size()

    def v(self, vm=None):
        # 64 bit addresses are always sign extended so we need to clear the top
        # bits.
        return Pointer.integer_to_address(self._proxy.v())

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

    def dereference(self, vm=None):
        offset = self.v()

        # Casts into the correct AS:
        vm = vm or self.obj_vm

        if vm.is_valid_address(offset):
            kwargs = copy.deepcopy(self.target_args)
            kwargs.update(dict(offset=offset,
                               vm=vm, profile=self.obj_profile,
                               parent=self.obj_parent, name=self.obj_name))

            if isinstance(self.target, basestring):
                result = self.obj_profile.Object(
                    type_name=self.target,
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

        This ideas here is to make it possible to easily write a condition such
        as:

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

        return self.__class__(
            target=self.target, target_args=self.target_args,
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

    def __unicode__(self):
        return u"Pointer to %s" % self.deref()

    def __getattr__(self, attr):
        ## We just dereference ourself
        result = self.dereference()

        return getattr(result, attr)

    def __iter__(self):
        """Delegate the iterator to the target."""
        return iter(self.dereference())

    def dereference_as(self, target=None, target_args=None, vm=None,
                       profile=None, parent=None):
        """Dereference ourselves into another type, or address space.

        This method allows callers to explicitly override the setting in the
        profile for this pointer.

        Args:
          target: The target to override.
          target_args: The args to instantiate this target with.
          vm: The address space to dereference the pointer in.
          profile: If a new profile should be used to instantiate the target.
        """
        vm = vm or self.obj_vm

        if profile is None:
            profile = self.obj_profile

        return profile.Object(
            type_name=target or self.target, offset=self.v(), vm=vm,
            parent=parent or self.obj_parent, context=self.obj_context,
            **(target_args or {}))

    @staticmethod
    def integer_to_address(value):
        """Addresses only use 48 bits."""
        return 0xffffffffffff & int(value)

    def __getstate__(self):
        state = super(Pointer, self).__getstate__()
        state["type"] = "Pointer"
        state["target"] = self.target
        return state


class Void(Pointer):
    def __init__(self, **kwargs):
        kwargs['type_name'] = 'unsigned long'
        super(Void, self).__init__(**kwargs)

    def v(self, vm=None):
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

    def __init__(self, count=0, target=None, target_args=None,
                 target_size=None, max_count=100000, size=0,
                 **kwargs):
        """Instantiate an array of like items.

        Args:
          count: How many items belong to the array (not strictly enforced -
            i.e. it is possible to read past the end). By default the array is
            unbound.

          max_count: The maximum size of the array. This is a safety mechanism
            if count is calculated. max_count should be set to an upper bound on
            the size of the array.

          target: The name of the element to be instantiated on each point. The
            size of the object returned by this should be the same for all
            members of the array (i.e. all elements should be the same size).

          size: The total size of the Array. If this is nonzero we calculate the
          count so that just the right number of items fit in this specified
          size.
        """
        super(Array, self).__init__(**kwargs)

        # Allow the count to be callable.
        if callable(count):
            count = count(self.obj_parent)

        if callable(target_size):
            target_size = target_size(self.obj_parent)

        self.count = count
        self.max_count = max_count

        if not target:
            raise AttributeError("Array must use a target parameter")

        self.target = target
        self.target_args = target_args or {}

        self.target_size = target_size
        if self.target_size is None:
            self.target_size = self.obj_profile.Object(
                self.target, offset=self.obj_offset, vm=self.obj_vm,
                profile=self.obj_profile, parent=self,
                **self.target_args).size()

        if size > 0:
            self.count = size / self.target_size

    def size(self):
        """The size of the entire array."""
        return self.target_size * self.count

    def __iter__(self):
        # If the array is invalid we do not iterate.
        if self.obj_vm.is_valid_address(self.obj_offset):
            for position in xrange(0, self.count):
                # Since we often calculate array counts it is possible to
                # calculate huge arrays. This will then spin here
                # uncontrollably. We use max_count as a safety to break out
                # early - but we need to ensure that users see we hit this
                # artificial limit.
                if position > self.max_count:
                    if self.obj_session.GetParameter("debug"):
                        pdb.set_trace()

                    logging.warn("%s Array iteration truncated by max_count!",
                                 self.obj_name)
                    break

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

    def __unicode__(self):
        result = [repr(self)]
        for i, x in enumerate(self):
            result.append(u"0x%04X %r" % (i, x))

            if len(result) > 10:
                result.append(u"... More entries hidden")
                break

        return u"\n".join(result)

    def __eq__(self, other):
        if not other or self.count != len(other):
            return False

        for i in xrange(self.count):
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

    def __getstate__(self):
        state = super(Array, self).__getstate__()
        state["type"] = "Array"
        state["target"] = self.target
        state["count"] = self.count

        return state



class ListArray(Array):
    """An array of structs which do not all have the same size."""

    def __init__(self, maximum_size=None, maximum_offset=None, **kwargs):
        """Constructor.

        This array may be initialized using one of the following parameters:

        maximum_size: The maximum size of the array in bytes.
        maximum_offset: If we reach this offset iteration is terminated.
        count: The total count of items in this list.

        max_count: The maximum size of the array. This is a safety mechanism if
          count is calculated. max_count should be set to an upper bound on the
          size of the array.
        """
        super(ListArray, self).__init__(**kwargs)
        if callable(maximum_size):
            maximum_size = int(maximum_size(self.obj_parent))

        if callable(maximum_offset):
            maximum_offset = int(maximum_offset(self.obj_parent))

        # Check the values for sanity.
        if self.count == 0 and maximum_size is None and maximum_offset is None:
            raise TypeError(
                "One of count, maximum_offset, maximum_size must be specified.")

        if maximum_size is not None:
            maximum_offset = self.obj_offset + maximum_size

        self.maximum_offset = maximum_offset

    def __len__(self):
        """It is generally too expensive to rely on the count of this array."""
        raise NotImplementedError

    def size(self):
        """It is generally too expensive to rely on the size of this array."""
        raise NotImplementedError

    def __iter__(self):
        offset = self.obj_offset
        count = 0
        while 1:
            # Exit conditions.
            if self.maximum_offset and offset > self.maximum_offset:
                break

            if self.count and count >= self.count:
                break

            if count >= self.max_count:
                logging.warn("%s ListArray iteration truncated by max_count!",
                             self.obj_name)
                break

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
    """A mixin providing comparison operators for its base offset."""
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
    def __init__(self, members=None, struct_size=0, **kwargs):
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
        ACCESS_LOG.LogFieldAccess(self.obj_profile.name, self.obj_type, None)

        if not members:
            # Warn rather than raise an error, since some types (_HARDWARE_PTE,
            # for example) are generated without members
            logging.debug("No members specified for Struct %s named %s",
                          self.obj_type, self.obj_name)
            members = {}

        self.members = members
        self.struct_size = struct_size

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
        return "[{0} {1}] @ 0x{2:08X}".format(
            self.obj_type, self.obj_name or '', self.obj_offset)

    def __unicode__(self):
        result = self.__repr__() + "\n"
        width_name = 0

        fields = []
        # Print all the fields sorted by offset within the struct.
        for k in self.members:
            width_name = max(width_name, len(k))
            obj = self.m(k)
            fields.append(
                (getattr(obj, "obj_offset", self.obj_offset) -
                 self.obj_offset, k, repr(obj)))

        fields.sort()

        return result + "\n".join(
            ["  0x%02X %s%s %s" % (offset, k, " " * (width_name - len(k)), v)
             for offset, k, v in fields]) + "\n"

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
        ACCESS_LOG.LogFieldAccess(self.obj_profile.name, self.obj_type, attr)

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
        result = self.m(attr)
        if result == None:
            raise AttributeError(attr)

        return result

    def SetMember(self, attr, value):
        """Write a value to a member."""
        member = self.m(attr)
        # Try to make the member write the new value.
        if not hasattr(member, 'write') or not member.write(value):
            raise ValueError("Error writing value to member " + attr)

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
            item = getattr(item, list_member).deref()

            # Sometimes in usermode page 0 is mapped, hence bool(item) == True
            # even if item == 0 since bool(item) refers to the pointer's
            # validity.
            if not item or item == 0 or item.obj_offset in seen:
                break

            seen.add(item.obj_offset)
            yield item

    def __getstate__(self):
        state = super(Struct, self).__getstate__()
        state["type"] = "Struct"

        return state


## Profiles are the interface for creating/interpreting
## objects

class Profile(object):
    """A collection of types relating to a single compilation unit.

    Profiles are usually not instantiated directly. Rather, the profiles are
    loaded from the profile repository using the session.LoadProfile() method.
    """
    # This is the list of overlays to be applied to the vtypes when compiling
    # into types.
    overlays = None

    # These are the vtypes - they are just a dictionary describing the types
    # using the "vtype" language. This dictionary will be compiled into
    # executable code and placed into self.types.
    vtypes = None

    # This hold the executable code compiled from the vtypes above.
    types = None

    # This holds all the entity collectors indexed by names of components that
    # they produce.
    collectors = None

    # This is the base class for all profiles.
    __metaclass__ = registry.MetaclassRegistry

    # This is a dict of constants
    constants = None

    # This is a record of all the modification classes that were applied to this
    # profile.
    applied_modifications = None

    # An empty type descriptor.
    EMPTY_DESCRIPTOR = [0, {}]

    # The metadata for this profile. This should be specified by derived
    # classes. It is OK To put a (mutable) dict in here. It will not be
    # directory modified by anything.
    METADATA = {}

    # The constructor will build this dict of metadata by copying the values
    # from METADATA here.
    _metadata = None

    @classmethod
    def LoadProfileFromData(cls, data, session=None, name=None):
        """Creates a profile directly from a JSON object.

        Args:
          data: A data structure of an encoded profile. Described:
          http://www.rekall-forensic.com/docs/development.html#_profile_serializations

        Returns:
          a Profile() instance.

        Raises:
          IOError if we can not load the profile.
        """
        metadata = data.get("$METADATA")
        if metadata:
            profile_type = metadata.get("Type", "Profile")

            # Support a symlink profile - this is a profile which is a short,
            # human meaningful name for another profile.
            if profile_type == "Symlink":
                return session.LoadProfile(metadata.get("Target"))

            profile_cls = cls.classes.get(metadata["ProfileClass"])

            if profile_cls is None:
                logging.warn("No profile implementation class %s" %
                             metadata["ProfileClass"])

                raise IOError(
                    "No profile implementation class %s" %
                    metadata["ProfileClass"])

            result = profile_cls(name=name, session=session,
                                 metadata=metadata)

            result._SetupProfileFromData(data)  # pylint: disable=protected-access
            return result

    def _SetupProfileFromData(self, data):
        """Sets up the current profile."""
        # The constants are stored both in the $CONSTANTS section and the
        # $FUNCTIONS section. We treat them the same here.
        for section in ["$CONSTANTS", "$FUNCTIONS"]:
            constants = data.get(section)
            if constants:
                self.add_constants(
                    constants_are_addresses=True, **constants)

        # The enums
        enums = data.get("$ENUMS")
        if enums:
            self.add_enums(**enums)

        # The reverse enums
        reverse_enums = data.get("$REVENUMS")
        if reverse_enums:
            self.add_reverse_enums(**reverse_enums)

        types = data.get("$STRUCTS")
        if types:
            self.add_types(types)

    @classmethod
    def Initialize(cls, profile):
        """Install required types, classes and constants.

        This method should be extended by derived classes. It is a class method
        to allow other profiles to call this method and install the various
        components into their own profiles.
        """
        # Basic types used in all profiles.
        profile.add_classes({'BitField': BitField,
                             'Pointer': Pointer,
                             'Void': Void,
                             'void': Void,
                             'Array': Array,
                             'ListArray': ListArray,
                             'NativeType': NativeType,
                             'Struct': Struct})

        profile._initialized = True  # pylint: disable=protected-access

    def __init__(self, name=None, session=None, metadata=None, **kwargs):
        if kwargs:
            logging.error("Unknown keyword args {0}".format(kwargs))

        if name is None:
            name = self.__class__.__name__

        self._metadata = self.METADATA.copy()
        for basecls in reversed(self.__class__.__mro__):
            self._metadata.update(getattr(basecls, "METADATA", {}))

        self._metadata.update(metadata or {})

        self.name = name
        self.session = session
        if session is None:
            raise RuntimeError("Session must be specified.")

        self.overlays = []
        self.vtypes = {}
        self.collectors = {
            "Entity": [],
        }
        self.constants = {}
        self.constant_addresses = utils.SortedCollection(key=lambda x: x[0])
        self.enums = {}
        self.reverse_enums = {}
        self.applied_modifications = set()
        self.object_classes = {}

        # Keep track of all the known types so we can command line complete.
        self.known_types = set()

        # This is the local cache of compiled expressions.
        self.flush_cache()

        class dummy(object):
            profile = self
            name = 'dummy'
            def is_valid_address(self, _offset):
                return True

            def read(self, _, length):
                return "\x00" * length

        # A dummy address space used internally.
        self._dummy = dummy()

        # Call Initialize on demand.
        self._initialized = False

    def EnsureInitialized(self):
        if not self._initialized:
            self.Initialize(self)

    def flush_cache(self):
        self.types = {}

    def copy(self):
        """Makes a copy of this profile."""
        self.EnsureInitialized()

        # pylint: disable=protected-access
        result = self.__class__(name=self.name, session=self.session)
        result.vtypes = self.vtypes.copy()
        result.collectors = self.collectors.copy()
        result.overlays = self.overlays[:]
        result.enums = self.enums.copy()
        result.reverse_enums = self.reverse_enums.copy()
        result.constants = self.constants.copy()
        result.constant_addresses = self.constant_addresses.copy()

        # Object classes are shallow dicts.
        result.object_classes = self.object_classes.copy()
        result._initialized = self._initialized
        result.known_types = self.known_types.copy()
        result._metadata = self._metadata.copy()
        # pylint: enable=protected-access

        return result

    def merge(self, other):
        """Merges another profile into this one.

        The result is that we are able to parse all the types that the other
        profile has.
        """
        other.EnsureInitialized()

        self.vtypes.update(other.vtypes)
        self.collectors.update(other.collectors)
        self.overlays += other.overlays
        self.constants.update(other.constants)
        self.object_classes.update(other.object_classes)
        self.flush_cache()
        self.name = "%s + %s" % (self.name, other.name)

        # Merge in the other's profile metadata which is not in this profile.
        metadata = other._metadata.copy()  # pylint: disable=protected-access
        metadata.update(self._metadata)
        self._metadata = metadata

    def metadata(self, name, default=None):
        """Obtain metadata about this profile."""
        self.EnsureInitialized()
        return self._metadata.get(name, default)

    def set_metadata(self, name, value):
        self._metadata[name] = value

    def metadatas(self, *args):
        """Obtain metadata about this profile."""
        self.EnsureInitialized()
        return tuple([self._metadata.get(x) for x in args])

    def has_type(self, type_name):
        # Make sure we are initialized on demand.
        self.EnsureInitialized()
        return type_name in self.vtypes

    def has_class(self, class_name):
        # Make sure we are initialized on demand.
        self.EnsureInitialized()
        return class_name in self.object_classes

    def add_classes(self, classes_dict=None, **kwargs):
        """Add the classes in the dict to our object classes mapping."""
        self.flush_cache()

        if classes_dict:
            self.object_classes.update(classes_dict)

        self.object_classes.update(kwargs)
        self.known_types.update(kwargs)

    def add_constants(self, constants_are_addresses=False, **kwargs):
        """Add the kwargs as constants for this profile."""
        self.flush_cache()

        for k, v in kwargs.iteritems():
            self.constants[k] = v
            if constants_are_addresses:
                try:
                    # We need to interpret the value as a pointer.
                    address = Pointer.integer_to_address(v)
                    if (address, 0) not in self.constant_addresses:
                        self.constant_addresses.insert((address, k))

                except ValueError:
                    pass

    def add_reverse_enums(self, **kwargs):
        """Add the kwargs as a reverse enum for this profile."""
        for k, v in kwargs.iteritems():
            self.reverse_enums[k] = str(v)

    def add_enums(self, **kwargs):
        """Add the kwargs as an enum for this profile."""
        # Alas JSON converts integer keys to strings.
        for k, v in kwargs.iteritems():
            self.enums[k] = enum_definition = {}
            for enum, name in v.items():
                enum_definition[str(enum)] = name

    def add_types(self, abstract_types):
        self.flush_cache()

        abstract_types = copy.deepcopy(abstract_types)
        self.known_types.update(abstract_types)

        ## we merge the abstract_types with self.vtypes and then recompile
        ## the whole thing again. This is essential because
        ## definitions may have changed as a result of this call, and
        ## we store curried objects (which might keep their previous
        ## definitions).
        for k, v in abstract_types.items():
            if isinstance(v, list):
                self.vtypes[k] = v

            else:
                original = self.vtypes.get(k, self.EMPTY_DESCRIPTOR)
                original[1].update(v[1])
                if v[0]:
                    original[0] = v[0]

                self.vtypes[k] = original

    def compile_type(self, type_name):
        """Compile the specific type and ensure it exists in the type cache.

        The type_name here is a reference to the vtypes which are loaded into
        the profile.
        """
        # Make sure we are initialized on demand.
        self.EnsureInitialized()
        if type_name in self.types:
            return

        original_type_descriptor = type_descriptor = copy.deepcopy(
            self.vtypes.get(type_name, self.EMPTY_DESCRIPTOR))

        for overlay in self.overlays:
            type_overlay = copy.deepcopy(overlay.get(type_name))
            type_descriptor = self._apply_type_overlay(
                type_descriptor, type_overlay)

        # An overlay which specifies a string as a definition is simply an alias
        # for another struct. We just copy the old struct in place of the
        # aliased one.
        if isinstance(type_descriptor, str):
            self.compile_type(type_descriptor)
            self.types[type_name] = self.types[type_descriptor]
            type_descriptor = self.vtypes[type_descriptor]

        if type_descriptor == self.EMPTY_DESCRIPTOR:
            # Mark that this is a pure object - not described by a
            # vtype. E.g. it is purely a class.
            self.types[type_name] = None

        else:
            # Now type_overlay will have all the overlays applied on it.
            members = {}
            callable_members = {}

            size, field_descrition = type_descriptor

            for k, v in field_descrition.items():
                # If the overlay specifies a callable, we place it in the
                # callable_members dict, and revert back to the vtype
                # definition.
                if callable(v):
                    callable_members[k] = v

                    # If the callable is masking an existing field, revert back
                    # to it.
                    original_v = original_type_descriptor[1].get(k)
                    if original_v:
                        members[k] = (original_v[0],
                                      self.list_to_type(k, original_v[1]))

                elif v[0] == None:
                    logging.warning(
                        "{0} has no offset in object {1}. Check that vtypes "
                        "has a concrete definition for it.".format(
                            k, type_name))
                else:
                    members[k] = (v[0], self.list_to_type(k, v[1]))

            ## Allow the class plugins to override the class constructor here
            cls = self.object_classes.get(type_name, Struct)

            self.types[type_name] = self._make_struct_callable(
                cls, type_name, members, size, callable_members)

    def _make_struct_callable(self, cls, type_name, members, size,
                              callable_members):
        """Compile the structs class into a callable.

        For write support we would like to add a __setattr__ on the struct
        classes. However, in python, once there is a __setattr__ method
        defined on an object, _EVERY_ setattr() operation on the object will
        go through this method - this is a performance killer. Since in this
        case we only want to trap accesses to the member fields, we can create
        a class with @property methods to get and set the attributes. We then
        overlay this class over the original struct class.

        The resulting callable will instantiate the derived class (with the
        additional properties) over the provided offset.

        Note that due to the JIT compiler, this method is called only once when
        each Struct object is first accessed, so it is not really
        expensive. OTOH the callables we produce here are called many many times
        (Each time the object is instantiated, or a field is accessed) and need
        to be as fast as possible.
        """
        # Note that lambdas below must get external parameters through default
        # args:
        # http://stackoverflow.com/questions/938429/scope-of-python-lambda-functions-and-their-parameters/938493#938493

        properties = {}
        for name in set(members).union(callable_members):

            # Do not mask hand written methods with autogenerated properties.
            if hasattr(cls, name):
                continue

            cb = callable_members.get(name)
            value = members.get(name)

            getter = None
            setter = None

            # This happens if the overlay specifies a callable. In that case we
            # install a special property which calls it. However, the callable
            # may still refer to self.m() to get the bare vtype item.
            if cb:
                # Only implement getter for callable fields since setters do
                # not really make sense.
                getter = lambda self, cb=cb: cb(self)

            elif value:
                # Specify both getters and setter for the field.
                getter = lambda self, name=name: self.m(name)
                setter = lambda self, v=value, n=name: self.SetMember(n, v)

            properties[name] = property(getter, setter, None, name)

        # Extend the provided class by attaching the properties to it. We can
        # not just monkeypatch here because cls will be shared between all
        # structs which do not define an explicit extension class. By creating a
        # new temporary class this uses the usual inheritance behaviour to
        # override the methods in cls depending on the members dict, without
        # altering the cls class permanently (This is a kind of metaclass
        # programming).
        derived_cls = type(str(type_name), (cls,), properties)

        return Curry(derived_cls,
                     type_name=type_name, members=members, struct_size=size)

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
            return Curry(self.Object, type_name=target, name=name,
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

        return Curry(self.Object, type_name='int', name=name)

    def _get_dummy_obj(self, name):
        """Make a dummy object on top of the dummy address space."""
        self.compile_type(name)

        # Make the object on the dummy AS.
        tmp = self.Object(type_name=name, offset=0, vm=self._dummy)
        return tmp

    def get_obj_offset(self, name, member):
        """ Returns a member's offset within the struct.

        Note that this can be wrong if the offset is a callable.
        """
        ACCESS_LOG.LogFieldAccess(self.name, name, member)

        tmp = self._get_dummy_obj(name)
        return tmp.members.get(member, NoneObject("No member"))[0]

    def get_obj_size(self, name):
        """Returns the size of a struct"""
        tmp = self._get_dummy_obj(name)
        return tmp.size()

    def obj_has_member(self, name, member):
        """Returns whether an object has a certain member"""
        ACCESS_LOG.LogFieldAccess(self.name, name, member)

        tmp = self._get_dummy_obj(name)
        return hasattr(tmp, member)

    def add_overlay(self, overlay):
        """Add an overlay to the current overlay stack."""
        self.flush_cache()
        self.overlays.append(copy.deepcopy(overlay))
        self.known_types.update(overlay)

    def add_collector(self, components, collector):
        """Add a collector for a particular entity component.

        Arguments:
          collector: A Callable that takes instance of Session as argument
            and yields tuples of (identity, components)

          components: Call the collector when this component is requested.
        """
        for component in components:
            self.collectors.setdefault(component, []).append(collector)

        self.collectors["Entity"].append(collector)

    def get_collectors(self, component):
        """Get collectors that yield a particular component."""
        for name, collectors in self.collectors.iteritems():
            if component == name:
                for collector in collectors:
                    yield collector

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
                field_overlay[k] = self._apply_field_overlay(
                    v, field_overlay[k])

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

        if callable(field_overlay):
            return field_overlay

        # Check the overlay and type descriptor for sanity.
        if len(field_overlay) != 2 or not isinstance(field_overlay[1], list):
            raise RuntimeError(
                "Overlay error: Invalid overlay %s" % field_overlay)

        if len(field_member) != 2 or not isinstance(field_member[1], list):
            raise RuntimeError("VType error: Invalid field type descriptor %s" %
                               field_member)

        offset, field_descrition = field_member
        if field_overlay[0] is None:
            field_overlay[0] = offset

        if field_overlay[1] is None:
            field_overlay[1] = field_descrition

        return field_overlay

    def get_constant(self, constant, is_address=False):
        """Retrieve a constant from the profile.

        Args:
           constant: The name of the constant to retrieve.

           is_address: If true the constant is converted to an address.
        """
        self.compile_type(constant)

        ACCESS_LOG.LogConstant(self.name, constant)

        result = self.constants.get(constant)
        if result is None:
            result = NoneObject(
                "Constant %s does not exist in profile." % constant)

        elif is_address:
            result = Pointer.integer_to_address(result)

        return result

    def get_constant_object(self, constant, target=None, target_args=None,
                            vm=None, **kwargs):
        """A help function for retrieving pointers from the symbol table."""
        self.compile_type(constant)
        if vm is None:
            vm = self.session.GetParameter("default_address_space")

        kwargs.update(target_args or {})
        offset = self.get_constant(constant, is_address=True)
        if not offset:
            return offset

        result = self.Object(target, profile=self, offset=offset, vm=vm,
                             **kwargs)
        return result

    def get_constant_by_address(self, address):
        address = Pointer.integer_to_address(address)

        lowest_eq, name = self.get_nearest_constant_by_address(address)
        if lowest_eq != address:
            return NoneObject("Constant not found")

        return name

    def get_nearest_constant_by_address(self, address, below=True):
        """Returns the closest constant below or equal to the address."""
        address = Pointer.integer_to_address(address)

        if below:
            func = self.constant_addresses.find_le
        else:
            func = self.constant_addresses.find_ge

        try:
            offset, name = func(address)

            return offset, name
        except ValueError:
            return -1, NoneObject("Constant not found")

    def get_enum(self, enum_name, field=None):
        result = self.enums.get(enum_name)
        if result and field != None:
            result = result.get(field)
        return result

    def get_reverse_enum(self, enum_name, field=None):
        result = self.reverse_enums.get(enum_name)
        if result and field != None:
            result = result.get(field)
        return result

    def __dir__(self):
        """Support tab completion."""
        return sorted(self.__dict__.keys() + list(self.known_types))

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

    def Object(self, type_name=None, offset=None, vm=None, name=None,
               parent=None, context=None, session=None, **kwargs):
        """ A function which instantiates the object named in type_name (as
        a string) from the type in profile passing optional args of
        kwargs.

        Args:
          type_name: The name of the Struct to instantiate (e.g. _EPROCESS).

          vm: The address space to instantiate the object onto. If not provided
            we use a dummy null padded address space.

          offset: The location in the address space where the object is
            instantiated.

          name: An optional name for the object.

          context: An opaque dict which is passed to all objects created from
            this object.

          parent: The object can maintain a reference to its parent object.
        """
        name = name or type_name
        if session is None:
            session = self.session

        # Ensure we are called correctly.
        if not isinstance(name, basestring):
            raise ValueError("Type name must be a string")

        if offset is None:
            offset = 0
            if vm is None:
                vm = addrspace.BaseAddressSpace.classes["DummyAddressSpace"](
                    size=self.get_obj_size(name), session=session)

        else:
            offset = int(offset)
            if vm is None:
                vm = self.session.GetParameter("default_address_space")

            if not vm.is_valid_address(offset):
                # If we can not instantiate the object here, we just error out:
                return NoneObject(
                    "Invalid Address 0x{0:08X}, instantiating {1}".format(
                        offset, name))

        kwargs['profile'] = self

        # Compile the type on demand.
        self.compile_type(type_name)

        # If the cache contains a None, this member is not represented by a
        # vtype (it might be a pure object class or a constant).
        if self.types[type_name] is not None:
            result = self.types[type_name](
                offset=offset, vm=vm, name=name,
                parent=parent, context=context,
                session=session, **kwargs)
            return result

        elif type_name in self.object_classes:
            result = self.object_classes[type_name](
                type_name=type_name,
                offset=offset,
                vm=vm,
                name=name,
                parent=parent,
                context=context,
                session=session,
                **kwargs)

            if isinstance(result, Struct):
                # This should not normally happen.
                logging.error(
                    "Instantiating a Struct class without an overlay. "
                    "Please ensure an overlay is defined.")

            return result

        else:
            # If we get here we have no idea what the type is supposed to be?
            return NoneObject("Cant find object {0} in profile {1}?".format(
                    type_name, self))

    def __unicode__(self):
        return u"<%s profile %s (%s)>" % (
            self.metadata("arch"), self.name, self.__class__.__name__)

    def __repr__(self):
        return unicode(self)


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
         self.profile = obj.ProfileModification.classes[
             'VolRegistrySupport'](self.profile)

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
        # Return a copy of the profile.
        result = profile.copy()

        # Apply the modification.
        cls.modify(result)

        return result

    @classmethod
    def modify(cls, profile):
        """This class should modify the profile appropritately.

        The profile will be a copy of the original profile and will be returned
        to the class caller.

        Args:
           A profile to be modified.
        """
