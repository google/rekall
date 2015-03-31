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
Helper functions to make defining components nicer.

Exists solely to support rekall.entities.definitions.
"""
__author__ = "Adam Sindelar <adamsh@google.com>"

import datetime

from rekall import obj
from rekall import registry


class TypeDescriptor(object):
    """Defines a type descriptor, which can coerce values into target type."""

    type_name = None
    __metaclass__ = registry.MetaclassRegistry

    def chill_coerce(self, value):
        """Like coerce, but is chill about getting exceptions.

        Will returned coerced value if it can, otherwise will return value.
        """
        try:
            return self.coerce(value)
        except TypeError:
            return value

    def coerce(self, value):
        """Return value as this type or raise TypeError if not convertible."""
        return value

    def sortkey(self, coerced):
        return coerced

    def __repr__(self):
        return "%s" % type(self).__name__

    def __unicode__(self):
        return repr(self)

    def __str__(self):
        return repr(self)

    def __eq__(self, other):
        return self.type_name == other.type_name

    def __ne__(self, other):
        return not self.__eq__(other)


class ScalarDescriptor(TypeDescriptor):
    """Take an instance of type and calls its constructor to coerce."""

    default_instance = None
    type_cls = int

    def __init__(self, type_cls=None):
        super(ScalarDescriptor, self).__init__()
        if type_cls:
            self.type_cls = type_cls
        self.type_name = self.type_cls.__name__

    def coerce(self, value):
        if value == None:
            return None

        if isinstance(value, self.type_cls):
            return value

        return self.type_cls(value)

    def sortkey(self, coerced):
        if not coerced:
            return self.default_instance

        return coerced

    def __repr__(self):
        return "%s (scalar type)" % self.type_cls.__name__


class DatetimeDescriptor(ScalarDescriptor):
    """Python's datetime is a special snowflake that requires some massaging.

    This is just like ScalarDescriptor, except it works around the weirdness
    in datetime's sorting behavior and absence of default parameters in the
    constructor.
    """

    default_instance = datetime.datetime.fromtimestamp(0)
    type_cls = datetime.datetime

    def sortkey(self, coerced):
        return super(DatetimeDescriptor, self).sortkey(coerced).strftime("%s")


class BaseObjectDescriptor(TypeDescriptor):
    """Makes sure base objects are dereferenced."""

    def __init__(self):
        super(BaseObjectDescriptor, self).__init__()
        self.type_cls = obj.BaseObject
        self.type_name = "BaseObject"

    def coerce(self, value):
        if not value:
            return None

        if not isinstance(value, obj.BaseObject):
            raise TypeError(
                "%s is not a BaseObject." % value)

        if isinstance(value, obj.Pointer):
            return value.deref()

        return value

    def __repr__(self):
        return "BaseObject type"


class PointerDescriptor(TypeDescriptor):
    """Stores a pointer."""

    def __init__(self):
        super(PointerDescriptor, self).__init__()
        self.type_cls = obj.Pointer
        self.type_name = "Pointer"

    def coerce(self, value):
        if not value:
            return None

        if isinstance(value, obj.Pointer):
            return value

        if isinstance(value, obj.BaseObject):
            return value.obj_profile.Pointer(value=value.obj_offset,
                                             vm=value.obj_vm,
                                             target=value.obj_type)

        raise TypeError("%s is not a Pointer of a BaseObject." % value)


class NoneDescriptor(TypeDescriptor):
    "NoneDescriptor doesn't care."

    def __init__(self):
        super(NoneDescriptor, self).__init__()

    def coerce(self, value):
        return value

    def __repr__(self):
        return "untyped (NoneDescriptor)"


class TupleDescriptor(TypeDescriptor):
    """Declared for tuple types; coerces each member to its respective type."""

    type_name = "tuple"

    def __init__(self, tpl):
        super(TupleDescriptor, self).__init__()
        self.types = [TypeFactory(x) for x in tpl]

    def coerce(self, value):
        return tuple(self.types[i].coerce(x) for i, x in enumerate(value))

    def __repr__(self):
        return "(%s)" % ", ".join(self.types)


class ListDescriptor(TypeDescriptor):
    """Declared for nested types (e.g. list of ints)."""

    type_name = "list"

    def __init__(self, member_type):
        super(ListDescriptor, self).__init__()
        self.member_type = TypeFactory(member_type)

    def coerce(self, value):
        if value is None:
            return frozenset()
        return frozenset([self.member_type.coerce(x) for x in value])

    def __repr__(self):
        return "[%s] (list type)" % self.member_type


class EnumDescriptor(TypeDescriptor):
    """Defines an enum type for a component attribute."""

    type_name = "str"

    def __init__(self, *args):
        super(EnumDescriptor, self).__init__()
        self.legal_values = args

    def coerce(self, value):
        if value == None:
            return value

        if value not in self.legal_values:
            raise TypeError(
                "%s is not a valid value for enum %s" % (value,
                                                         self.legal_values))

        return value

    def __repr__(self):
        return "{%s} (enum type)" % ", ".join(self.legal_values)


def TypeFactory(type_desc):
    """Creates the appropriate TypeDescriptor or subclass instance.

    If given a type instance, will create TypeDescriptor (most common use).

    If given a set, will interpret it as enum and create EnumDescriptor.

    If given a tuple, will interpret as composite attribute and create a
    TupleDescriptor.

    If given a list, will interpret is as a nested type and create a
    ListDescriptor.
    """
    if isinstance(type_desc, TypeDescriptor):
        # Fall through for stuff defined explictly.
        return type_desc

    if isinstance(type_desc, type):
        return ScalarDescriptor(type_desc)

    if isinstance(type_desc, str):
        return TypeDescriptor.classes[type_desc]()

    if type_desc is None:
        return NoneDescriptor()

    if isinstance(type_desc, set):
        return EnumDescriptor(*type_desc)

    if isinstance(type_desc, tuple):
        return TupleDescriptor(type_desc)

    if isinstance(type_desc, list):
        return ListDescriptor(type_desc[0])

    raise TypeError("%s is not a valid type descriptor.", type_desc)
