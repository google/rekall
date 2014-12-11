# Rekall Memory Forensics
#
# Copyright 2014 Google Inc. All Rights Reserved.
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

import collections
import operator

from rekall import registry

from rekall.entities import superposition
from rekall.entities import types


# DeclareComponent will ensure this namedtuple has a field for every type of
# component we define in rekall.entities.definitions. It's used as a
# high-performance container class by the Entity class.
ComponentContainer = collections.namedtuple("ComponentContainer", [])

# An empty instance (prototype) of ComponentContainer used for quickly
# instantiating entities.
CONTAINER_PROTOTYPE = ComponentContainer()


class Attribute(object):
    """Represents an attribute, which can be a field or an alias.

    Properties:
    name: This is the property name on the Component subclass. E.g. "pid".
    typedesc: Instance of Typedesc or subclass, describing the type.
    docstring: Docstring needs no docstring.
    component: Component subclass that owns this attribute (e.g. Process)
    hidden: Is this visible in result printouts by default?
    width: How wide is the result by default? (Number of characters.)
    """

    def __init__(self, name, typedesc, docstring, component=None,
                 hidden=False, width=20, style="compact"):
        self.name = name
        self.typedesc = types.TypeFactory(typedesc)
        self.docstring = docstring
        self.component = component
        self.hidden = hidden
        self.width = width
        self.style = style

    @property
    def path(self):
        """Fully-qualified name, including component. E.g. 'Process/pid'."""
        return "%s/%s" % (self.component.component_name, self.name)

    def __unicode__(self):
        return repr(self)

    def __str__(self):
        return repr(self)

    def __repr__(self):
        return "%s(%s, type=%s)" % (type(self).__name__,
                                    self.name, self.typedesc)


class AttributePath(Attribute):
    """This is returned by reflection API in some special cases."""

    def __init__(self, attribute, path):
        super(AttributePath, self).__init__(name=attribute.name,
                                            typedesc=attribute.typedesc,
                                            docstring=attribute.docstring,
                                            component=attribute.component,
                                            hidden=True,
                                            width=attribute.width)
        self._path = path

    @property
    def path(self):
        return self._path


class Field(Attribute):
    """Defines a component attribute that's actually stored in the component."""


class Alias(Attribute):
    """Defines a component attribute that's an alias for another attribute."""

    def __init__(self, *args, **kwargs):
        self.alias = kwargs.pop("alias")
        kwargs.setdefault("hidden", True)
        kwargs["typedesc"] = "IdentityDescriptor"
        super(Alias, self).__init__(*args, **kwargs)


class ComponentDescriptor(types.TypeDescriptor):
    """Describes a component."""

    type_name = "Component"

    def coerce(self, value):
        if not isinstance(value, Component):
            raise TypeError("%s is not a component." % repr(value))

        return value


class Component(object):
    """A high-performance container similar to namedtuple."""

    __slots__ = ("_contents", "_object_id")
    component_fields = None
    component_attributes = None
    component_name = None
    component_docstring = None
    component_helpstring = None

    __abstract = True
    __metaclass__ = registry.MetaclassRegistry

    typedesc = ComponentDescriptor()

    def __init__(self, *args, **kwargs):
        self._set_values(args, kwargs)

        if kwargs:
            raise ValueError("Unknown attributes %s on component %s" % (
                kwargs, self.component_name))

    def _set_values(self, args, kwargs):
        self._contents = []
        for idx, arg in enumerate(args):
            typedesc = self.component_fields[idx].typedesc
            self._contents.append(typedesc.coerce(arg))

        for field in self.component_fields[len(args):]:
            value = kwargs.pop(field.name, None)
            self._contents.append(field.typedesc.coerce(value))

    @classmethod
    def reflect_attribute(cls, attribute_name):
        return cls.component_attributes.get(attribute_name, None)

    def union(self, other):
        if other is None:
            return self

        if not isinstance(other, type(self)):
            raise TypeError("Cannot merge %s with %s" % (type(self),
                                                         type(other)))

        merged_fields = []
        for i, x in enumerate(self._contents):
            y = other[i]
            typedesc = self.component_fields[i].typedesc
            superposition_cls = superposition.BaseSuperposition.impl_for_type(
                self.component_fields[i].typedesc)
            merged_fields.append(superposition_cls.merge_values((x, y),
                                                                typedesc))

        return type(self)(*merged_fields)

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False

        for idx, val in enumerate(self._contents):
            if val != other[idx]:
                return False

        return True

    def issuperset(self, other):
        """Is this component a strict superset of other?"""
        if not isinstance(other, type(self)):
            return False

        for idx, val in enumerate(self._contents):
            other_val = other[idx]
            if other_val == None:
                continue

            if not superposition.FastSuperpositionCompare(val, other_val):
                return False

        return True

    def _mutate(self, member, value):
        """Changes the component by setting component.member to value.

        The entity system uses this internally as optimization in some
        very specific cases. Not intended for normal use.
        """
        for idx, field in enumerate(self.component_fields):
            if field.name == member:
                self._contents[idx] = value
                return

    def __ne__(self, other):
        return not self.__eq__(other)

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._contents[key]

        return getattr(self, key)

    def asdict(self):
        result = {}
        for idx, field in enumerate(self.component_fields):
            result[field.name] = self._contents[idx]

        return result

    def __repr__(self):
        pairs = []
        for key, val in self.asdict().iteritems():
            pairs.append("%s=%s" % (key, repr(val)))

        return "%s(%s)" % (self.component_name, ",\n\t".join(pairs))

    def __unicode__(self):
        pairs = []
        for idx, field in enumerate(self.component_fields):
            pairs.append("%s: %s" % (
                field.name,
                field.typedesc.coerce(self._contents[idx])))

        return "%s(%s)" % (self.component_name, ",\n\t".join(pairs))

    def __str__(self):
        return self.__unicode__()


# pylint: disable=protected-access
def DeclareComponent(name, docstring, *attributes, **kwargs):
    """Declare a new component by subclassing the Component class.

    Arguments:
        name: Name of the new component.
        docstring: Short (one sentence) description.
        helpstring: Arbitrary discussion of the component and its usage.
        *attributes: Instances of Attribute, describing the data model.

    Returns:
        A subclass of Component.
    """
    helpstring = kwargs.pop("helpstring", None)
    fields = []
    indexed_attributes = {}
    for attribute in attributes:
        if isinstance(attribute, Field):
            fields.append(attribute)

        indexed_attributes[attribute.name] = attribute

    # Subclass Component, overriding the component_* class variables.
    props = dict(__slots__=(),
                 component_fields=fields,
                 component_attributes=indexed_attributes,
                 component_name=name,
                 component_docstring=docstring,
                 component_helpstring=helpstring)

    for idx, field in enumerate(fields):
        props[field.name] = property(operator.itemgetter(idx))

    component_cls = type(name, (Component,), props)

    # Attach a reference back to the component to each field.
    for attribute in attributes:
        attribute.component = component_cls

    # Redefine ComponentContainer to add a field for the new component class.
    global ComponentContainer
    component_names = list(ComponentContainer._fields)
    component_names.append(name)
    ComponentContainer = collections.namedtuple("ComponentContainer",
                                                component_names)

    # Update the container prototype.
    global CONTAINER_PROTOTYPE
    CONTAINER_PROTOTYPE = ComponentContainer(*[None for _ in component_names])

    return component_cls
