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
The Rekall Entity Layer.
"""
__author__ = "Adam Sindelar <adamsh@google.com>"

from efilter.protocols import associative
from efilter.protocols import indexable
from efilter.protocols import hashable
from efilter.protocols import name_delegate

from rekall import obj
from rekall import plugin as rekall_plugin

from rekall.entities import entity
from rekall.entities import identity
from rekall.entities import component as entity_component


class RekallDelegate(object):
    """Exposes the global Rekall namespace and types to EFILTER.

    This is a work in progress.
    """

    def __init__(self, session, profile):
        self.session = session
        self.profile = profile

    def _reflect_global(self, name):
        if name in entity_component.Component.classes.keys():
            # Is this a valid component? If so, just tell EFILTER it's an
            # Entity.
            return entity_component.Component.classes.get(name)
        elif name.startswith("_"):
            # Could be a global.
            value = self.profile.get_constant(name)
            if value:
                return type(value)

            return None
        else:
            # Try a plugin name.
            # If name is in session plugins, return the plugin class.
            return None

    def _reflect_scoped(self, name, scope):
        if issubclass(scope, entity_component.Component):
            return self._reflect_component(name, scope)

        if issubclass(scope, obj.BaseObject):
            return self._reflect_vtype(name, scope)

        if issubclass(scope, rekall_plugin.Plugin):
            return self._reflect_plugin(name, scope)

        return None

    def _reflect_component(self, name, component):
        field = component.reflect_attribute(name)
        if not field:
            return None

        return getattr(field.typedesc, "type_cls", None)

    def _reflect_vtype(self, name, vtype):
        pass

    def _reflect_plugin(self, name, plugin):
        pass

    def reflect(self, name, scope=None):
        if scope is None:
            return self._reflect_global(name)

        return self._reflect_scoped(name, scope)

    def provide(self, name):
        return None

    def getnames(self):
        return ()


name_delegate.INameDelegate.implement(
    for_type=RekallDelegate,
    implementations={
        name_delegate.reflect: RekallDelegate.reflect,
        name_delegate.provide: RekallDelegate.provide,
        name_delegate.getnames: RekallDelegate.getnames})


def _getkeys_Entity(e):
    for component_name in entity_component.Component.classes.keys():
        component = getattr(e.components, component_name)
        if component is None:
            continue

        for idx, field in enumerate(component.component_fields):
            if component[idx]:
                yield "%s/%s" % (component_name, field.name)


### Entity-related types: ###

associative.IAssociative.implement(
    for_type=entity.Entity,
    implementations={
        associative.select: lambda e, key: e.get_raw(key),
        associative.resolve: lambda e, key: e.get(key),
        associative.getkeys: _getkeys_Entity})


associative.IAssociative.implement(
    for_type=entity_component.Component,
    implementations={
        associative.select: lambda c, key: c[key],
        associative.resolve: lambda c, key: c[key],
        associative.getkeys: lambda c: (f.name for f in c.component_fields)})


associative.IAssociative.implement(
    for_type=entity.CurriedComponent,
    implementations={
        associative.select: entity.CurriedComponent.get,
        associative.resolve: entity.CurriedComponent.get_raw,
        associative.getkeys:
            lambda c: (f.name for f in c.component.component_fields)})


indexable.IIndexable.implement(
    for_types=(identity.Identity, entity.Entity),
    implementations={
        indexable.indices: lambda x: x.indices})

### Structs/vtypes: ###

associative.IAssociative.implement(
    for_type=obj.Struct,
    implementations={
        associative.select: lambda o, key: o.m(key),
        associative.resolve: lambda o, key: getattr(o, key, None),
        associative.getkeys: lambda o: o.members.iterkeys()})


indexable.IIndexable.implement(
    for_type=obj.Struct,
    implementations={
        indexable.indices: lambda o: o.indices})


hashable.IHashable.implement(
    for_type=obj.BaseObject,
    implementations={
        hashable.hashed: hash})
