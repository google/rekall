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

from efilter.types import associative
from rekall.entities import entity
from rekall.entities import component as entity_component


def _getkeys_Entity(e):
    for component_name in entity_component.Component.classes.keys():
        component = getattr(e.components, component_name)
        if component is None:
            continue

        for idx, field in enumerate(component.component_fields):
            if component[idx]:
                yield "%s/%s" % (component_name, field.name)


associative.IAssociative.implement(
    for_type=entity.Entity,
    implementations={
        associative.select: lambda e, key: e.get_raw(key),
        associative.resolve: lambda e, key: e.get(key),
        associative.getkeys: _getkeys_Entity})
