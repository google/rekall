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


class EntityLookupTable(object):
    """Lookup table for entities."""

    def __init__(self, key_name, key_func, entity_manager):
        self.key_name = key_name
        self.key_func = key_func
        self.entity_manager = entity_manager
        self.table = {}

    def update_index(self, entities):
        for entity in entities:
            for key in self.key_func(entity):
                if key:
                    self.table.setdefault(key, set()).add(entity.identity)

    def lookup(self, *keys):
        unique_results = set()

        for key in keys:
            for identity in self.table.get(key, []):
                for entity in self.entity_manager.find_by_identity(identity):
                    unique_results.add(entity)

        return unique_results
