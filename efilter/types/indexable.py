# -*- coding: utf-8 -*-

# EFILTER Forensic Query Language
#
# Copyright 2015 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""EFILTER abstract type system."""

from efilter import dispatch
from efilter import protocol
from efilter.types import hashable

# Declarations:
# pylint: disable=unused-argument


@dispatch.polymorphic
def indices(x):
    """Return a list of keys to represent 'self' in maps.

    It is sometimes desirable to store objects in sets or dicts, which are
    not hashable. There may be two reasons for this:
    1) Mutable objects may not be hashable for obvious reasons.
    2) Hashable objects must satisfy:
       x == y -> hash(x) == hash(y).
       This requirement may be impossible to meet for certain types that
       can compare as multiple types, for example emulated C enumerations,
       which compare as either integers or strings, but can only be hashed
       as one or the other.

    The former is easily addressed by not using mutable types for
    non-ephemeral state. It's the 21st century, people.

    The Indexable interface addresses the latter, by letting the object
    return a collection of keys, here called 'indices', at which it desires
    to appear in any associative collection. The indices must themselves be
    hashable.

    See ext.indexset for more details about how indices may be used.
    """
    raise NotImplementedError()


class IIndexable(protocol.Protocol):
    _protocol_functions = (indices,)


# Default implementations:

IIndexable.implement(for_type=hashable.IHashable,
                     implementations={indices: lambda x: (x,)})
