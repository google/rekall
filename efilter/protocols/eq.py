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

# Declarations:
# pylint: disable=unused-argument


@dispatch.polymorphic
def eq(x, y):
    raise NotImplementedError()


@dispatch.polymorphic
def ne(x, y):
    raise NotImplementedError()


class IEq(protocol.Protocol):
    _protocol_functions = (eq, ne)


# Default implementations:

IEq.implement(
    for_type=protocol.AnyType,
    implementations={
        eq: lambda x, y: x == y,
        ne: lambda x, y: x != y
    }
)
