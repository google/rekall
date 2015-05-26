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

"""EFILTER abstract type system.

This special protocol defines functions for an application/service level
delegate object, intended to provide type information and a global name service
to EFILTER. Implementing this protocol will enable EFILTER expressions to
reference globals and provide stronger type protections and hints in the
query analyzer.
"""

from efilter import dispatch
from efilter import protocol


# Declarations:
# pylint: disable=unused-argument


@dispatch.polymorphic
def reflect(delegate, name, scope=None):
    """Provide the type of 'name', which is either a global or part of 'scope'.

    Arguments:
        delegate: The application delegate.
        name: The name to be reflected. Either a global (from getnames) or
            a member of 'scope', which is a type or a container.
        scope: The optional type scope, which was returned by a previous call
            to 'reflect'. Used to qualify that 'name' is not global, but a
            member of 'scope'.

    Returns:
        The type of 'name' or None. Invalid names should return None,
        whereas valid names with unknown type should return AnyType.

    Examples:
        # What's a process?
        reflect(delegate, "Process") #=> Process

        # Invalid - must be scoped.
        reflect(delegate, "name") #=> None

        # Attribute 'ProcessName' of a Process Entity.
        reflect(delegate, "name", Process) #=> basestring

        # Plugin output:
        reflect(delegate, "pslist") #=> pslist
        reflect(delegate, "pid", pslist) #=> int
        reflect(delegate, "process", netstat) #=> Entity

        # Globals:
        reflect(delegate, "_PsListHead") #=> proc
        reflect(delegate, "p_pid", proc) #=> unsigned
        reflect(delegate, "void_pointer", proc) #=> AnyType
    """
    raise NotImplementedError()


@dispatch.polymorphic
def asglobal(delegate, name, scope=None):
    """Does the name (with scope) represent a global?

    Arguments:
        delegate: The application delegate.
        name: The name to be reduced to global, if possible.
        scope: The scope the name was found in.

    Returns:
        None if the name is not a global. Otherwise the global name.

    Examples:
        asglobal(delegate, "Process") #=> "Process"
        asglobal(delegate, "name", Process) #=> None
        asglobal(delegate, "Process", )
    """
    raise NotImplementedError()


@dispatch.polymorphic
def provide(delegate, name):
    """Provide the value of a global constant.

    Examples:
        # Global constant:
        provide(delegate, "_PsListHead") #=> <struct pslisthead @0xffff503ac...
    """
    raise NotImplementedError()


@dispatch.polymorphic
def getnames(delegate):
    """Provide a list of global names which can be reflected or provided.

    Returns an iterable of strings.
    """
    raise NotImplementedError()


class INameDelegate(protocol.Protocol):
    _protocol_functions = (reflect, provide, getnames)
