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

"""
EFILTER abstract type system.

The type protocols defined under efilter.protocols.* provide a very thin layer
over Python's builtin types, defined as collections of related functions with
defined semantics. Each type protocol is intended to uniformly support a
specific behavior across any type that participates in the protocol.

To participate in a protocol, two things are required:
1) Implementations of each of the member functions must be provided.
2) The type must be formally added to the protocol.

In this manner, we are able to declare strict compositional types on atoms and
expressions in the EFILTER AST and allow type hierarchies external to EFILTER
(Plaso Events, Rekall Entities) to be passed to the EFILTER engines without
casting or wrapping.

The compositional, flat nature of the type protocols makes it simple to support
basic type inference, by annotating each expression type with sets of
protocols it requires on its children and guarantees on its return type.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

import abc


class AnyType(object):
    """Sentinel used to provide a default implementation of a protocol.

    If you need to provide a default implementation of functions in a
    protocol (for example, providing fall-through behavior for objects that
    don't participate in the protocol) you may pass this type in place of
    'object'. This will cause the polymorphic functions to fall through to
    this default implementation, but won't cause 'object' to be a subclass
    of the protocol.

    Example:
        MyProtocol.implement(for_type=AnyType,
                             implementations={foo=lambda x: "foo"})

        foo(5)  # => "foo"
        isinstance(5, MyProtocol)  # => False
    """
    pass


class Protocol(object):
    """Collection of related functions that operate on a type (interface)."""
    __metaclass__ = abc.ABCMeta

    _protocol_functions = set()

    @classmethod
    def functions(cls):
        result = set(cls._protocol_functions)

        for scls in cls.mro():
            protocol_functions = getattr(scls, "_protocol_functions", None)
            if protocol_functions:
                result.update(protocol_functions)

        return result

    @classmethod
    def implemented(cls, for_type):
        for function in cls.functions():
            if not function.implemented_for_type(for_type):
                raise TypeError(
                    "%r doesn't implement %r so it cannot participate in "
                    "the protocol %r." %
                    (for_type, function.func.func_name, cls))

        cls.register(for_type)

    @classmethod
    def _implement_for_type(cls, for_type, implementations):
        # AnyType is a sentinel that means the polymorphic function should
        # just dispatch on 'object'.
        dispatch_type = object if for_type is AnyType else for_type
        protocol_functions = cls.functions()
        remaining = set(protocol_functions)

        for func, impl in implementations.iteritems():
            if func not in protocol_functions:
                func_name = getattr(func, "func_name", repr(func))
                raise TypeError("Function %s is not part of the protocol %r." %
                                (func_name, cls))

            func.implement(for_type=dispatch_type,
                           implementation=impl)
            remaining.remove(func)

        if remaining:
            raise TypeError(
                "%s.implement invokation must provide implementations of "
                "%r" % (cls.__name__, remaining))

        cls.implemented(for_type=for_type)

    @classmethod
    def implement(cls, implementations, for_type=None, for_types=None):
        """Provide protocol implementation for a type.

        Register all implementations of polymorphic functions in this
        protocol and adds the type into the abstract base class of the
        protocol.

        Arguments:
            implementations: A dict of (function, implementation), where each
                function is polymorphic and each implementation is a callable.
            for_type: The concrete type implementations apply to.
            for_types: Same as for_type, but takes a tuple of types.

            You may not supply both for_type and for_types for obvious reasons.

        Raises:
            ValueError for arguments.
            TypeError if not all implementations are provided or if there
                are issues related to polymorphism (e.g. attempting to
                implement a non-polymorphic function.
        """
        if for_type:
            if for_types:
                raise ValueError("Cannot pass both for_type and for_types.")
            for_types = (for_type,)
        elif for_types:
            if not isinstance(for_types, tuple):
                raise TypeError("for_types must be passed as a tuple of "
                                "types (classes).")
        else:
            raise ValueError("Must pass either for_type or for_types.")

        for type_ in for_types:
            cls._implement_for_type(for_type=type_,
                                    implementations=implementations)
