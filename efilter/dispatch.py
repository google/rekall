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
EFILTER type system.

This module implements polymorphic function dispatch.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"

import functools
import threading


class polymorphic(object):
    """Polymorphic function that dispatches on the type of the first arg.

    This function decorator can be used on instance methods as well as regular
    functions. It allows the function to dispatch on the type of its first
    argument, much like standard python instance methods dispatch on the type
    of self (conceptually, not in actuality).

    This enables us to define arbitrary interfaces and have already existing
    types participate in those interfaces, without having to actually alter
    the existing type hierarchy or monkey-patch additional functions into their
    namespaces.

    This approach is used in EFILTER to enable it to be easily added to
    existing codebases, which may already overload many operators and have
    their own conventions about how members of objects are accessed and types
    interact.

    Examples:
        @polymorphic
        def say_moo(bovine):
            raise NotImplementedError()

        class Cow():
            pass

        say_moo.implement(for_type=Cow, implementation=lambda x: "Moo!")

        class Sheep():
            pass

        say_moo.implement(for_type=Sheep, implementation=lambda x: "Baah!")

        shaun = Sheep()
        bessy = Cow()

        say_moo(shaun)  # => "Baah!"
        say_moo(bessy)  # => "Moo!"
    """

    # Locks _dispatch_table and implementations.
    _write_lock = None

    # Cache of type -> implementation.
    _dispatch_table = None

    # Table of which dispatch type is preferred over which other type in
    # cases that benefit from disambiguation.
    _prefer_table = None

    implementations = None
    func = None

    is_polymorphic_function = True

    def __init__(self, func):
        self._write_lock = threading.Lock()
        self.func = func
        self._dispatch_table = {}
        self._prefer_table = {}
        self.implementations = []
        functools.update_wrapper(self, func)

    @property
    def func_name(self):
        return self.func.func_name

    def __repr__(self):
        return "polymorphic(%s)" % self.func_name

    def __call__(self, obj, *args, **kwargs):
        implementation = self._find_and_cache_best_function(type(obj))
        if implementation:
            return implementation(obj, *args, **kwargs)

        # Fall-through to calling default implementation. By convention, the
        # default will usually raise a NotImplemented exception, but there
        # may be times when it will actually do something useful (good example
        # are convenience type checking functions, such as issuperposition).
        try:
            return self.func(obj, *args, **kwargs)
        except NotImplementedError:
            # Throw a better exception.
            raise NotImplementedError(
                "Polymorphic function %r has no concrete implementation for "
                "type %r and no default implementation. Available handlers: %r"
                % (self.func, type(obj), self.implementations))

    def implemented_for_type(self, dispatch_type):
        candidate = self._find_and_cache_best_function(dispatch_type)
        if candidate == self.func:
            return False

        return True

    def _preferred(self, preferred, over):
        prefs = self._prefer_table.get(preferred)
        if prefs and over in prefs:
            return True

        return False

    def prefer_type(self, prefer, over):
        """Prefer one type over another type, all else being equivalent.

        With abstract base classes (Python's abc module) it is possible for
        a type to appear to be a subclass of another type without the supertype
        appearing in the subtype's MRO. As such, the supertype has no order
        with respect to other supertypes, and this may lead to amguity if two
        implementations are provided for unrelated abstract types.

        In such cases, it is possible to disambiguate by explictly telling the
        function to prefer one type over the other.

        Arguments:
            prefer: Preferred type (class).
            over: The type we don't like (class).

        Raises:
            ValueError: In case of logical conflicts.
        """
        self._write_lock.acquire()
        try:
            if self._preferred(preferred=over, over=prefer):
                raise ValueError(
                    "Type %r is already preferred over %r." % (over, prefer))
            prefs = self._prefer_table.setdefault(prefer, set())
            prefs.add(over)
        finally:
            self._write_lock.release()

    def _find_and_cache_best_function(self, dispatch_type):
        """Finds the best implementation of this function given a type.

        This function caches the result, and uses locking for thread safety.

        Returns:
            Implementing function, in below order of preference:
            1. Explicitly registered implementations (through
               polymorphic.register) for types that arg_type either is
               or inherits from directly.
            2. Explicitly registered implementations accepting an abstract type
               (interface) in which dispatch_type participates (through
               abstract_type.register()).
            3. An implementation of the same name on dispatch_type itself.
            4. Default behavior of the polymorphic function. This will usually
               raise a NotImplementedError, by convention.

        Raises:
            TypeError: If two implementing functions are registered for
                different abstract types, and dispatch_type participates in
                both, because no order of preference exists in that situation.
        """
        result = self._dispatch_table.get(dispatch_type)
        if result:
            return result

        self._write_lock.acquire()

        try:
            dispatch_mro = dispatch_type.mro()
        except TypeError:
            # Not every type has an MRO.
            dispatch_mro = ()

        best_match = None
        result_type = None
        try:
            for candidate_type, candidate_func in self.implementations:
                if not issubclass(dispatch_type, candidate_type):
                    # Skip implementations that are obviously unrelated.
                    continue

                try:
                    # The candidate implementation may be for a type that's
                    # actually in the MRO, or it may be for an abstract type.
                    match = dispatch_mro.index(candidate_type)
                except ValueError:
                    # This means we have an implementation for an abstract
                    # type, which ranks below all concrete types.
                    match = None

                if best_match is None:
                    if result and match is None:
                        # Already have a result, and no order of preference.
                        # This is probably because the type is a member of two
                        # abstract types and we have separate implementations
                        # for those two abstract types.

                        if self._preferred(candidate_type, over=result_type):
                            result = candidate_func
                            result_type = candidate_type
                        elif self._preferred(result_type, over=candidate_type):
                            # No need to update anything.
                            pass
                        else:
                            raise TypeError(
                                "Two candidate implementations found for "
                                "polymorphic function %s (dispatch type %s) "
                                "and neither is preferred." %
                                (self.func.func_name, dispatch_type))
                    else:
                        result = candidate_func
                        result_type = candidate_type

                if match < best_match:
                    result = candidate_func
                    result_type = candidate_type
                    best_match = match

            # As last resolve, we will use a function defined on the type
            # being dispatched, to enable direct inheritance from interfaces
            # that define methods which are both polymorphic and abstract.
            if result is None:
                result = getattr(dispatch_type, self.func.func_name, None)

            self._dispatch_table[dispatch_type] = result
            return result
        finally:
            self._write_lock.release()

    def implement(self, implementation, for_type=None, for_types=None):
        """Registers an implementing function for for_type.

        Arguments:
            implementation: Callable implementation for this type.
            for_type: The type this implementation applies to.
            for_types: Same as for_type, but takes a tuple of types.

            for_type and for_types cannot both be passed (for obvious reasons.)

        Raises:
            ValueError
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

        for t in for_types:
            self._write_lock.acquire()
            try:
                self.implementations.append((t, implementation))
            finally:
                self._write_lock.release()
