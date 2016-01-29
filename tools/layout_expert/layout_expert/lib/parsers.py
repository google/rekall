# -*- coding: utf-8 -*-

# Copyright (C) 2016 Google Inc. All Rights Reserved.
#
# Authors:
# Arkadiusz Socała <as277575@mimuw.edu.pl>
# Michael Cohen <scudette@google.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License.  You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations under
# the License.

"""Miscellaneous routine useful for parsing."""
import inspect
import string
import pyparsing

# pylint: disable=protected-access

# Patch pyparsing to be more sensible.
if not getattr(pyparsing.ParseResults, "_patched_by_rekall", None):

    # Pyparsing uses this function to wrap setParseAction() callbacks. Their
    # implementation is inefficient and masks errors within the callback itself
    # (since it catches all AttributeError and tries with a different number of
    # parameters). We replace this implementation with a more efficient one.
    old_trim_arity = pyparsing._trim_arity

    def _trim_arity(func, maxargs=2):
        func_spec = inspect.getargspec(func)

        # Function has var args (e.g. foo(*args)) so it should take all our
        # args.
        if func_spec.varargs:
            return lambda s, l, t: func(l, t)

        func_args = func_spec.args
        if len(func_args) == 0:
            return lambda s, l, t: func()

        if func_args[0] == "self":
            func_args.pop(0)

        if len(func_args) == 0:
            return lambda s, l, t: func()
        elif len(func_args) == 1:
            return lambda s, l, t: func(t)
        elif len(func_args) == 2:
            return lambda s, l, t: func(l, t)
        elif len(func_args) == 3:
            return func

        return old_trim_arity(func, maxargs=maxargs)

    # Replace pyparsing's implementation.
    pyparsing._trim_arity = _trim_arity

    class ParseResults(pyparsing.ParseResults):
        _patched_by_rekall = True

        @property
        def first(self):
            try:
                return self[0]
            except IndexError:
                return None

        def __getattr__(self, name):
            """Modified getattr to make it easier to access named results.

            It now always returns a ParseResults() instance, even if the element
            is not there.
            """
            result = self.get(name, None)
            if result is None:
                return ParseResults([])

            # if not isinstance(result, ParseResults):
            #    return ParseResults(result)

            return result

    pyparsing.ParseResults = ParseResults


def identifier():
    return pyparsing.Word(pyparsing.alphas + '_', pyparsing.alphanums + '_')


def anything_in_curly():
    return anything_in('{}')


def anything_in_parentheses():
    return anything_in('()')


def anything_in_brackets():
    return anything_in('[]')


def anything_in(opener_and_closer):
    opener = opener_and_closer[0]
    closer = opener_and_closer[1]
    anything = anything_beetween(opener_and_closer)
    return opener + anything + closer


def anything_beetween(opener_and_closer):
    """Builds a (pyparsing) parser for the content inside delimiters.

    Args:
    opener_and_closer: a string containing two elements: opener and closer

    Returns:
      A (pyparsing) parser for the content inside delimiters.
    """
    opener = pyparsing.Literal(opener_and_closer[0])
    closer = pyparsing.Literal(opener_and_closer[1])
    char_removal_mapping = dict.fromkeys(map(ord, opener_and_closer))
    other_chars = unicode(string.printable).translate(char_removal_mapping)
    word_without_delimiters = pyparsing.Word(other_chars).setName(
        "other_chars")
    anything = pyparsing.Forward()
    delimited_block = opener + anything + closer
    # pylint: disable=expression-not-assigned
    anything << pyparsing.ZeroOrMore(
        word_without_delimiters.setName("word_without_delimiters")
        | delimited_block.setName("delimited_block")
    )

    # Combine all the parts into a single string.
    return pyparsing.Combine(anything)



def attribute_name_match(name1, name2):
    name1 = _drop_starting_and_ending_double_underscores(name1)
    name2 = _drop_starting_and_ending_double_underscores(name2)
    return name1 == name2


def _drop_starting_and_ending_double_underscores(name):
    if name.startswith('__'):
        name = name[2:]
    if name.endswith('__'):
        name = name[:-2]
    return name
