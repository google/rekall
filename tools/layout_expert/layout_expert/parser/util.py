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

"""Common utils to be used by other parser modules."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import functools
import inspect
import itertools
import json
import logging
import os
import time

import pyparsing

from rekall import utils as rekall_utils
from layout_expert.serialization import json_serialization


def action(function):
    """A convenience ParseAction decorator.

    It transforms a function(token1, token2, token3,...) into
    a function(string, line, parser_result) which can be passed to
    some_parser.setParseAction(...) or some_parser.addParseAction(...)
    methods.

    Args:
        function: a function to be wrapped.
        **kwargs: additional keyword arguments to be passed in a function call,
                useful in the non-decorator form e.g.:
                integer_parser.setParseAction(action(int, base=0))
    Returns:
        A result of the given function with tokens provided as arguments and
        passed **kwargs.
    """

    @functools.wraps(function)
    def wrap_function(string, line, tokens):
        _ = string
        _ = line
        try:
            return function(*tokens.asList())
        except pyparsing.ParseException:
            raise
        except Exception as e:
            print(e)
            import pdb
            pdb.post_mortem()
            raise

    @functools.wraps(function)
    def wrap_method(self, string, line, tokens):
        _ = string
        _ = line
        try:
            return function(self, *tokens.asList())
        except pyparsing.ParseException:
            raise
        except Exception as e:
            print(e)
            import pdb
            pdb.post_mortem()
            raise

    try:
        if function.func_code.co_varnames[0] == "self":
            return wrap_method
    except (IndexError, AttributeError):
        pass

    return wrap_function


def join(tok):
    return " ".join(tok.asList())


def pyparsing_debug(function):
    @functools.wraps(function)
    def wrapper(self, *args, **kwargs):
        result = function(self, *args, **kwargs)
        result.setName(function.__name__)
        return result

    return wrapper


class CacheManager(object):
    def __init__(self, cache_dir, force=False):
        self.force = force
        self.cache_dir = cache_dir

    def run(self, key, cb, *args, **kwargs):
        raw = kwargs.pop("raw", False)
        desc = kwargs.pop("desc", None)
        if not self.cache_dir:
            now = time.time()
            result = cb(*args)
            if desc:
                logging.info("Completed %s in %d Seconds",
                             desc, time.time() - now)

            return result

        normalized_key = key.replace("/", "_")
        normalized_key = normalized_key.replace(".", "_")
        path = os.path.join(self.cache_dir, normalized_key)

        if not self.force:
            try:
                raw_data = open(path).read()
                if raw:
                    return raw_data

                json_data = json.loads(raw_data)
                result = json_serialization.load(json_data)
                logging.debug("Cache hit %s", path)

                return result
            except (IOError, OSError):
                pass

            except Exception as e:
                logging.error("Error loading from cache: %s" % e)

        now = time.time()
        result = cb(*args, **kwargs)
        if desc:
            logging.info("Completed %s in %d Seconds", desc, time.time() - now)

        with open(path, "wb") as fd:
            if raw:
                fd.write(result)
            else:
                fd.write(
                    rekall_utils.PPrint(json_serialization.dump(result)))

        return result


def debug(_, offset, match):
    print("%s: %s" % (offset, match))


CALLS = {}


def instrument():
    curframe = inspect.currentframe()
    callframe = inspect.getouterframes(curframe, 2)

    caller = "%s:%s:%s" % (
        callframe[1][1], callframe[1][2], (callframe[1][4][0]).strip())

    def counter(_a, _b, _c, caller=caller):
        try:
            CALLS[caller] += 1
        except KeyError:
            CALLS[caller] = 1

    return counter


def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    return itertools.izip_longest(*args, fillvalue=fillvalue)


def memoize_method(f):
    cache = {}
    @functools.wraps(f)
    def wrapper(self, *args):
        try:
            return cache[args]
        except KeyError:
            result = cache[args] = f(self, *args)
            return result

    return wrapper


def memoize(f):
    """Memoization decorator for functions taking one or more arguments.

    http://code.activestate.com/recipes/578231-probably-the-fastest-memoization-decorator-in-the-/#c1
    """
    class Memodict(dict):
        def __init__(self, f):
            super(Memodict, self).__init__()
            self.f = f

        def __call__(self, *args):
            return self[args]

        def __missing__(self, key):
            ret = self[key] = self.f(*key)
            return ret

    return Memodict(f)
