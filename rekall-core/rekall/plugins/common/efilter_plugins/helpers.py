# The below are helper routines for

import functools
import re

from efilter import query as q
from efilter import api

from efilter.protocols import applicative
from efilter.protocols import repeated
from efilter.protocols import structured
from efilter.transforms import solve
from rekall import utils


# Exported EFilter functions. These can be used within efilter
# queries. For example select hex(cmd_address) from dis(0xfa8000895a32).
def hex_function(value):
    """A Function to format the output as a hex string."""
    if value == None:
        return

    return "%#x" % value

def str_function(value):
    if value == None:
        return

    return utils.SmartUnicode(value)

def int_function(value):
    if value == None:
        return

    return int(value)

def noncase_search_function(regex, value):
    """Case insensitive regex search function."""
    return bool(re.search(unicode(regex), unicode(value), re.I))


EFILTER_SCOPES = dict(
    hex=api.user_func(
        hex_function, arg_types=[int], return_type=[str]),

    str=api.user_func(
        str_function, arg_types=[], return_type=[unicode]),

    int=api.user_func(
        int_function, arg_types=[], return_type=[int]),

    regex_search=api.user_func(
        noncase_search_function, arg_types=[unicode, unicode],
        return_type=[bool]),
)


class GeneratorRunner(object):
    def __init__(self, cb):
        self.cb = cb

    def apply(self, args, kwargs):
        return repeated.lazy(functools.partial(self.cb, *args, **kwargs))


# Implement IApplicative for Command to get reflection APIs.
applicative.IApplicative.implement(
    for_type=GeneratorRunner,
    implementations={
        applicative.apply:
            lambda x, *args, **kwargs: x.apply(*args, **kwargs),

        # Plugins "return" themselves, as far as the type inference cares.
        applicative.reflect_runtime_return: lambda x: x
    }
)


class EfilterRunner(object):
    """An easy to use class for using Efilter.

    The Efilter interface is fairly complex but most people just want to filter
    a range of callables. This class is a helper class to help with using
    Efilter.

    All one needs to do is to extend this class and implement any functions
    which should exist in the EFilter namespace. For example, to add a foo()
    function:

    class NewRunner(search.EfilterRunner):
        def run_foo(self):
            for x in range(10):
                yield dict(A=x, B=2*x)


    for x in NewRunner().filter("select * from foo()"):
        print x

    {'A': 0, 'B': 0}
    {'A': 1, 'B': 2}
    {'A': 2, 'B': 4}
    {'A': 3, 'B': 6}
    {'A': 4, 'B': 8}
    """

    def resolve(self, name):
        function = EFILTER_SCOPES.get(name)
        if function:
            return function

        method = getattr(self, "run_" + name, None)
        if method:
            return GeneratorRunner(method)

        raise KeyError("No plugin named %r." % name)

    def getmembers_runtime(self):
        return [c["name"] for c in self.columns]

    def filter(self, query, **query_args):
        query = q.Query(query, params=query_args)
        return repeated.getvalues(solve.solve(query, self).value)


structured.IStructured.implicit_dynamic(EfilterRunner)


class ListFilter(EfilterRunner):
    """A helper to filter a list of dicts using efilter."""

    _list = None

    def run_list(self):
        return self._list

    def filter(self, filter_exr, data, **query_args):
        """Filter the data using the filter expression.

        Args:
          filter_exr: essentially the where clause.
          data: A list of dicts, each dict representing a row.
        """
        if not filter_exr:
            return data

        self._list = data
        query = "select * from list()"
        if filter_exr:
            query += "where " + filter_exr

        return super(ListFilter, self).filter(query, **query_args)
