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
EFILTER frontend base class.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"


import abc


class Frontend(object):
    """Base class representing parsers or generators of the EFILTER AST."""
    __metaclass__ = abc.ABCMeta

    FRONTENDS = {}

    def __init__(self, original, params=None):
        """Create a frontend parser for this dialect.

        Arguments:
            original: The source code of this query. Most often this is a
                string type, but there are exceptions (e.g. lisp)
            params: Some dialects support parametric queries (for safety) -
                if used, pass them as params. This should be a dict for
                keywords or a tuple for positional.
        """
        super(Frontend, self).__init__()
        self.params = params
        self.original = original

    @abc.abstractproperty
    def root(self):
        """The root of the resultant AST.

        Subclasses MUST implement parsing here.
        """

    @classmethod
    def register_frontend(cls, subcls, shorthand=None):
        cls.register(subcls)

        if shorthand is None:
            shorthand = repr(subcls)

        cls.FRONTENDS[shorthand] = subcls

    @classmethod
    def get_frontend(cls, shorthand):
        return cls.FRONTENDS.get(shorthand)
