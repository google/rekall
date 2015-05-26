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
EFILTER abstract syntax.
"""

__author__ = "Adam Sindelar <adamsh@google.com>"


class EfilterError(Exception):
    query = None
    root = None
    message = None
    start = None
    end = None

    def __init__(self, query, message, root=None, start=None, end=None):
        super(EfilterError, self).__init__(message)

        self.query = query
        self.message = message
        self.root = root
        self.start = start if start is not None else self.root.start
        self.end = end if end is not None else self.root.end

    def __str__(self):
        if self.start is not None and self.end is not None:
            query = "%s >>> %s <<< %s" % (
                self.query.source[0:self.start],
                self.query.source[self.start:self.end],
                self.query.source[self.end:])
        else:
            query = self.query.source

        return "%s (%s) in query %r" % (
            type(self).__name__,
            self.message,
            query)

    def __repr__(self):
        return "%s(message=%r, start=%r, end=%r)" % (
            type(self), self.message, self.start, self.end)


class EfilterParseError(EfilterError):
    token = None

    def __init__(self, *args, **kwargs):
        self.token = kwargs.pop("token")
        super(EfilterParseError, self).__init__(*args, **kwargs)


class EfilterTypeError(EfilterError):
    expected = None
    actual = None

    def __init__(self, *args, **kwargs):
        self.expected = kwargs.pop("expected")
        self.actual = kwargs.pop("actual")

        if self.expected and self.actual:
            kwargs.setdefault("message", "Expected type %r, got %r instead." %
                              (self.expected, self.actual))

        super(EfilterTypeError, self).__init__(*args, **kwargs)
