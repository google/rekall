#!/usr/bin/env python
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

"""A common base class for data holder objects."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals


class DataContainer(object):
    """A common base class for data holder objects.

    Provides equality checks and string representation.
    """
    # This is the dict that holds the state variables.
    state = None

    def __init__(self, **kwargs):
        self.state = kwargs

    def __getattr__(self, item):
        try:
            return self.state[item]
        except KeyError:
            raise AttributeError(item)

    def __setattr__(self, key, value):
        try:
            super(DataContainer, self).__getattribute__(key)
            super(DataContainer, self).__setattr__(key, value)
        except AttributeError:
            self.state[key] = value

    def __eq__(self, other):
        if type(other) is not type(self):
            return False
        return self.state == other.state

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        str_key_values = []
        for key, value in self.state.iteritems():
            if value not in [None, [], ()]:
                str_key_value = '%s: %s' % (key, value)
                str_key_values.append(str_key_value)
        return self.__class__.__name__ + '{' + ', '.join(str_key_values) + '}'

    def __dir__(self):
        return self.state.keys()
