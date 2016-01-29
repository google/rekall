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

"""A module containing a visitor that transforms a simple Pre-AST to string.

It is used to pretty print the AST.
Also used to substitute macros when evaluation the Pre-AST.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals


class ToStringVisitor(object):
    """A visitor class that transforms a simple Pre-AST to string.

    Works on already prepared Pre-AST so it can only contain a reduced
    set of nodes.

    This is used to convert the preprocessed AST (Which should only contain
    TextBlock nodes) to the flat pre-processed C file.
    """

    def to_string(self, node, parts=None):
        if parts is None:
            parts = []
        node.accept(self, parts)
        return ' '.join(parts)

    def visit_file(self, file_, parts):
        self.to_string(file_.content, parts)

    def visit_composite_block(self, composite_block, parts):
        for element in composite_block.content:
            if element is not None:
                self.to_string(element, parts)

    def visit_text_block(self, text_block, parts):
        parts.append(text_block.content)
