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

"""A module containing an include following loader for C header files."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import itertools
import logging
import os

from layout_expert.parsers import util
from layout_expert.preprocessing_visitors import include_collecting_visitor
from layout_expert.preprocessing_parser import preprocessing_parser


# We deliberately exclude these headers from the pre-ast because the kernel
# build system autogenerates them from the config and it bakes the config into
# them. If we allowed these files into the pre-ast then the kernel config of the
# current kernel headers package will override the settings introduced by the
# runtime config file.
EXCLUDED_INCLUDE_FILES = set([
    "generated/autoconf.h"
])


class PreprocessingLoader(object):
    """A class representing an include following loader for C header files."""

    def __init__(self, include_directories, cache=None, progress_cb=None):
        self._preprocessing_parser = preprocessing_parser.PreprocessingParser()
        self._include_collector = (
            include_collecting_visitor.IncludeCollectingVisitor())
        self.include_directories = include_directories
        self.cache = cache or util.CacheManager(None)
        self.opened_files = []
        self.loaded_files = {}
        self.progress_cb = progress_cb or (lambda *_: None)

    def load(self, file_path):
        """Loads a header file and all its includes recursively."""
        if file_path in self.loaded_files:
            return self.loaded_files

        self.progress_cb("Processing %s", file_path)
        source = self._get_file_content(file_path)
        file_ = self.cache.run(
            file_path, self._preprocessing_parser.parse, source,
        )

        self.opened_files.append(file_path)
        self.loaded_files[file_path] = file_
        self._load_includes(file_)
        self.opened_files.pop()
        return self.loaded_files

    def _load_includes(self, tree):
        includes = self._include_collector.collect_includes(tree)
        for include in includes:
            if include.path in EXCLUDED_INCLUDE_FILES:
                logging.info("Excluding include file %s", include.path)
                continue

            directories_to_try = self._get_directories_to_try(include)
            self._try_to_load_from_directories(directories_to_try, include)

    def _get_directories_to_try(self, include):
        if include.quotes_type == "<":
            return self.include_directories

        elif include.quotes_type == '"':
            opened_files_directories = map(os.path.dirname, self.opened_files)
            return itertools.chain(
                reversed(opened_files_directories),
                iter(self.include_directories))

        else:
            raise RuntimeError("Unknown quote type for include %s!" % include)

    def _try_to_load_from_directories(self, directories_to_try, include):
        for directory_path in directories_to_try:
            if self._try_to_load_from_directory(directory_path, include):
                return

    def _try_to_load_from_directory(self, directory_path, include):
        absolute_path = os.path.join(directory_path, include.path)
        normalized_path = os.path.normpath(absolute_path)
        if self._file_exists(normalized_path):
            self.load(normalized_path)
            include.absolute_path = normalized_path
            return True
        return False

    def _file_exists(self, file_path):
        return os.path.isfile(file_path)

    def _get_file_content(self, file_path):
        with open(file_path) as opened_file:
            return opened_file.read().decode('utf8')


class IncludeNotFoundException(Exception):
    pass
