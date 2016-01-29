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

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest

from layout_expert.preprocessing_loader import preprocessing_loader


class MockPreprocessingLoader(preprocessing_loader.PreprocessingLoader):
    # A lookup between file name and file contents.
    def __init__(self, *args, **kwargs):
        super(MockPreprocessingLoader, self).__init__(*args, **kwargs)
        self.mock_files = {}
        self.mock_opened_files = []

    def _get_file_content(self, file_path):
        self.mock_opened_files.append(file_path)
        content = self.mock_files.get(file_path)
        if content is None:
            raise IOError()

        return content

    def _file_exists(self, file_path):
        return file_path in self.mock_files


class TestPreprocessingLoader(unittest.TestCase):

    def setUp(self):
        self.preprocessing_loader = MockPreprocessingLoader([])

    def test_load_with_file_with_no_includes(self):
        self.preprocessing_loader.mock_files = {
            'dir_1/file_1': '',
        }
        self.preprocessing_loader.load(file_path='dir_1/file_1')
        self.assertEqual(
            self.preprocessing_loader.mock_opened_files, ['dir_1/file_1'])

    def test_load_with_quoted_include_in_the_same_directory(self):
        self.preprocessing_loader.include_directories = [
            'dir_5',
            'dir_6',
        ]
        self.preprocessing_loader.mock_files = {
            'dir_1/dir_2/file_1': '''
        #include "../dir_3/file_2"
        #include "../dir_4/file_3"
        #include "file_4"
        ''',
            'dir_1/dir_2/file_4': '',
            'dir_1/dir_3/file_2': '',
            'dir_1/dir_3/file_4': '',
            'dir_1/dir_4/file_3': '',
            'dir_1/dir_4/file_4': '',
            'dir_1/file_4': '',
            'dir_5/file_4': '',
            'file_4': '',
        }

        self.preprocessing_loader.load(file_path='dir_1/dir_2/file_1')
        # This should open all includes - including file_4 in the directory relative
        # to its include statement.
        self.assertEqual(
            self.preprocessing_loader.mock_opened_files,
            ['dir_1/dir_2/file_1', 'dir_1/dir_3/file_2', 'dir_1/dir_4/file_3',
             'dir_1/dir_2/file_4'])

    def test_load_with_quoted_include_in_include_directory(self):
        self.preprocessing_loader.include_directories = [
            'dir_5',
            'dir_6',
        ]
        self.preprocessing_loader.mock_files = {
            'dir_1/dir_2/file_1': '''
        #include "../dir_3/file_2"
        #include "../dir_4/file_3"
        #include "file_4"
        ''',
            'dir_1/dir_3/file_2': '',
            'dir_1/dir_4/file_3': '',
            'dir_1/file_4': '',
            'dir_5/file_4': '',
            'file_4': '',
        }

        self.preprocessing_loader.load(file_path='dir_1/dir_2/file_1')

        # This should open all includes - including file_4 in the directory relative
        # to its include statement.
        self.assertEqual(
            self.preprocessing_loader.mock_opened_files,
            ['dir_1/dir_2/file_1',
             'dir_1/dir_3/file_2',
             'dir_1/dir_4/file_3',
             'dir_5/file_4'])

    def test_load_with_quoted_include_nonexisting_file(self):
        self.preprocessing_loader.include_directories = [
            'dir_5',
            'dir_6',
        ]
        self.preprocessing_loader.mock_files = {
            'dir_1/dir_2/file_1': '''
        #include "../dir_3/file_2"
        #include "../dir_4/file_3"
        #include "file_4"
        ''',
            'dir_1/dir_3/file_2': '',
            'dir_1/dir_4/file_3': '',
            'dir_1/file_4': '',
            'file_4': '',
        }

        self.preprocessing_loader.load(file_path='dir_1/dir_2/file_1')

        # Can not find file_4 on search path.
        self.assertEqual(
            self.preprocessing_loader.mock_opened_files,
            ['dir_1/dir_2/file_1',
             'dir_1/dir_3/file_2',
             'dir_1/dir_4/file_3'])

    def assertEqual(self, actual, expected):
        message = '\n%s\n!=\n%s' % (actual, expected)
        super(TestPreprocessingLoader, self).assertEqual(
            actual, expected, message)


if __name__ == '__main__':
    unittest.main()
