from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import StringIO
import unittest


import mock

from rekall.layout_expert.c_ast import pre_ast
from rekall.layout_expert.preprocessing_loader import preprocessing_loader


class TestPreprocessingLoader(unittest.TestCase):

  def setUp(self):
    self.preprocessing_parser = mock.MagicMock()
    self.include_collector = mock.MagicMock()
    self.preprocessing_loader = preprocessing_loader.PreprocessingLoader(
        preprocessing_parser=self.preprocessing_parser,
        include_collector=self.include_collector,
    )
    self.include_directories = []
    self.files = {}

  def _mock_open(self, path):
    mock_file = StringIO.StringIO(self.files[path])
    mock_context_manager = mock.MagicMock()
    mock_context_manager.__enter__.return_value = mock_file
    return mock_context_manager

  def _mock_isfile(self, file_path):
    return file_path in self.files

  def test_load_with_file_with_no_includes(self):
    self.include_directories = []
    self.files = {
        'dir_1/file_1': 'content_1',
    }
    dir_1_file_1 = mock.MagicMock()
    self.preprocessing_parser.parse.side_effect = (
        dir_1_file_1,
    )
    self.include_collector.collect_includes.side_effect = (
        [],
    )
    with mock.patch('__builtin__.open', self._mock_open):
      with mock.patch('os.path.isfile', self._mock_isfile):
        actual = self.preprocessing_loader.load(
            file_path='dir_1/file_1',
            include_directories=self.include_directories,
        )
    expected = {
        'dir_1/file_1': dir_1_file_1,
    }
    self.preprocessing_parser.parse.assert_called_with('content_1')
    self.include_collector.collect_includes.assert_called_with(dir_1_file_1)
    self.assertEqual(actual, expected)

  def test_load_with_quoted_include_in_the_same_directory(self):
    self.include_directories = [
        'dir_5',
        'dir_6',
    ]
    self.files = {
        'dir_1/dir_2/file_1': 'content_1',
        'dir_1/dir_2/file_4': 'content_4_a',
        'dir_1/dir_3/file_2': 'content_2',
        'dir_1/dir_3/file_4': 'content_4_b',
        'dir_1/dir_4/file_3': 'content_3',
        'dir_1/dir_4/file_4': 'content_4_c',
        'dir_1/file_4': 'content_4_d',
        'dir_5/file_4': 'content_4_e',
        'file_4': 'content_4_f',
    }
    file_1 = mock.MagicMock()
    file_2 = mock.MagicMock()
    file_3 = mock.MagicMock()
    file_4 = mock.MagicMock()
    self.preprocessing_parser.parse.side_effect = (
        file_1,
        file_2,
        file_3,
        file_4,
    )
    include_file_2 = pre_ast.Include(
        path='../dir_3/file_2',
        quotes_type=pre_ast.Include.QuotesType.DOUBLE_QUOTES,
    )
    include_file_3 = pre_ast.Include(
        path='../dir_4/file_3',
        quotes_type=pre_ast.Include.QuotesType.DOUBLE_QUOTES,
    )
    include_file_4 = pre_ast.Include(
        path='file_4',
        quotes_type=pre_ast.Include.QuotesType.DOUBLE_QUOTES,
    )
    self.include_collector.collect_includes.side_effect = (
        [include_file_2],
        [include_file_3],
        [include_file_4],
        [],
    )
    with mock.patch('__builtin__.open', self._mock_open):
      with mock.patch('os.path.isfile', self._mock_isfile):
        actual = self.preprocessing_loader.load(
            file_path='dir_1/dir_2/file_1',
            include_directories=self.include_directories,
        )
    expected_parser_calls = [
        mock.call('content_1'),
        mock.call('content_2'),
        mock.call('content_3'),
        mock.call('content_4_c'),
    ]
    self.assertEqual(
        self.preprocessing_parser.parse.call_args_list,
        expected_parser_calls,
    )
    expected_include_collector_calls = [
        mock.call(file_1),
        mock.call(file_2),
        mock.call(file_3),
        mock.call(file_4),
    ]
    self.assertEqual(
        self.include_collector.collect_includes.call_args_list,
        expected_include_collector_calls,
    )
    expected = {
        'dir_1/dir_2/file_1': file_1,
        'dir_1/dir_3/file_2': file_2,
        'dir_1/dir_4/file_3': file_3,
        'dir_1/dir_4/file_4': file_4,
    }
    self.assertEqual(actual, expected)

  def test_load_with_quoted_include_in_parent_include_file_directory(self):
    self.include_directories = [
        'dir_5',
        'dir_6',
    ]
    self.files = {
        'dir_1/dir_2/file_1': 'content_1',
        'dir_1/dir_2/file_4': 'content_4_a',
        'dir_1/dir_3/file_2': 'content_2',
        'dir_1/dir_3/file_4': 'content_4_b',
        'dir_1/dir_4/file_3': 'content_3',
        'dir_1/file_4': 'content_4_c',
        'dir_5/file_4': 'content_4_d',
        'file_4': 'content_4_e',
    }
    file_1 = mock.MagicMock()
    file_2 = mock.MagicMock()
    file_3 = mock.MagicMock()
    file_4 = mock.MagicMock()
    self.preprocessing_parser.parse.side_effect = (
        file_1,
        file_2,
        file_3,
        file_4,
    )
    include_file_2 = pre_ast.Include(
        path='../dir_3/file_2',
        quotes_type=pre_ast.Include.QuotesType.DOUBLE_QUOTES,
    )
    include_file_3 = pre_ast.Include(
        path='../dir_4/file_3',
        quotes_type=pre_ast.Include.QuotesType.DOUBLE_QUOTES,
    )
    include_file_4 = pre_ast.Include(
        path='file_4',
        quotes_type=pre_ast.Include.QuotesType.DOUBLE_QUOTES,
    )
    self.include_collector.collect_includes.side_effect = (
        [include_file_2],
        [include_file_3],
        [include_file_4],
        [],
    )
    with mock.patch('__builtin__.open', self._mock_open):
      with mock.patch('os.path.isfile', self._mock_isfile):
        actual = self.preprocessing_loader.load(
            file_path='dir_1/dir_2/file_1',
            include_directories=self.include_directories,
        )
    expected_parser_calls = [
        mock.call('content_1'),
        mock.call('content_2'),
        mock.call('content_3'),
        mock.call('content_4_b'),
    ]
    self.assertEqual(
        self.preprocessing_parser.parse.call_args_list,
        expected_parser_calls,
    )
    expected_include_collector_calls = [
        mock.call(file_1),
        mock.call(file_2),
        mock.call(file_3),
        mock.call(file_4),
    ]
    self.assertEqual(
        self.include_collector.collect_includes.call_args_list,
        expected_include_collector_calls,
    )
    expected = {
        'dir_1/dir_2/file_1': file_1,
        'dir_1/dir_3/file_2': file_2,
        'dir_1/dir_4/file_3': file_3,
        'dir_1/dir_3/file_4': file_4,
    }
    self.assertEqual(actual, expected)

  def test_load_with_quoted_include_in_grandparent_include_file_directory(
      self,
  ):
    self.include_directories = [
        'dir_5',
        'dir_6',
    ]
    self.files = {
        'dir_1/dir_2/file_1': 'content_1',
        'dir_1/dir_2/file_4': 'content_4_a',
        'dir_1/dir_3/file_2': 'content_2',
        'dir_1/dir_4/file_3': 'content_3',
        'dir_1/file_4': 'content_4_b',
        'dir_5/file_4': 'content_4_c',
        'file_4': 'content_4_d',
    }
    file_1 = mock.MagicMock()
    file_2 = mock.MagicMock()
    file_3 = mock.MagicMock()
    file_4 = mock.MagicMock()
    self.preprocessing_parser.parse.side_effect = (
        file_1,
        file_2,
        file_3,
        file_4,
    )
    include_file_2 = pre_ast.Include(
        path='../dir_3/file_2',
        quotes_type=pre_ast.Include.QuotesType.DOUBLE_QUOTES,
    )
    include_file_3 = pre_ast.Include(
        path='../dir_4/file_3',
        quotes_type=pre_ast.Include.QuotesType.DOUBLE_QUOTES,
    )
    include_file_4 = pre_ast.Include(
        path='file_4',
        quotes_type=pre_ast.Include.QuotesType.DOUBLE_QUOTES,
    )
    self.include_collector.collect_includes.side_effect = (
        [include_file_2],
        [include_file_3],
        [include_file_4],
        [],
    )
    with mock.patch('__builtin__.open', self._mock_open):
      with mock.patch('os.path.isfile', self._mock_isfile):
        actual = self.preprocessing_loader.load(
            file_path='dir_1/dir_2/file_1',
            include_directories=self.include_directories,
        )
    expected_parser_calls = [
        mock.call('content_1'),
        mock.call('content_2'),
        mock.call('content_3'),
        mock.call('content_4_a'),
    ]
    self.assertEqual(
        self.preprocessing_parser.parse.call_args_list,
        expected_parser_calls,
    )
    expected_include_collector_calls = [
        mock.call(file_1),
        mock.call(file_2),
        mock.call(file_3),
        mock.call(file_4),
    ]
    self.assertEqual(
        self.include_collector.collect_includes.call_args_list,
        expected_include_collector_calls,
    )
    expected = {
        'dir_1/dir_2/file_1': file_1,
        'dir_1/dir_3/file_2': file_2,
        'dir_1/dir_4/file_3': file_3,
        'dir_1/dir_2/file_4': file_4,
    }
    self.assertEqual(actual, expected)

  def test_load_with_quoted_include_in_include_directory(
      self,
  ):
    self.include_directories = [
        'dir_5',
        'dir_6',
    ]
    self.files = {
        'dir_1/dir_2/file_1': 'content_1',
        'dir_1/dir_3/file_2': 'content_2',
        'dir_1/dir_4/file_3': 'content_3',
        'dir_1/file_4': 'content_4_a',
        'dir_5/file_4': 'content_4_b',
        'file_4': 'content_4_c',
    }
    file_1 = mock.MagicMock()
    file_2 = mock.MagicMock()
    file_3 = mock.MagicMock()
    file_4 = mock.MagicMock()
    self.preprocessing_parser.parse.side_effect = (
        file_1,
        file_2,
        file_3,
        file_4,
    )
    include_file_2 = pre_ast.Include(
        path='../dir_3/file_2',
        quotes_type=pre_ast.Include.QuotesType.DOUBLE_QUOTES,
    )
    include_file_3 = pre_ast.Include(
        path='../dir_4/file_3',
        quotes_type=pre_ast.Include.QuotesType.DOUBLE_QUOTES,
    )
    include_file_4 = pre_ast.Include(
        path='file_4',
        quotes_type=pre_ast.Include.QuotesType.DOUBLE_QUOTES,
    )
    self.include_collector.collect_includes.side_effect = (
        [include_file_2],
        [include_file_3],
        [include_file_4],
        [],
    )
    with mock.patch('__builtin__.open', self._mock_open):
      with mock.patch('os.path.isfile', self._mock_isfile):
        actual = self.preprocessing_loader.load(
            file_path='dir_1/dir_2/file_1',
            include_directories=self.include_directories,
        )
    expected_parser_calls = [
        mock.call('content_1'),
        mock.call('content_2'),
        mock.call('content_3'),
        mock.call('content_4_b'),
    ]
    self.assertEqual(
        self.preprocessing_parser.parse.call_args_list,
        expected_parser_calls,
    )
    expected_include_collector_calls = [
        mock.call(file_1),
        mock.call(file_2),
        mock.call(file_3),
        mock.call(file_4),
    ]
    self.assertEqual(
        self.include_collector.collect_includes.call_args_list,
        expected_include_collector_calls,
    )
    expected = {
        'dir_1/dir_2/file_1': file_1,
        'dir_1/dir_3/file_2': file_2,
        'dir_1/dir_4/file_3': file_3,
        'dir_5/file_4': file_4,
    }
    self.assertEqual(actual, expected)

  def test_load_with_quoted_include_nonexisting_file(
      self,
  ):
    self.include_directories = [
        'dir_5',
        'dir_6',
    ]
    self.files = {
        'dir_1/dir_2/file_1': 'content_1',
        'dir_1/dir_3/file_2': 'content_2',
        'dir_1/dir_4/file_3': 'content_3',
        'dir_1/file_4': 'content_4_a',
        'file_4': 'content_4_b',
    }
    file_1 = mock.MagicMock()
    file_2 = mock.MagicMock()
    file_3 = mock.MagicMock()
    self.preprocessing_parser.parse.side_effect = (
        file_1,
        file_2,
        file_3,
    )
    include_file_2 = pre_ast.Include(
        path='../dir_3/file_2',
        quotes_type=pre_ast.Include.QuotesType.DOUBLE_QUOTES,
    )
    include_file_3 = pre_ast.Include(
        path='../dir_4/file_3',
        quotes_type=pre_ast.Include.QuotesType.DOUBLE_QUOTES,
    )
    include_file_4 = pre_ast.Include(
        path='file_4',
        quotes_type=pre_ast.Include.QuotesType.DOUBLE_QUOTES,
    )
    self.include_collector.collect_includes.side_effect = (
        [include_file_2],
        [include_file_3],
        [include_file_4],
    )
    with mock.patch('__builtin__.open', self._mock_open):
      with mock.patch('os.path.isfile', self._mock_isfile):
        actual = self.preprocessing_loader.load(
            file_path='dir_1/dir_2/file_1',
            include_directories=self.include_directories,
        )
    expected_parser_calls = [
        mock.call('content_1'),
        mock.call('content_2'),
        mock.call('content_3'),
    ]
    self.assertEqual(
        self.preprocessing_parser.parse.call_args_list,
        expected_parser_calls,
    )
    expected_include_collector_calls = [
        mock.call(file_1),
        mock.call(file_2),
        mock.call(file_3),
    ]
    self.assertEqual(
        self.include_collector.collect_includes.call_args_list,
        expected_include_collector_calls,
    )
    expected = {
        'dir_1/dir_2/file_1': file_1,
        'dir_1/dir_3/file_2': file_2,
        'dir_1/dir_4/file_3': file_3,
    }
    self.assertEqual(actual, expected)

  def test_load_with_angle_brackets_include_and_existing_file(self):
    self.include_directories = [
        'dir_5',
        'dir_6',
    ]
    self.files = {
        'dir_1/dir_2/file_1': 'content_1',
        'dir_1/dir_2/file_4': 'content_4_a',
        'dir_1/dir_3/file_2': 'content_2',
        'dir_1/dir_3/file_4': 'content_4_b',
        'dir_1/dir_4/file_3': 'content_3',
        'dir_1/dir_4/file_4': 'content_4_c',
        'dir_1/file_4': 'content_4_d',
        'dir_5/file_4': 'content_4_e',
        'file_4': 'content_4_f',
    }
    file_1 = mock.MagicMock()
    file_2 = mock.MagicMock()
    file_3 = mock.MagicMock()
    file_4 = mock.MagicMock()
    self.preprocessing_parser.parse.side_effect = (
        file_1,
        file_2,
        file_3,
        file_4,
    )
    include_file_2 = pre_ast.Include(
        path='../dir_3/file_2',
        quotes_type=pre_ast.Include.QuotesType.DOUBLE_QUOTES,
    )
    include_file_3 = pre_ast.Include(
        path='../dir_4/file_3',
        quotes_type=pre_ast.Include.QuotesType.DOUBLE_QUOTES,
    )
    include_file_4 = pre_ast.Include(
        path='file_4',
        quotes_type=pre_ast.Include.QuotesType.ANGLE_BRACKETS,
    )
    self.include_collector.collect_includes.side_effect = (
        [include_file_2],
        [include_file_3],
        [include_file_4],
        [],
    )
    with mock.patch('__builtin__.open', self._mock_open):
      with mock.patch('os.path.isfile', self._mock_isfile):
        actual = self.preprocessing_loader.load(
            file_path='dir_1/dir_2/file_1',
            include_directories=self.include_directories,
        )
    expected_parser_calls = [
        mock.call('content_1'),
        mock.call('content_2'),
        mock.call('content_3'),
        mock.call('content_4_e'),
    ]
    self.assertEqual(
        self.preprocessing_parser.parse.call_args_list,
        expected_parser_calls,
    )
    expected_include_collector_calls = [
        mock.call(file_1),
        mock.call(file_2),
        mock.call(file_3),
        mock.call(file_4),
    ]
    self.assertEqual(
        self.include_collector.collect_includes.call_args_list,
        expected_include_collector_calls,
    )
    expected = {
        'dir_1/dir_2/file_1': file_1,
        'dir_1/dir_3/file_2': file_2,
        'dir_1/dir_4/file_3': file_3,
        'dir_5/file_4': file_4,
    }
    self.assertEqual(actual, expected)

  def test_load_with_angle_brackets_include_and_nonexisting_file(self):
    self.include_directories = [
        'dir_5',
        'dir_6',
    ]
    self.files = {
        'dir_1/dir_2/file_1': 'content_1',
        'dir_1/dir_2/file_4': 'content_4_a',
        'dir_1/dir_3/file_2': 'content_2',
        'dir_1/dir_3/file_4': 'content_4_b',
        'dir_1/dir_4/file_3': 'content_3',
        'dir_1/dir_4/file_4': 'content_4_c',
        'dir_1/file_4': 'content_4_d',
        'file_4': 'content_4_e',
    }
    file_1 = mock.MagicMock()
    file_2 = mock.MagicMock()
    file_3 = mock.MagicMock()
    self.preprocessing_parser.parse.side_effect = (
        file_1,
        file_2,
        file_3,
    )
    include_file_2 = pre_ast.Include(
        path='../dir_3/file_2',
        quotes_type=pre_ast.Include.QuotesType.DOUBLE_QUOTES,
    )
    include_file_3 = pre_ast.Include(
        path='../dir_4/file_3',
        quotes_type=pre_ast.Include.QuotesType.DOUBLE_QUOTES,
    )
    include_file_4 = pre_ast.Include(
        path='file_4',
        quotes_type=pre_ast.Include.QuotesType.ANGLE_BRACKETS,
    )
    self.include_collector.collect_includes.side_effect = (
        [include_file_2],
        [include_file_3],
        [include_file_4],
    )
    with mock.patch('__builtin__.open', self._mock_open):
      with mock.patch('os.path.isfile', self._mock_isfile):
        actual = self.preprocessing_loader.load(
            file_path='dir_1/dir_2/file_1',
            include_directories=self.include_directories,
        )
    expected_parser_calls = [
        mock.call('content_1'),
        mock.call('content_2'),
        mock.call('content_3'),
    ]
    self.assertEqual(
        self.preprocessing_parser.parse.call_args_list,
        expected_parser_calls,
    )
    expected_include_collector_calls = [
        mock.call(file_1),
        mock.call(file_2),
        mock.call(file_3),
    ]
    self.assertEqual(
        self.include_collector.collect_includes.call_args_list,
        expected_include_collector_calls,
    )
    expected = {
        'dir_1/dir_2/file_1': file_1,
        'dir_1/dir_3/file_2': file_2,
        'dir_1/dir_4/file_3': file_3,
    }
    self.assertEqual(actual, expected)

  def assertEqual(self, actual, expected):
    message = '\n%s\n!=\n%s' % (actual, expected)
    super(TestPreprocessingLoader, self).assertEqual(actual, expected, message)


if __name__ == '__main__':
  unittest.main()
