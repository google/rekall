"""A module containing an include following loader for C header files."""


from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import itertools
import os

from rekall.layout_expert.c_ast import pre_ast


class PreprocessingLoader(object):
  """A class representing an include following loader for C header files."""

  def __init__(self, preprocessing_parser, include_collector):
    self._preprocessing_parser = preprocessing_parser
    self._include_collector = include_collector

  def load(
      self,
      file_path,
      include_directories,
      opened_files=None,
      loaded_files=None,
  ):
    """A method that loads a header file and all its includes recursively."""
    if not opened_files:
      opened_files = []

    if not loaded_files:
      loaded_files = {}

    if file_path in loaded_files:
      return loaded_files

    source = self._get_file_content(file_path)
    file_ = self._preprocessing_parser.parse(source)
    opened_files.append(file_path)
    loaded_files[file_path] = file_
    self._load_includes(file_, include_directories, opened_files, loaded_files)
    opened_files.pop()
    return loaded_files

  def _load_includes(
      self,
      tree,
      include_directories,
      opened_files,
      loaded_files,
  ):
    includes = self._include_collector.collect_includes(tree)
    for include in includes:
      directories_to_try = self._get_directories_to_try(
          include,
          include_directories,
          opened_files,
      )
      self._try_to_load_from_directories(
          directories_to_try,
          include,
          include_directories,
          opened_files,
          loaded_files,
      )

  def _get_directories_to_try(
      self,
      include,
      include_directories,
      opened_files,
  ):
    if include.quotes_type == pre_ast.Include.QuotesType.ANGLE_BRACKETS:
      return include_directories
    elif include.quotes_type == pre_ast.Include.QuotesType.DOUBLE_QUOTES:
      opened_files_directories = map(os.path.dirname, opened_files)
      return itertools.chain(
          reversed(opened_files_directories),
          include_directories,
      )

  def _try_to_load_from_directories(
      self,
      directories_to_try,
      include,
      include_directories,
      opened_files,
      loaded_files,
  ):
    for directory_path in directories_to_try:
      if self._try_to_load_from_directory(
          directory_path,
          include,
          include_directories,
          opened_files,
          loaded_files,
      ):
        return

  def _try_to_load_from_directory(
      self,
      directory_path,
      include,
      include_directories,
      opened_files,
      loaded_files,
  ):
    absolute_path = os.path.join(directory_path, include.path)
    normalized_path = os.path.normpath(absolute_path)
    if os.path.isfile(normalized_path):
      self.load(
          normalized_path,
          include_directories,
          opened_files,
          loaded_files,
      )
      include.absolute_path = normalized_path
      return True
    else:
      return False

  def _get_file_content(self, file_path):
    with open(file_path) as opened_file:
      return opened_file.read().decode('utf8')


class IncludeNotFoundException(Exception):
  pass
