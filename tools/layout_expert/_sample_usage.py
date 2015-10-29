"""A module containing an example of usage of the layout expert system."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import json
import logging
import os
import sys

from rekall import utils
from rekall.plugins.tools import profile_tool

from rekall.layout_expert.builtins import functions
from rekall.layout_expert.builtins import gcc_constants
from rekall.layout_expert.builtins import lazy_functions
from rekall.layout_expert.builtins import types as types_module
from rekall.layout_expert.c_ast import c_ast
from rekall.layout_expert.c_ast import pre_ast
from rekall.layout_expert.config_parser import config_parser as config_parser_module

from rekall.layout_expert.layout import layout_to_vtype_converter
from rekall.layout_expert.parser import expression_parser
from rekall.layout_expert.parser import parser
from rekall.layout_expert.preprocessing_loader import preprocessing_loader
from rekall.layout_expert.preprocessing_parser import preprocessing_parser
from rekall.layout_expert.preprocessing_visitors import include_collecting_visitor
from rekall.layout_expert.preprocessing_visitors import include_linking_visitor
from rekall.layout_expert.preprocessing_visitors import macro_expander
from rekall.layout_expert.preprocessing_visitors import macro_expression_evaluator_visitor
from rekall.layout_expert.preprocessing_visitors import preprocessing_visitor
from rekall.layout_expert.preprocessing_visitors import to_string_visitor
from rekall.layout_expert.serialization import json_serialization
from rekall.layout_expert.visitors import expression_evaluator_visitor
from rekall.layout_expert.visitors import field_collecting_visitor
from rekall.layout_expert.visitors import layout_computing_visitor
from rekall.layout_expert.visitors import type_collecting_visitor
from rekall.layout_expert.visitors import type_description_visitor
from rekall.layout_expert.visitors import typedef_resolving_visitor

sys.setrecursionlimit(25000)


def _build_pre_ast(args):
  result_paths = _get_result_paths(args.results_directory_path)
  include_directories = _get_include_directories(args.linux_repository_path)

  encoder = json_serialization.create_encoder()
  _set_safe_constructors_for_pre_ast_json_serialization()

  # From source to Pre-AST.
  _parse_encode_and_dump_pre_ast(
      args.source_file_path,
      include_directories,
      result_paths,
      encoder,
  )


def _make_profile(args):
  """A procedure that loads Pre-AST, computes a profile and stores it."""
  result_paths = _get_result_paths(args.results_directory_path)
  encoder = json_serialization.create_encoder()
  decoder = json_serialization.create_decoder()
  _set_safe_constructors_for_pre_ast_json_serialization()

  # From Pre-AST to preprocessed Pre-AST.
  _load_preprocess_and_dump_preprocessed_pre_ast(
      args.source_file_path,
      args.config_file_path,
      result_paths,
      encoder,
      decoder,
  )

  # From preprocessed Pre-AST to preprocessed source.
  _load_preprocessed_pre_ast_and_write_preprocessed_source_file(
      result_paths,
      decoder,
  )

  # From preprocessed source to AST.
  _parse_encode_and_dump_ast(
      result_paths,
      encoder,
  )

  # From AST to profile
  _set_safe_constructors_for_ast_json_serialization()
  _load_ast_compute_and_dump_profile(
      result_paths,
      args.config_file_path,
      args.system_map_file_path,
      args.layouts_to_compute,
      decoder,
  )


def _get_result_paths(results_directory_path):
  return utils.AttributeDict(
      pre_ast_forest_file_path=os.path.join(
          results_directory_path,
          'pre_ast.json',
      ),
      preprocessed_file_path=os.path.join(
          results_directory_path,
          'preprocessed.json',
      ),
      preprocessed_string_file_path=os.path.join(
          results_directory_path,
          'preprocessed.c',
      ),
      ast_file_path=os.path.join(
          results_directory_path,
          'ast.json',
      ),
      profile_file_path=os.path.join(
          results_directory_path,
          'profile.json',
      )
  )


def _get_include_directories(linux_repository_path):
  return (
      os.path.join(linux_repository_path, 'arch/x86/include'),
      os.path.join(linux_repository_path, 'arch/x86/include/generated'),
      os.path.join(linux_repository_path, 'arch/x86/include/uapi'),
      os.path.join(linux_repository_path, 'include'),
      os.path.join(linux_repository_path, 'include/uapi'),

      '/usr/lib/gcc/x86_64-linux-gnu/4.8/include',
      '/usr/include',
  )


def _parse_encode_and_dump_pre_ast(
    source_file_path,
    include_directories,
    result_paths,
    encoder,
):
  """A function that parses headers into a Pre-AST forest and stores it."""
  loader = _get_preprocessing_loader()

  logging.info('LOADING AND PARSING HEADERS')
  pre_ast_forest = loader.load(source_file_path, include_directories)
  logging.info('LOADED AND PARSED')

  logging.info('ENCODING HEADERS')
  encoded_pre_ast_forest = encoder.Encode(pre_ast_forest)
  logging.info('ENCODED')

  with open(result_paths.pre_ast_forest_file_path, 'w') as pre_ast_forest_file:
    json.dump(encoded_pre_ast_forest, pre_ast_forest_file)


def _load_preprocess_and_dump_preprocessed_pre_ast(
    source_file_path,
    config_file_path,
    result_paths,
    encoder,
    decoder,
):
  """A procedure that loads Pre-AST, preprocesses it and stores the result."""
  files = _load_and_decode(result_paths.pre_ast_forest_file_path, decoder)
  _link_includes(files)
  program = files[source_file_path]
  config_flags = _extract_config_flags(config_file_path)

  preprocessor = _get_preprocessor(config_flags)
  logging.info('PREPROCESSING')
  preprocessed_pre_ast = preprocessor.preprocess(program)
  logging.info('PREPROCESSED')

  logging.info('ENCODING PREPROCESSED')
  encoded = encoder.Encode(preprocessed_pre_ast)
  logging.info('ENCODED')

  with open(result_paths.preprocessed_file_path, 'w') as file_to_write:
    json.dump(encoded, file_to_write)


def _link_includes(files):
  logging.info('LINKING INCLUDES')
  include_linker = include_linking_visitor.IncludeLinkingVisitor()
  for file_ in files.values():
    include_linker.resolve(file_, files)
  logging.info('LINKED')


def _extract_config_flags(config_file_path):
  config_parser = config_parser_module.ConfigParser()
  logging.info('EXTRACTING CONFIG FLAGS')
  with open(config_file_path) as config_file:
    config = config_file.read()
  config_flags = config_parser.parse(config)
  logging.info('EXTRACTED')
  return config_flags


def _load_preprocessed_pre_ast_and_write_preprocessed_source_file(
    paths,
    decoder,
):
  preprocessed = _load_and_decode(paths.preprocessed_file_path, decoder)

  to_string_visitor_ = to_string_visitor.ToStringVisitor()
  logging.info('PRINTING TO STRING')
  string = to_string_visitor_.to_string(preprocessed)
  logging.info('PRINTED')

  with open(paths.preprocessed_string_file_path, 'w') as file_to_write:
    file_to_write.write(string)


def _parse_encode_and_dump_ast(paths, encoder):
  """A function that parses preprocessed source to AST tree and stores it."""
  preprocessed_string = _load_from_string(paths.preprocessed_string_file_path)

  parser_ = parser.Parser()
  logging.info('PARSING PREPROCESSED TO AST')
  parsed_ast = parser_.parse(preprocessed_string)
  logging.info('PARSED')

  logging.info('ENCODING AST')
  encoded = encoder.Encode(parsed_ast)
  logging.info('ENCODED')

  with open(paths.ast_file_path, 'w') as ast_file:
    json.dump(encoded, ast_file)


def _load_ast_compute_and_dump_profile(
    result_paths,
    config_file_path,
    system_map_file_path,
    layouts_to_compute,
    decoder,
):
  """A procedure that loads AST, computes the profile and stores it."""
  program = _load_and_decode(result_paths.ast_file_path, decoder)
  layouts, types = _get_layouts_and_types(program, layouts_to_compute)
  vtypes = _get_vtypes(layouts, types)

  linux_profile_converter = profile_tool.LinuxConverter(None, None)
  system_map = _load_from_string(system_map_file_path)
  system_map = linux_profile_converter.ParseSystemMap(system_map)

  config = _load_from_string(config_file_path)
  config = linux_profile_converter.ParseConfigFile(config)

  profile = linux_profile_converter.BuildProfile(system_map, vtypes, config)

  with open(result_paths.profile_file_path, 'w') as profile_file:
    profile_file.write(utils.PPrint(profile))


def _get_layouts_and_types(program, layouts_to_compute):
  """A function that computes layouts and type definitions from AST tree."""
  functions_ = functions.get_64bit_functions()
  expression_evaluator = _get_expression_evaluator(functions_)
  type_collector = _get_type_collector(expression_evaluator)
  types = type_collector.collect_types(program)
  types.update(types_module.get_64bit_types())
  layout_computer = _get_layout_computer(expression_evaluator, types)

  def _sizeof(type_name):
    return layout_computer.compute_layout(types[type_name]).bit_size // 8
  functions_['sizeof'] = _sizeof

  layouts = {}
  for name in layouts_to_compute:
    layouts[name] = layout_computer.compute_layout(types[name])

  return layouts, types


def _get_vtypes(layouts, types):
  typedef_resolver = typedef_resolving_visitor.TypedefResolvingVisitor()
  type_descriptor = type_description_visitor.TypeDescriptionVisitor(
      typedef_resolver,
  )
  converter = layout_to_vtype_converter.LayoutToVTypeConverter(type_descriptor)
  vtypes = {}
  for name, layout in layouts.iteritems():
    vtypes[name] = converter.to_vtype(layout, types[name], types)
  return vtypes


def _load_and_decode(file_path, decoder):
  with open(file_path) as file_to_load:
    encoded = json.load(file_to_load)

  logging.info('DECODING ' + file_path)
  decoded = decoder.Decode(encoded)
  logging.info('DECODED')
  return decoded


def _load_from_string(file_path):
  """A function that reads the content of a string file and returns it."""
  logging.info('LOADING FROM STRING %s', file_path)
  with open(file_path) as file_to_read:
    content = file_to_read.read()
  logging.info('LOADED')
  return content


def _get_preprocessing_loader():
  preprocessing_parser_ = preprocessing_parser.PreprocessingParser()
  include_collector = include_collecting_visitor.IncludeCollectingVisitor()
  return preprocessing_loader.PreprocessingLoader(
      preprocessing_parser_,
      include_collector
  )


def _get_preprocessor(config_flags):
  """A function that is a factory for preprocessor object."""
  object_like_macros = _get_object_like_macros(config_flags)

  function_like_macros = {}

  preprocessor_and_64bit_functions = (
      functions.get_preprocessor_and_64bit_functions()
  )

  lazy_and_state_dependent_functions = (
      lazy_functions.get_lazy_and_state_dependent_functions(
          object_like_macros,
          function_like_macros,
      )
  )

  macro_expression_evaluator = (
      macro_expression_evaluator_visitor.MacroExpressionEvaluatorVisitor(
          object_likes=object_like_macros,
          function_likes=function_like_macros,
          functions=preprocessor_and_64bit_functions,
          lazy_functions=lazy_and_state_dependent_functions,
      )
  )

  state_dependent_functions = lazy_functions.get_state_dependent_functions(
      object_like_macros,
      function_like_macros,
  )

  expression_parser_ = expression_parser.expression_parser()
  term_expression_evaluator = (
      macro_expression_evaluator_visitor.MacroExpressionEvaluatorVisitor(
          object_likes=object_like_macros,
          function_likes=function_like_macros,
          functions=functions.get_preprocessor_functions(),
          lazy_functions=state_dependent_functions,
          keep_parentheses=True,
      )
  )

  macro_expander_ = macro_expander.MacroExpander(
      expression_parser=expression_parser_,
      expression_evaluator=term_expression_evaluator,
  )

  return preprocessing_visitor.PreprocessingVisitor(
      object_likes=object_like_macros,
      function_likes=function_like_macros,
      functions=preprocessor_and_64bit_functions,
      expression_evaluator=macro_expression_evaluator,
      macro_expander=macro_expander_,
  )


def _get_object_like_macros(config_flags):
  """A function that produces object like macros from config flags."""
  macros = {}
  # Add object like intrinsics from gcc.
  macros.update(gcc_constants.get_x86_64_kernel_compile_object_likes())
  # Append config vars.
  for flag, value in config_flags.iteritems():
    macros[flag] = pre_ast.DefineObjectLike(
        name=flag,
        replacement=value,
        string_replacement=str(value.value),
    )
  return macros


def _get_expression_evaluator(functions_):
  enum_count_variables = {
      'NR_MM_COUNTERS': 3,
      'PIDTYPE_MAX': 3,
      'perf_nr_task_contexts': 2,
  }

  return expression_evaluator_visitor.ExpressionEvaluatorVisitor(
      variables=enum_count_variables,
      functions=functions_,
  )


def _get_type_collector(expression_evaluator):
  return type_collecting_visitor.TypeCollectingVisitor(
      expression_evaluator,
  )


def _get_layout_computer(expression_evaluator, types):
  """A function that is a factory for layout computer object."""
  field_collector = field_collecting_visitor.FieldCollectingVisitor(
      expression_evaluator=expression_evaluator,
  )
  layout_computer = layout_computing_visitor.LayoutComputingVisitor(
      expression_evaluator=expression_evaluator,
      field_collector=field_collector,
      types=types,
  )
  field_collector.layout_computer = layout_computer
  return layout_computer


def _set_safe_constructors_for_pre_ast_json_serialization():
  """A functions that sets constructors for Pre-AST de-serialization."""
  json_serialization.DataContainerObjectRenderer.set_safe_constructors(
      c_ast.CNestedExpression,
      c_ast.CVariable,
      c_ast.CNumber,
      c_ast.CFunctionCall,
      c_ast.CLiteral,
      pre_ast.File,
      pre_ast.Include,
      pre_ast.Include.QuotesType,
      pre_ast.Pragma,
      pre_ast.PragmaArgument,
      pre_ast.Error,
      pre_ast.DefineObjectLike,
      pre_ast.DefineFunctionLike,
      pre_ast.Undef,
      pre_ast.If,
      pre_ast.ConditionalBlock,
      pre_ast.CompositeBlock,
      pre_ast.TextBlock,
  )


def _set_safe_constructors_for_ast_json_serialization():
  """A functions that sets the set of constructors for AST de-serialization."""
  json_serialization.DataContainerObjectRenderer.set_safe_constructors(
      pre_ast.If,
      pre_ast.ConditionalBlock,
      c_ast.CProgram,
      c_ast.CEnum,
      c_ast.CStruct,
      c_ast.CUnion,
      c_ast.CArray,
      c_ast.CPointer,
      c_ast.CPointerToFunction,
      c_ast.CSimpleType,
      c_ast.CTypeReference,
      c_ast.CTypeDefinition,
      c_ast.CField,
      c_ast.CTypedef,
      c_ast.CFunctionCall,
      c_ast.CNestedExpression,
      c_ast.CVariable,
      c_ast.CNumber,
      c_ast.CLiteral,
      CAttribute=lambda name, parameters: c_ast.CAttribute(name, *parameters)
  )


def _get_parser():
  """A function that creates a (argparse) argument parser."""
  argument_parser = argparse.ArgumentParser()
  argument_parser.add_argument(
      '--source_file_path',
      dest='source_file_path',
      default='/usr/local/google/home/arkadiuszs/rekall/tools/linux/module.c',
  )
  argument_parser.add_argument(
      '--results_directory_path',
      dest='results_directory_path',
      default='/usr/local/google/home/arkadiuszs/experimental/parser',
  )
  subparsers = argument_parser.add_subparsers()
  build_pre_ast_parser = subparsers.add_parser('build_pre_ast')
  build_pre_ast_parser.set_defaults(action=_build_pre_ast)
  build_pre_ast_parser.add_argument(
      '--linux_repository_path',
      dest='linux_repository_path',
      default='/usr/local/google/home/arkadiuszs/experimental/dwarf/repo',
  )
  make_profile_parser = subparsers.add_parser('make_profile')
  make_profile_parser.set_defaults(action=_make_profile)
  make_profile_parser.add_argument(
      '--config_file_path',
      dest='config_file_path',
      default=(
          '/usr/local/google/home/arkadiuszs/experimental/dwarf/repo/.config'
      ),
  )
  make_profile_parser.add_argument(
      '--system_map_file_path',
      dest='system_map_file_path',
      default=(
          '/usr/local/google/home/arkadiuszs/experimental/parser/system_map'
      ),
  )
  make_profile_parser.add_argument(
      '--layouts_to_compute',
      dest='layouts_to_compute',
      nargs='*',
      default=[
          'struct cpuinfo_x86',
          'struct cred',
          'struct dentry',
          'struct file',
          'union fpregs_state',
          'struct fpu',
          'struct fs_struct',
          'struct list_head',
          'struct load_weight',
          'struct mm_struct',
          'struct module',
          'struct path',
          'struct qstr',
          'struct rb_node',
          'struct restart_block',
          'struct sched_entity',
          'struct sched_rt_entity',
          'struct task_struct',
          'struct timespec',
          'struct thread_struct',
          'struct tty_ldisc',
          'struct vfsmount',
      ],
  )
  return argument_parser


if __name__ == '__main__':
  logging.basicConfig(level=logging.INFO)
  _parser_obj = _get_parser()
  _args = _parser_obj.parse_args()
  _args.action(_args)
