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

"""The layout expert's public interface."""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import logging
import os
import sys
import time


from layout_expert.builtins import functions
from layout_expert.builtins import types as types_module
from layout_expert.c_ast import c_ast
from layout_expert.config_parser import config_parser as config_parser_module
from layout_expert.lib import type_manager as type_manager_module
from layout_expert.parsers import trimming_parser
from layout_expert.parsers import util
from layout_expert.preprocessing_parser import preprocessing_parser
from layout_expert.preprocessing_visitors import include_linking_visitor
from layout_expert.preprocessing_loader import preprocessing_loader
from layout_expert.preprocessing_visitors import preprocessing_visitor
from layout_expert.preprocessing_visitors import to_string_visitor
from layout_expert.visitors import type_collecting_visitor
from rekall.plugins.tools import profile_tool


class ProgressReporter(object):
    def __init__(self):
        self.last_time = 0
        self.last_message_len = 0
        self.refresh = 0.2

    def report_progress(self, message, *args):
        now = time.time()
        if now - self.last_time > self.refresh:
            # Clear the last message.
            sys.stdout.write("\r" + " " * self.last_message_len + "\r")

            # Write the new message.
            message = message % args
            sys.stdout.write(" " + message + "\r")
            sys.stdout.flush()

            self.last_time = now
            self.last_message_len = len(message) + 2



class RekallProfileBuilder(object):
    """Builds Rekall profiles."""

    def __init__(self, type_manager, system_map_text, config_text):
        self.structs = {}
        self.enums = {}
        self.rev_enums = {}
        self.type_manager = type_manager
        self.linux_profile_converter = profile_tool.LinuxConverter(None, None)
        self.system_map = self.linux_profile_converter.ParseSystemMap(
            system_map_text)
        self.config = self.linux_profile_converter.ParseConfigFile(config_text)

    def add_type(self, name, type):
        if isinstance(type, (c_ast.CStruct, c_ast.CUnion)):
            self._add_struct(name, type)

        elif isinstance(type, c_ast.CEnum):
            self._add_enum(name, type)

        elif isinstance(type, c_ast.CProgram):
            self.add_type(name, type.content[0])

        elif isinstance(type, (c_ast.CTypedef, c_ast.CTypeDefinition)):
            self.add_type(name, type.type_definition)

        elif isinstance(type, c_ast.CTypeReference):
            self.add_type(name, self.type_manager.get_type_ast(type.name))

    def _normalize_name(self, name):
        """Rekall profile strip the "struct" from the full type name."""
        parts = name.split()
        if parts[0] in ("struct", "enum", "union"):
            name = name.split()[-1]

        return name

    def _resolve_typedef(self, type):
        """Return the final type that a typedef is pointing to."""
        if isinstance(type, c_ast.CProgram):
            return self._resolve_typedef(type.content[0])

        if isinstance(type, (c_ast.CTypedef, c_ast.CTypeDefinition)):
            referred_type = self._resolve_typedef(type.type_definition)
            # If the target is anonymous we refer to it by the typedef name.
            if referred_type.name and "__unknown" in referred_type.name:
                referred_type.name = type.name

            return referred_type

        if isinstance(type, c_ast.CTypeReference):
            referred_type = self.type_manager.get_type_ast(type.name)
            if referred_type.name == type.name:
                return type

            return self._resolve_typedef(referred_type)

        return type

    def _resolve_reference(self, type):
        """Recursively resolve the type_name.

        We stop when we reach a CSimpleType, CStruct or CEnum.

        Returns: a list of [target, target_args]
        """
        type = self._resolve_typedef(type)

        if isinstance(type, (c_ast.CUnion, c_ast.CStruct, c_ast.CSimpleType)):
            return [self._normalize_name(type.name), {}]

        # The actual Enum should be exported separately so we just refer to it
        # by name here.
        elif isinstance(type, c_ast.CEnum):
            return ["Enumeration",
                    dict(enum_name=self._normalize_name(type.name),
                         target="unsigned int")]

        elif isinstance(type, c_ast.CPointer):
            target, target_args = self._resolve_reference(type.type_definition)
            return ["Pointer", dict(target=target, target_args=target_args)]

        elif isinstance(type, c_ast.CProgram):
            return self._resolve_reference(type.content[0])

        elif isinstance(type, c_ast.CTypedef):
            target, target_args = self._resolve_reference(type.type_definition)

            # If the target is anonymous we refer to it by the typedef name.
            if "__unknown" in target:
                target = type.name

            return target, target_args

        elif isinstance(type, c_ast.CTypeReference):
            referred_type = self.type_manager.get_type_ast(type.name)

            if isinstance(referred_type, c_ast.CProgram):
                referred_type = referred_type.content[0]

            if not isinstance(referred_type, c_ast.CEnum):
                # Reference loop means the type is not known, just refer to it
                # and let Rekall sort it out (It might be able to get type
                # definitions for this type later).
                if referred_type.name == type.name:
                    return [self._normalize_name(type.name), {}]

            return self._resolve_reference(referred_type)

        elif isinstance(type, c_ast.CArray):
            target, target_args = self._resolve_reference(type.type_definition)
            return ["Array", dict(
                target=target, target_args=target_args, count=type.length)]

        elif isinstance(type, c_ast.CVoidType):
            return ["Void", {}]

        elif isinstance(type, c_ast.CTypeDefinition):
            return self._resolve_reference(type.type_definition)

        elif isinstance(type, c_ast.CFunction):
            return ["Function", {}]

    def _add_enum(self, name, enum_type):
        enum = {}
        rev_enum = {}
        for field in enum_type.fields:
            value = self.type_manager.evaluate(field.value)
            enum[value] = field.name
            rev_enum[field.name] = value

        name = self._normalize_name(name)
        self.enums[name] = enum
        self.rev_enums[name] = rev_enum

    def _get_bitfield(self, field_layout, target):
        # To make it easier we start the field at the bit offset and
        start_bit = field_layout.bit_offset % field_layout.layout.bit_alignment
        end_bit = start_bit + field_layout.layout.bit_size
        byte_offset = (field_layout.bit_offset - start_bit) // 8
        return [
            'BitField', {
                'start_bit': start_bit,
                'end_bit': end_bit,
                'target': target,
            },
            byte_offset
        ]

    def _add_struct(self, name, struct_type):
        local_field_id = 1
        layout = self.type_manager.get_type_layout(name)
        fields = {}
        result = [layout.bit_size // 8, fields]
        for field_layout, field in zip(layout.fields, struct_type.content):
            target, target_args = self._resolve_reference(
                field.type_definition)

            # This is actually a bit field.
            if field_layout.layout.bit_field:
                target, target_args, byte_offset = self._get_bitfield(
                    field_layout, target)
            else:
                byte_offset = field_layout.bit_offset // 8

            # Name local unknown fields in a consistent way.
            field_name = field.name
            if "unknown" in field_name:
                field_name = "u%s" % local_field_id
                local_field_id += 1

            fields[field_name] = [byte_offset, [target, target_args]]

        self.structs[self._normalize_name(name)] = result

    def get_profile(self):
        self.structs["$ENUMS"] = self.enums
        self.structs["$REVENUMS"] = self.rev_enums

        return self.linux_profile_converter.BuildProfile(
            self.system_map, self.structs, self.config)


class PreASTBuilder(object):
    """Builds the initial Preprocessor AST."""

    def __init__(self, linux_source_path, module_source_path, progress_cb=None,
                 cache_dir=None, overwrite=False):
        self.linux_source_path = linux_source_path
        self.module_source_path = module_source_path
        self.include_directories = (
            os.path.join(self.linux_source_path, 'arch/x86/include'),
            os.path.join(self.linux_source_path, 'arch/x86/include/generated'),
            os.path.join(self.linux_source_path, 'arch/x86/include/uapi'),
            os.path.join(self.linux_source_path, 'include'),
            os.path.join(self.linux_source_path, 'include/uapi'),
            '/usr/lib/gcc/x86_64-linux-gnu/4.8/include',
            '/usr/include',
        )
        self.cache = util.CacheManager(cache_dir, force=overwrite)
        if progress_cb:
            self.progress_cb = progress_cb
        else:
            self.progress_cb = ProgressReporter().report_progress

    def generate_pre_ast(self):
        logging.info('LOADING AND PARSING HEADERS')
        result = self.cache.run(
            'pre-ast-forest.json',
            self._generate_pre_ast,
            desc="built pre-ast forest")

        logging.info('LOADED AND PARSED')
        return result

    def _generate_pre_ast(self):
        loader = preprocessing_loader.PreprocessingLoader(
            include_directories=self.include_directories,
            cache=self.cache, progress_cb=self.progress_cb)

        # We start parsing from the debug module.
        root_node = self.module_source_path
        pre_ast_forest = loader.load(root_node)

        # Mark the root of the tree especially so it can be found in the next
        # stage.
        root_node_ast = pre_ast_forest.pop(root_node)
        pre_ast_forest["ROOT"] = root_node_ast

        return pre_ast_forest


class ProfileBuilder(object):
    """Builds a Rekall profile given a pre-processor AST.

    The Pre-AST is produced from kernel sources using the PreASTBuilder() class.
    """

    # Filenames for intermediate cached data.
    preprocessed_json_file_path = 'preprocessed.json'
    preprocessed_string_file_path = 'preprocessed.c'
    c_ast_file_path = 'c_ast.json'
    profile_file_path = 'profile.json'
    trimming_dict_path = 'trimming_dict.json'

    def __init__(self, pre_ast, config_text, system_map_text, progress_cb=None,
                 cache_dir=None, overwrite=False):
        """Initialize the ProfileBuilder.

        Args:
          pre_ast: A Preprocessor AST object.
          config_text: The content text of the kernel .config file
            (e.g. /boot/config-3.13.0-71-generic)
          system_map_text: The content text of the system map.
            (e.g. /boot/System.map-3.13.0-71-generic)
        """
        self.pre_ast_forest = pre_ast
        self.config_text = config_text
        self.system_map_text = system_map_text
        self.cache = util.CacheManager(cache_dir, force=overwrite)
        self.functions_ = functions.get_arithmetic_functions()

        if progress_cb:
            self.progress_cb = progress_cb
        else:
            self.progress_cb = ProgressReporter().report_progress

    def _extract_config_flags(self):
        logging.info('EXTRACTING CONFIG FLAGS')
        config_parser = config_parser_module.ConfigParser()
        config_flags = config_parser.parse(self.config_text)
        logging.info('EXTRACTED')

        return config_flags

    def _preprocess_pre_ast(self):
        # First step - link includes in the Pre_AST forest.
        self._link_includes()

        # Second step - Use the config #defines to pre-process the Pre-AST.
        config_flags = self._extract_config_flags()

        # Pre-processor macro database.
        macros = preprocessing_parser.Macros(config_flags)

        # Get the preprocessing visitor.
        visitor = preprocessing_visitor.PreprocessingVisitor(
            macros, progress_cb=self.progress_cb)

        logging.info('PREPROCESSING')
        # Preprocess starting from the root node.
        root_node = self.pre_ast_forest["ROOT"]
        result = visitor.preprocess(root_node)
        logging.info('PREPROCESSED')

        return result

    def _link_includes(self):
        logging.info('LINKING INCLUDES')
        include_linker = include_linking_visitor.IncludeLinkingVisitor()
        for file_ in self.pre_ast_forest.values():
            include_linker.resolve(file_, self.pre_ast_forest)
        logging.info('LINKED')

    def _preprocess_source_file(self, preprocessed_pre_ast):
        visitor = to_string_visitor.ToStringVisitor()
        logging.info('GENERATING PURE C FILE')
        string = visitor.to_string(preprocessed_pre_ast)
        logging.info('GENERATED')

        return string

    def _get_layouts_and_types(self, program, layouts_to_compute):
        """Computes layouts and type definitions from AST tree."""
        expression_evaluator = self._get_expression_evaluator()
        type_collector = type_collecting_visitor.TypeCollectingVisitor(
            expression_evaluator)

        types = type_collector.collect_types(program)
        types.update(types_module.get_64bit_types())
        layout_computer = self._get_layout_computer(expression_evaluator, types)

        def _sizeof(type_name):
            return layout_computer.compute_layout(
                types[type_name]).bit_size // 8

        # Implement a sizeof function.
        self.functions_['sizeof'] = _sizeof

        layouts = {}
        for name in layouts_to_compute:
            layouts[name] = layout_computer.compute_layout(types[name])

        return layouts, types

    def create_profile(self, layouts_to_compute):
        """Create a profile."""

        # First step: Preprocess the Pre-AST using the settings in the config
        # file.  This reduces the complete Pre_AST (which contains all branches
        # of #ifdef) into only those which are actually used.
        preprocessed_pre_ast = self.cache.run(
            self.preprocessed_json_file_path,
            self._preprocess_pre_ast,
            desc="preprocessing pre-ast")

        # Step 2: Now visit all text nodes in the preprocessed_pre_ast to
        # produce a concatenated C source file, free from preprocessing
        # directives.
        preprocessed_source_file = unicode(self.cache.run(
            self.preprocessed_string_file_path,
            self._preprocess_source_file, preprocessed_pre_ast, raw=True,
            desc="generating pure C file"))

        # Step 3: Trim the large pre-processed C source file into a smaller file
        # containing only those layouts we care about. First we partition the
        # large C file into snippets.
        logging.info('TRIMMING C FILE')
        trimming_dict = self.cache.run(
            self.trimming_dict_path,
            trimming_parser.build_snippets, preprocessed_source_file,
            progress_cb=self.progress_cb,
            desc="trimming C file")
        logging.info('TRIMMED C FILE')

        # Step 4: Use the layout computer to parse only the snippets we want.
        type_manager = type_manager_module.TypeManager(
            trimming_dict=trimming_dict, progress_cb=self.progress_cb)

        def compute_layouts():
            for type_name in layouts_to_compute:
                type_manager.get_type_ast(type_name)

            return type_manager.types

        logging.info('PARSING STRUCTS')
        program_c_ast = self.cache.run(
            self.c_ast_file_path,
            compute_layouts,
            desc="parsing struct layouts")
        logging.info('PARSED')

        # Restore the types into the layout_manager.
        type_manager.types = program_c_ast

        # Step 5: Use the computed AST to produce a usable profile.
        logging.info('GENERATING PROFILE')
        rekall_profile_builder = RekallProfileBuilder(
            type_manager,
            self.system_map_text,
            self.config_text)

        logging.info("Exporting %s structs", len(program_c_ast))
        for type_name, type_definition in program_c_ast.items():
            rekall_profile_builder.add_type(type_name, type_definition)
        logging.info('GENERATED')

        return rekall_profile_builder.get_profile()
