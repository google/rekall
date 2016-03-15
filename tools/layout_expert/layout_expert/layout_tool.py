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

"""The layout expert system main tool."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import logging
import sys

from rekall import utils as rekall_utils
from layout_expert.lib import layout_manager
from layout_expert.serialization import json_serialization

sys.setrecursionlimit(25000)


def _build_pre_ast_forest(args):
    """Build the pre-ast forest.

    The Pre-AST forest is a dict keyed by header path and the value is the
    Pre-AST generated from parsing that file.
    """
    pre_ast_builder = layout_manager.PreASTBuilder(
        linux_source_path=args.linux_repository_path,
        module_source_path=args.source_file_path,
        cache_dir=args.cache_dir,
        overwrite=args.overwrite)

    pre_ast_forest = pre_ast_builder.generate_pre_ast()
    with open(args.output, "wb") as fd:
        json_serialization.dump_file(pre_ast_forest, fd)


def _make_profile(args):
    """A procedure that loads Pre-AST, computes a profile and stores it."""
    config_text = open(args.config_file_path).read()
    system_map_text = open(args.system_map_file_path).read()
    logging.info('LOADING PREPROCESSOR AST FROM: %s', args.pre_ast_path)
    preprocessed_ast = json_serialization.load_file(open(args.pre_ast_path))
    logging.info('DONE')

    if not preprocessed_ast:
        raise RuntimeError("Unable to load pre-ast file.")

    manager = layout_manager.ProfileBuilder(
        preprocessed_ast, config_text, system_map_text,
        cache_dir=args.cache_dir)

    profile = manager.create_profile(args.layouts_to_compute)

    with open(args.output, "wb") as fd:
        fd.write(rekall_utils.PPrint(profile))


def _get_parser():
    """A function that creates a (argparse) argument parser."""

    # Global options.
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument(
        "-v", "--verbose",
        default=False,
        action="store_true",
        help="Enable to see more verbose messages")

    argument_parser.add_argument(
        '--cache_dir',
        default=None,
        help="The path where cache files can be written."
    )

    argument_parser.add_argument(
        '--overwrite',
        default=False, action="store_true",
        help="If set we overwrite cached files."
    )

    subparsers = argument_parser.add_subparsers()
    build_pre_ast_parser = subparsers.add_parser('build_pre_ast')
    build_pre_ast_parser.set_defaults(action=_build_pre_ast_forest)
    build_pre_ast_parser.add_argument(
        '-s', '--source_file_path',
        required=True,
        help="The path to the module.c file.",
    )

    build_pre_ast_parser.add_argument(
        '-l', '--linux_repository_path',
        required=True,
        help="The path to the linux source or headers tree."
    )

    build_pre_ast_parser.add_argument(
        'output',
        default=None,
        help="Path to write the produced profile."
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
            'struct timekeeper',
            'struct fpu',
            'struct fs_struct',
            'struct list_head',
            'struct load_weight',
            'struct mm_struct',
            'struct module',
            'struct path',
            'struct pv_info',
            'struct qstr',
            'struct mount',
            'struct rb_node',
            'struct restart_block',
            'struct sched_entity',
            'struct sched_rt_entity',
            'struct task_struct',
            'struct timespec',
            'struct thread_struct',
            'struct tty_ldisc',
            'struct vfsmount',
            'struct kuid_t',
            'struct kgid_t',
        ],
    )

    make_profile_parser.add_argument(
        'pre_ast_path',
        default=None,
        help="Path to the serialized Pre-AST file "
        "(as obtained from the build_pre_ast command)"
    )

    make_profile_parser.add_argument(
        'output',
        default=None,
        help="Path to write the produced profile."
    )

    return argument_parser


def main():
    try:
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.INFO)
        root_logger.handlers[0].setFormatter(
            logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')
        )

        _parser_obj = _get_parser()
        _args = _parser_obj.parse_args()
        if _args.verbose:
            root_logger.setLevel(logging.DEBUG)

        _args.action(_args)
    except (Exception, KeyboardInterrupt):
        import pdb
        pdb.post_mortem()
        raise


if __name__ == '__main__':
    main()
