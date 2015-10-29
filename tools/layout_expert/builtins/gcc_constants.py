"""A module containing GCC compile time constants."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from rekall.layout_expert.c_ast import c_ast
from rekall.layout_expert.c_ast import pre_ast


def get_x86_64_kernel_compile_object_likes():
  return {
      '__STDC__': pre_ast.DefineObjectLike(
          name='__STDC__',
          replacement=c_ast.CNumber(1),
          string_replacement='1',
      ),
      '__STDC_VERSION__': pre_ast.DefineObjectLike(
          name='__STDC_VERSION__',
          replacement=c_ast.CNumber(201112L),
          string_replacement='201112L',
      ),
      '_XOPEN_SOURCE': pre_ast.DefineObjectLike(
          name='_XOPEN_SOURCE',
          replacement=c_ast.CNumber(500),
          string_replacement='500',
      ),
      '__GNUC__': pre_ast.DefineObjectLike(
          name='__GNUC__',
          replacement=c_ast.CNumber(4),
          string_replacement='4',
      ),
      '__GNUC_MINOR__': pre_ast.DefineObjectLike(
          name='__GNUC_MINOR__',
          replacement=c_ast.CNumber(8),
          string_replacement='8',
      ),
      '__GNUC_PATCHLEVEL__': pre_ast.DefineObjectLike(
          name='__GNUC_PATCHLEVEL__',
          replacement=c_ast.CNumber(4),
          string_replacement='4',
      ),
      '__x86_64__': pre_ast.DefineObjectLike(
          name='__x86_64__',
          replacement=c_ast.CNumber(1),
          string_replacement='1',
      ),
      '__KERNEL__': pre_ast.DefineObjectLike(
          name='__KERNEL__',
          replacement=c_ast.CLiteral(''),
          string_replacement='',
      ),
  }
