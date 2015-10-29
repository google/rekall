from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest

from rekall.layout_expert.builtins import gcc_constants
from rekall.layout_expert.c_ast import c_ast


class TestGetX8664KernelCompileObjectLikes(unittest.TestCase):

  def setUp(self):
    self.object_likes = gcc_constants.get_x86_64_kernel_compile_object_likes()

  def test_stdc(self):
    stdc = self.object_likes['__STDC__']
    self.assertEqual(stdc.name, '__STDC__')
    self.assertEqual(stdc.replacement, c_ast.CNumber(1))
    self.assertEqual(stdc.string_replacement, '1')

  def test_stdc_version(self):
    stdc_version = self.object_likes['__STDC_VERSION__']
    self.assertEqual(stdc_version.name, '__STDC_VERSION__')
    self.assertEqual(stdc_version.replacement, c_ast.CNumber(201112L))
    self.assertEqual(stdc_version.string_replacement, '201112L')

  def test_xopen_source(self):
    xopen_source = self.object_likes['_XOPEN_SOURCE']
    self.assertEqual(xopen_source.name, '_XOPEN_SOURCE')
    self.assertEqual(xopen_source.replacement, c_ast.CNumber(500))
    self.assertEqual(xopen_source.string_replacement, '500')

  def test_gnuc(self):
    gnuc = self.object_likes['__GNUC__']
    self.assertEqual(gnuc.name, '__GNUC__')
    self.assertEqual(gnuc.replacement, c_ast.CNumber(4))
    self.assertEqual(gnuc.string_replacement, '4')

  def test_gnuc_minor(self):
    gnuc_minor = self.object_likes['__GNUC_MINOR__']
    self.assertEqual(gnuc_minor.name, '__GNUC_MINOR__')
    self.assertEqual(gnuc_minor.replacement, c_ast.CNumber(8))
    self.assertEqual(gnuc_minor.string_replacement, '8')

  def test_gnuc_patchlevel(self):
    gnuc_patchlevel = self.object_likes['__GNUC_PATCHLEVEL__']
    self.assertEqual(gnuc_patchlevel.name, '__GNUC_PATCHLEVEL__')
    self.assertEqual(gnuc_patchlevel.replacement, c_ast.CNumber(4))
    self.assertEqual(gnuc_patchlevel.string_replacement, '4')

  def test_x86_64(self):
    x86_64 = self.object_likes['__x86_64__']
    self.assertEqual(x86_64.name, '__x86_64__')
    self.assertEqual(x86_64.replacement, c_ast.CNumber(1))
    self.assertEqual(x86_64.string_replacement, '1')

  def test_kernel(self):
    kernel = self.object_likes['__KERNEL__']
    self.assertEqual(kernel.name, '__KERNEL__')
    self.assertEqual(kernel.replacement, c_ast.CLiteral(''))
    self.assertEqual(kernel.string_replacement, '')

  def assertEqual(self, actual, expected):
    message = '\n%s\n!=\n%s' % (actual, expected)
    super(TestGetX8664KernelCompileObjectLikes, self).assertEqual(
        actual,
        expected,
        message,
    )


if __name__ == '__main__':
  unittest.main()
