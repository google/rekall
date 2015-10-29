from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest

import pyparsing

from rekall.layout_expert.c_ast import c_ast
from rekall.layout_expert.c_ast import pre_ast
from rekall.layout_expert.parser import parser


class TestParser(unittest.TestCase):

  @classmethod
  def setUpClass(cls):
    cls.parser = parser.Parser()

  def test_construction(self):
    self.assertIsNotNone(self.parser)

  def test_parse_with_empty_program(self):
    source = ''
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([])
    self.assertEqual(actual, expected)

  def test_parse_with_one_field(self):
    source = """
        int v1;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField('v1', type_definition=c_ast.CTypeReference('int')),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_simple_fields(self):
    source = """
        int v1;
        type_t v2, v3;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField('v1', c_ast.CTypeReference('int')),
        c_ast.CField('v2', c_ast.CTypeReference('type_t')),
        c_ast.CField('v3', c_ast.CTypeReference('type_t')),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_pointer(self):
    source = """
        int *p;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField('p', c_ast.CPointer(c_ast.CTypeReference('int'))),
    ])
    self.assertEqual(actual, expected)

  def test_parse_pointer_to_const_int(self):
    source = """
        const int *p;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField('p', c_ast.CPointer(c_ast.CTypeReference('int'))),
    ])
    self.assertEqual(actual, expected)

  def test_parse_pointer_to_const_int_with_const_between(self):
    source = """
        int const *p;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField('p', c_ast.CPointer(c_ast.CTypeReference('int'))),
    ])
    self.assertEqual(actual, expected)

  def test_parse_const_pointer_to_int(self):
    source = """
        int *const p;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField('p', c_ast.CPointer(c_ast.CTypeReference('int'))),
    ])
    self.assertEqual(actual, expected)

  def test_parse_const_pointer_to_const_int(self):
    source = """
        const int *const p;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField('p', c_ast.CPointer(c_ast.CTypeReference('int'))),
    ])
    self.assertEqual(actual, expected)

  def test_parse_cosnt_pointer_to_const_int_with_const_between(self):
    source = """
        int const *const p;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField('p', c_ast.CPointer(c_ast.CTypeReference('int'))),
    ])
    self.assertEqual(actual, expected)

  def test_parse_cosnt_pointer_to_const_int_with_additional_const_between(
      self,
  ):
    source = """
        const int const *const p;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField('p', c_ast.CPointer(c_ast.CTypeReference('int'))),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_pointer_to_pointer(self):
    source = """
        int **p;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='p',
            type_definition=c_ast.CPointer(
                c_ast.CPointer(c_ast.CTypeReference('int')),
            ),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_const_pointer_to_const_pointer(self):
    source = """
        int *const *const p;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='p',
            type_definition=c_ast.CPointer(
                c_ast.CPointer(c_ast.CTypeReference('int')),
            ),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_const_pointer_to_const_pointer_to_const(self):
    source = """
        const int *const *const p;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='p',
            type_definition=c_ast.CPointer(
                c_ast.CPointer(c_ast.CTypeReference('int')),
            ),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_const_pointer_to_const_pointer_to_const_and_additional_const(
      self
  ):
    source = """
        const int const *const *const p;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='p',
            type_definition=c_ast.CPointer(
                c_ast.CPointer(c_ast.CTypeReference('int')),
            ),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_volatile_variable(self):
    source = """
        volatile int x;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='x',
            type_definition=c_ast.CTypeReference('int'),
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_pointer_as_array(self):
    source = """
        int p[];
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField('p', c_ast.CPointer(c_ast.CTypeReference('int'))),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_pointer_to_pointer_as_arrays(self):
    source = """
        int p[][];
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='p',
            type_definition=c_ast.CPointer(
                c_ast.CPointer(c_ast.CTypeReference('int')),
            ),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_pointer_as_array_to_pointer(self):
    source = """
        int *p[];
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='p',
            type_definition=c_ast.CPointer(
                c_ast.CPointer(c_ast.CTypeReference('int')),
            ),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_pointer_to_function_field(self):
    source = """
        int (*f)();
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='f',
            type_definition=c_ast.CPointerToFunction(),
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_pointer_to_function_with_arguments_field(self):
    source = """
        int (*f)(int a, int b);
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='f',
            type_definition=c_ast.CPointerToFunction(),
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_const_pointer_to_function_with_arguments_field(self):
    source = """
        int (* const f)(int a, int b);
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='f',
            type_definition=c_ast.CPointerToFunction(),
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_pointers_and_simple_fields(self):
    source = """
        int v1;
        type_t v2, *v3, v4[], v5;
        int v6, *v7[], v8;
        """
    actual = self.parser.parse(source)
    type_t = c_ast.CTypeReference('type_t')
    int_ = c_ast.CTypeReference('int')
    pointer_to_type_t = c_ast.CPointer(type_t)
    pointer_to_int = c_ast.CPointer(int_)
    pointer_to_pointer_to_int = c_ast.CPointer(type_definition=pointer_to_int)
    expected = c_ast.CProgram([
        c_ast.CField('v1', int_),
        c_ast.CField('v2', type_t),
        c_ast.CField('v3', pointer_to_type_t),
        c_ast.CField('v4', pointer_to_type_t),
        c_ast.CField('v5', type_t),
        c_ast.CField('v6', int_),
        c_ast.CField('v7', pointer_to_pointer_to_int),
        c_ast.CField('v8', int_),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_array_field(self):
    source = """
        int t[42];
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='t',
            type_definition=c_ast.CArray(
                length=c_ast.CNumber(42),
                type_definition=c_ast.CTypeReference('int'),
            ),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_array_of_arrays(self):
    source = """
        int t[42][33];
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='t',
            type_definition=c_ast.CArray(
                length=c_ast.CNumber(42),
                type_definition=c_ast.CArray(
                    length=c_ast.CNumber(33),
                    type_definition=c_ast.CTypeReference('int'),
                )
            )
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_array_of_pointers(self):
    source = """
        int *t[42];
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='t',
            type_definition=c_ast.CArray(
                length=c_ast.CNumber(42),
                type_definition=c_ast.CPointer(c_ast.CTypeReference('int'))
            )
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_array_of_pointers_as_arrays(self):
    source = """
        int t[42][];
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='t',
            type_definition=c_ast.CArray(
                length=c_ast.CNumber(42),
                type_definition=c_ast.CPointer(c_ast.CTypeReference('int')),
            ),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_array_of_pointers_of_pointers(self):
    source = """
        int **t[42];
        """
    actual = self.parser.parse(source)
    pointer_to_int = c_ast.CPointer(c_ast.CTypeReference('int'))
    pointer_to_pointer_to_int = c_ast.CPointer(pointer_to_int)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='t',
            type_definition=c_ast.CArray(
                length=c_ast.CNumber(42),
                type_definition=pointer_to_pointer_to_int,
            ),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_array_of_pointers_as_arrays_of_pointers(self):
    source = """
        int *t[42][];
        """
    actual = self.parser.parse(source)
    pointer_to_int = c_ast.CPointer(c_ast.CTypeReference('int'))
    pointer_to_pointer_to_int = c_ast.CPointer(pointer_to_int)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='t',
            type_definition=c_ast.CArray(
                length=c_ast.CNumber(42),
                type_definition=pointer_to_pointer_to_int,
            ),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_array_of_pointers_of_pointers_as_arrays(self):
    source = """
        int t[42][][];
        """
    actual = self.parser.parse(source)
    pointer_to_int = c_ast.CPointer(c_ast.CTypeReference('int'))
    pointer_to_pointer_to_int = c_ast.CPointer(pointer_to_int)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='t',
            type_definition=c_ast.CArray(
                length=c_ast.CNumber(42),
                type_definition=pointer_to_pointer_to_int,
            ),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_array_length_as_expression(self):
    source = """
        typedef struct {
          unsigned long fds_bits[1024 / (8 * sizeof(long))];
        } __kernel_fd_set;
        """
    actual = self.parser.parse(source)
    struct = c_ast.CStruct([
        c_ast.CField(
            name='fds_bits',
            type_definition=c_ast.CArray(
                length=c_ast.CFunctionCall(
                    function_name='/',
                    arguments=[
                        c_ast.CNumber(1024),
                        c_ast.CNestedExpression(
                            opener='(',
                            content=c_ast.CFunctionCall(
                                function_name='*',
                                arguments=[
                                    c_ast.CNumber(8),
                                    c_ast.CFunctionCall(
                                        function_name='sizeof',
                                        arguments=[c_ast.CLiteral('long')]
                                    ),
                                ],
                            ),
                            closer=')',
                        ),
                    ],
                ),
                type_definition=c_ast.CTypeReference('unsigned long')
            ),
        ),
    ])
    expected = c_ast.CProgram([
        c_ast.CTypedef(
            name='__kernel_fd_set',
            type_definition=struct,
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_int_bit_field(self):
    source = """
        int v1 : 3;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='v1',
            type_definition=c_ast.CTypeReference('int'),
            bit_size=c_ast.CNumber(3),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_unsigned_bit_field(self):
    source = """
        unsigned v1 : 7;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='v1',
            type_definition=c_ast.CTypeReference('unsigned'),
            bit_size=c_ast.CNumber(7),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_unsigned_int_bit_field(self):
    source = """
        unsigned int v1 : 7;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='v1',
            type_definition=c_ast.CTypeReference('unsigned int'),
            bit_size=c_ast.CNumber(7),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_int_bit_field_with_expression(self):
    source = """
        int x:32 - 2;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='x',
            type_definition=c_ast.CTypeReference('int'),
            bit_size=c_ast.CFunctionCall(
                function_name='-',
                arguments=[
                    c_ast.CNumber(32),
                    c_ast.CNumber(2),
                ],
            ),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_field_with_packed_attribute_for_type(self):
    source = """
        u64 __attribute__((packed)) x;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='x',
            type_definition=c_ast.CTypeReference('u64'),
            attributes=[
                c_ast.CAttribute('packed'),
            ],
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_field_with_aligned_attribute_for_type(self):
    source = """
        u64 __attribute__((aligned(8))) x;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='x',
            type_definition=c_ast.CTypeReference('u64'),
            attributes=[
                c_ast.CAttribute('aligned', c_ast.CNumber(8)),
            ],
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_field_with_packed_and_aligned_attributes_for_type(self):
    source = """
        u64 __attribute__((packed)) __attribute__((aligned(16))) x;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='x',
            type_definition=c_ast.CTypeReference('u64'),
            attributes=[
                c_ast.CAttribute('packed'),
                c_ast.CAttribute('aligned', c_ast.CNumber(16)),
            ],
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_two_fields_with_packed_and_aligned_attributes_for_type(self):
    source = """
        u64 __attribute__((packed)) __attribute__((aligned(16))) x, *y;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='x',
            type_definition=c_ast.CTypeReference('u64'),
            attributes=[
                c_ast.CAttribute('packed'),
                c_ast.CAttribute('aligned', c_ast.CNumber(16)),
            ],
        ),
        c_ast.CField(
            name='y',
            type_definition=c_ast.CPointer(c_ast.CTypeReference('u64')),
            attributes=[
                c_ast.CAttribute('packed'),
                c_ast.CAttribute('aligned', c_ast.CNumber(16)),
            ],
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_one_field_with_packed_attribute(self):
    source = """
        unsigned x __attribute__((packed));
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='x',
            type_definition=c_ast.CTypeReference('unsigned'),
            attributes=[
                c_ast.CAttribute('packed'),
            ],
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_one_field_with_aligned_attribute(self):
    source = """
        unsigned x __attribute__((aligned(32)));
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='x',
            type_definition=c_ast.CTypeReference('unsigned'),
            attributes=[
                c_ast.CAttribute('aligned', c_ast.CNumber(32)),
            ],
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_one_field_with_double_underscored_aligned_attribute(self):
    source = """
        unsigned x __attribute__((__aligned__(32)));
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='x',
            type_definition=c_ast.CTypeReference('unsigned'),
            attributes=[
                c_ast.CAttribute('__aligned__', c_ast.CNumber(32)),
            ],
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_one_field_with_aligned_attribute_with_expression_inside(self):
    source = """
        unsigned x __attribute__((aligned(1 << SHIFT)));
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='x',
            type_definition=c_ast.CTypeReference('unsigned'),
            attributes=[
                c_ast.CAttribute(
                    'aligned',
                    c_ast.CFunctionCall(
                        function_name='<<',
                        arguments=[
                            c_ast.CNumber(1),
                            c_ast.CVariable('SHIFT'),
                        ],
                    ),
                ),
            ],
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_one_field_with_aligned_and_packed_attributes(self):
    source = """
        u16 x __attribute__((aligned(32))) __attribute__((packed));
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='x',
            type_definition=c_ast.CTypeReference('u16'),
            attributes=[
                c_ast.CAttribute('aligned', c_ast.CNumber(32)),
                c_ast.CAttribute('packed'),
            ],
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_one_field_with_two_attributes_in_one_clause(self):
    source = """
        u16 x __attribute__ ((packed, aligned (64)));
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='x',
            type_definition=c_ast.CTypeReference('u16'),
            attributes=[
                c_ast.CAttribute('packed'),
                c_ast.CAttribute('aligned', c_ast.CNumber(64)),
            ],
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_array_of_pointers_as_arrays_of_pointers_with_attributes(self):
    source = """
        u16 *x[8][] __attribute__((aligned(32))) __attribute__((packed));
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='x',
            type_definition=c_ast.CArray(
                length=c_ast.CNumber(8),
                type_definition=c_ast.CPointer(
                    type_definition=c_ast.CPointer(
                        c_ast.CTypeReference('u16'),
                    ),
                )
            ),
            attributes=[
                c_ast.CAttribute('aligned', c_ast.CNumber(32)),
                c_ast.CAttribute('packed'),
            ],
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_two_fields_with_attributes_for_first(self):
    source = """
        u64 *x __attribute__((packed)) __attribute__((aligned(8))), y;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='x',
            type_definition=c_ast.CPointer(c_ast.CTypeReference('u64')),
            attributes=[
                c_ast.CAttribute('packed'),
                c_ast.CAttribute('aligned', c_ast.CNumber(8)),
            ],
        ),
        c_ast.CField(
            name='y',
            type_definition=c_ast.CTypeReference('u64')
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_two_fields_with_attributes_for_second(self):
    source = """
        u64 *x, y __attribute__((aligned(8))) __attribute__((packed));
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='x',
            type_definition=c_ast.CPointer(c_ast.CTypeReference('u64')),
        ),
        c_ast.CField(
            name='y',
            type_definition=c_ast.CTypeReference('u64'),
            attributes=[
                c_ast.CAttribute('aligned', c_ast.CNumber(8)),
                c_ast.CAttribute('packed'),
            ],
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_two_fields_with_different_attributes(self):
    source = """
        u64 x __attribute__((packed)), *y __attribute__((aligned(16)));
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='x',
            type_definition=c_ast.CTypeReference('u64'),
            attributes=[
                c_ast.CAttribute('packed'),
            ],
        ),
        c_ast.CField(
            name='y',
            type_definition=c_ast.CPointer(c_ast.CTypeReference('u64')),
            attributes=[
                c_ast.CAttribute('aligned', c_ast.CNumber(16)),
            ],
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_attribute_for_type_and_for_the_first_field_of_two(self):
    source = """
        u64  __attribute__((aligned(16))) *x __attribute__((packed)), y;
        """
    actual = self.parser.parse(source)
    u64 = c_ast.CTypeReference('u64')
    expected = c_ast.CProgram([
        c_ast.CField(
            name='x',
            type_definition=c_ast.CPointer(u64),
            attributes=[
                c_ast.CAttribute('packed'),
                c_ast.CAttribute('aligned', c_ast.CNumber(16)),
            ],
        ),
        c_ast.CField(
            name='y',
            type_definition=u64,
            attributes=[
                c_ast.CAttribute('aligned', c_ast.CNumber(16)),
            ],
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_attribute_for_type_and_for_the_second_field_of_two(self):
    source = """
        u64  __attribute__((packed)) *x, y __attribute__((aligned(8)));
        """
    actual = self.parser.parse(source)
    u64 = c_ast.CTypeReference('u64')
    expected = c_ast.CProgram([
        c_ast.CField(
            name='x',
            type_definition=c_ast.CPointer(u64),
            attributes=[
                c_ast.CAttribute('packed'),
            ],
        ),
        c_ast.CField(
            name='y',
            type_definition=u64,
            attributes=[
                c_ast.CAttribute('aligned', c_ast.CNumber(8)),
                c_ast.CAttribute('packed'),
            ],
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_field_with_section_attribute(self):
    source = """
        struct s __attribute__ ((__section__(".init.data"))) s1;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='s1',
            type_definition=c_ast.CTypeReference('struct s'),
            attributes=[
                c_ast.CAttribute('__section__', '".init.data"'),
            ],
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_signed_char_field(self):
    source = """
        __signed__ char x;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='x',
            type_definition=c_ast.CTypeReference('__signed__ char'),
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_unsigned_short_field(self):
    source = """
        unsigned short x;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='x',
            type_definition=c_ast.CTypeReference('unsigned short'),
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_unsigned_int_field(self):
    source = """
        unsigned int x;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='x',
            type_definition=c_ast.CTypeReference('unsigned int'),
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_long_long_field(self):
    source = """
        long long x;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='x',
            type_definition=c_ast.CTypeReference('long long'),
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_signed_long_long_field(self):
    source = """
        __signed__ long long x;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='x',
            type_definition=c_ast.CTypeReference('__signed__ long long'),
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_unsigned_long_long_field(self):
    source = """
        unsigned long long x;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='x',
            type_definition=c_ast.CTypeReference('unsigned long long'),
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_unsigned_short_int(self):
    source = """
        unsigned short int x;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='x',
            type_definition=c_ast.CTypeReference('unsigned short int'),
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_signed_long_long_int(self):
    source = """
        signed long long int x;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='x',
            type_definition=c_ast.CTypeReference('signed long long int'),
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_top_level_enum(self):
    source = """
        enum Foo {
          VAL1 = 33,
          VAL2 = 42,
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition('enum Foo', c_ast.CEnum(), []),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_top_level_enum_with_one_attribute(self):
    source = """
        enum Foo {
          VAL1 = 33,
          VAL2 = 42,
        } __attribute__((packed));
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='enum Foo',
            type_definition=c_ast.CEnum(
                attributes=[
                    c_ast.CAttribute('packed'),
                ],
            ),
            following_fields=[],
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_top_level_enum_with_two_attributes(self):
    source = """
        enum Foo {
          VAL1 = 33,
          VAL2 = 42,
        } __attribute__((packed)) __attribute__((aligned(2)));
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='enum Foo',
            type_definition=c_ast.CEnum(
                attributes=[
                    c_ast.CAttribute('packed'),
                    c_ast.CAttribute('aligned', c_ast.CNumber(2)),
                ],
            ),
            following_fields=[],
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_anonymous_top_level_enum(self):
    source = """
        enum {
          VAL1 = 33,
          VAL2 = 42,
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name=None,
            type_definition=c_ast.CEnum(),
            following_fields=[],
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_anonymous_top_level_enum_with_two_attributes(self):
    source = """
        enum {
          VAL1 = 33,
          VAL2 = 42,
        } __attribute__((aligned(4))) __attribute__((packed));
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name=None,
            type_definition=c_ast.CEnum(
                attributes=[
                    c_ast.CAttribute('aligned', c_ast.CNumber(4)),
                    c_ast.CAttribute('packed'),
                ],
            ),
            following_fields=[],
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_top_level_enum_and_variables(self):
    source = """
        enum Foo {
          VAL1 = 33,
          VAL2 = 42,
        } v1, v2, v3;
        """
    actual = self.parser.parse(source)
    enum_foo = c_ast.CEnum()
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='enum Foo',
            type_definition=enum_foo,
            following_fields=[
                c_ast.CField('v1', type_definition=enum_foo),
                c_ast.CField('v2', type_definition=enum_foo),
                c_ast.CField('v3', type_definition=enum_foo),
            ],
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_const_enum_field(self):
    source = """
      const enum e {
      } e1;
      """
    actual = self.parser.parse(source)
    enum_s = c_ast.CEnum()
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='enum e',
            type_definition=enum_s,
            following_fields=[
                c_ast.CField(
                    name='e1',
                    type_definition=enum_s,
                ),
            ],
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_top_level_enum_variables_with_attributes(self):
    source = """
        enum Foo {
          VAL1 = 33,
          VAL2 = 42,
        } __attribute__((aligned(4))) v1, v2, v3 __attribute__((packed));
        """
    actual = self.parser.parse(source)
    anonymous_enum = c_ast.CEnum(
        attributes=[
            c_ast.CAttribute('aligned', c_ast.CNumber(4)),
        ],
    )
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='enum Foo',
            type_definition=anonymous_enum,
            following_fields=[
                c_ast.CField('v1', anonymous_enum),
                c_ast.CField('v2', anonymous_enum),
                c_ast.CField(
                    name='v3',
                    type_definition=anonymous_enum,
                    attributes=[
                        c_ast.CAttribute('packed'),
                    ],
                )
            ],
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_anonymous_top_level_enum_and_variables(self):
    source = """
        enum {
          VAL1 = 33,
          VAL2 = 42,
        } v42, v33;
        """
    actual = self.parser.parse(source)
    anonymous_enum = c_ast.CEnum()
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name=None,
            type_definition=anonymous_enum,
            following_fields=[
                c_ast.CField('v42', anonymous_enum),
                c_ast.CField('v33', anonymous_enum),
            ],
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_anonymous_top_level_enum_variables_with_attributes(self):
    source = """
        enum {
          VAL1 = 33,
          VAL2 = 42,
        } __attribute__((aligned(4))) v1, v2, v3 __attribute__((packed));
        """
    actual = self.parser.parse(source)
    anonymous_enum = c_ast.CEnum(
        attributes=[
            c_ast.CAttribute('aligned', c_ast.CNumber(4)),
        ],
    )
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name=None,
            type_definition=anonymous_enum,
            following_fields=[
                c_ast.CField('v1', anonymous_enum),
                c_ast.CField('v2', anonymous_enum),
                c_ast.CField(
                    name='v3',
                    type_definition=anonymous_enum,
                    attributes=[
                        c_ast.CAttribute('packed'),
                    ],
                )
            ],
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_top_level_enum_and_array(self):
    source = """
        enum Foo {
          VAL1 = 33,
          VAL2 = 42,
        } v1, v2[7], v3;
        """
    actual = self.parser.parse(source)
    enum_foo = c_ast.CEnum()
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='enum Foo',
            type_definition=enum_foo,
            following_fields=[
                c_ast.CField('v1', type_definition=enum_foo),
                c_ast.CField(
                    'v2',
                    type_definition=c_ast.CArray(
                        length=c_ast.CNumber(7),
                        type_definition=enum_foo
                    )),
                c_ast.CField('v3', type_definition=enum_foo),
            ],
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_top_level_enum_variables_array_and_attributes(self):
    source = """
        enum Foo {
          VAL1 = 33,
          VAL2 = 42,
        } __attribute__((aligned(4))) v1, v2[3] __attribute__((packed)), v3;
        """
    actual = self.parser.parse(source)
    enum_foo = c_ast.CEnum(
        attributes=[
            c_ast.CAttribute('aligned', c_ast.CNumber(4)),
        ],
    )
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='enum Foo',
            type_definition=enum_foo,
            following_fields=[
                c_ast.CField('v1', enum_foo),
                c_ast.CField(
                    name='v2',
                    type_definition=c_ast.CArray(
                        length=c_ast.CNumber(3),
                        type_definition=enum_foo,
                    ),
                    attributes=[
                        c_ast.CAttribute('packed'),
                    ],
                ),
                c_ast.CField('v3', enum_foo),
            ],
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_top_level_enum_and_array_of_pointers(self):
    source = """
        enum Foo {
          VAL1 = 33,
          VAL2 = 42,
        } v1, *v2[8], v3;
        """
    actual = self.parser.parse(source)
    enum_foo = c_ast.CEnum()
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='enum Foo',
            type_definition=enum_foo,
            following_fields=[
                c_ast.CField('v1', type_definition=enum_foo),
                c_ast.CField(
                    'v2',
                    type_definition=c_ast.CArray(
                        length=c_ast.CNumber(8),
                        type_definition=c_ast.CPointer(
                            type_definition=enum_foo
                        )
                    )),
                c_ast.CField('v3', type_definition=enum_foo),
            ],
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_top_level_enum_array_of_pointers_and_attributes(self):
    source = """
        enum Foo {
          VAL1 = 33,
          VAL2 = 42,
        } __attribute__((aligned(4))) v1, *v2[3] __attribute__((packed)), v3;
        """
    actual = self.parser.parse(source)
    enum_foo = c_ast.CEnum(
        attributes=[
            c_ast.CAttribute('aligned', c_ast.CNumber(4)),
        ],
    )
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='enum Foo',
            type_definition=enum_foo,
            following_fields=[
                c_ast.CField('v1', enum_foo),
                c_ast.CField(
                    name='v2',
                    type_definition=c_ast.CArray(
                        length=c_ast.CNumber(3),
                        type_definition=c_ast.CPointer(enum_foo),
                    ),
                    attributes=[
                        c_ast.CAttribute('packed'),
                    ],
                ),
                c_ast.CField('v3', enum_foo),
            ],
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_top_level_enum_and_array_of_pointers_as_array(self):
    source = """
        enum Foo {
          VAL1 = 33,
          VAL2 = 42,
        } v1, v2[9][], v3;
        """
    actual = self.parser.parse(source)
    enum_foo = c_ast.CEnum()
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='enum Foo',
            type_definition=enum_foo,
            following_fields=[
                c_ast.CField('v1', type_definition=enum_foo),
                c_ast.CField(
                    'v2',
                    type_definition=c_ast.CArray(
                        length=c_ast.CNumber(9),
                        type_definition=c_ast.CPointer(
                            type_definition=enum_foo
                        )
                    )),
                c_ast.CField('v3', type_definition=enum_foo),
            ],
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_top_level_enum_array_of_array_pointers_and_attributes(self):
    source = """
        enum Foo {
          VAL1 = 33,
          VAL2 = 42,
        } __attribute__((aligned(4))) v1, v2[8][] __attribute__((packed)), v3;
        """
    actual = self.parser.parse(source)
    enum_foo = c_ast.CEnum(
        attributes=[
            c_ast.CAttribute('aligned', c_ast.CNumber(4)),
        ],
    )
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='enum Foo',
            type_definition=enum_foo,
            following_fields=[
                c_ast.CField('v1', enum_foo),
                c_ast.CField(
                    name='v2',
                    type_definition=c_ast.CArray(
                        length=c_ast.CNumber(8),
                        type_definition=c_ast.CPointer(enum_foo),
                    ),
                    attributes=[
                        c_ast.CAttribute('packed'),
                    ],
                ),
                c_ast.CField('v3', enum_foo),
            ],
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_empty_top_level_struct(self):
    source = """
      struct s {
      };
      """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='struct s',
            type_definition=c_ast.CStruct([]),
            following_fields=[],
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_attributed_empty_top_level_struct(self):
    source = """
      struct s {
      } __attribute__((aligned(4)));
      """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='struct s',
            type_definition=c_ast.CStruct(
                content=[],
                attributes=[
                    c_ast.CAttribute('aligned', c_ast.CNumber(4))
                ],
            ),
            following_fields=[],
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_top_level_struct(self):
    source = """
      struct s1 {
        int x;
        type_t y;
      };
      """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='struct s1',
            type_definition=c_ast.CStruct([
                c_ast.CField('x', c_ast.CTypeReference('int')),
                c_ast.CField('y', c_ast.CTypeReference('type_t')),

            ]),
            following_fields=[],
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_top_level_struct_with_attributes(self):
    source = """
      struct s1 {
        int x;
        type_t y;
      } __attribute__((packed)) __attribute__((aligned(2)));
      """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='struct s1',
            type_definition=c_ast.CStruct(
                content=[
                    c_ast.CField('x', c_ast.CTypeReference('int')),
                    c_ast.CField('y', c_ast.CTypeReference('type_t')),
                ],
                attributes=[
                    c_ast.CAttribute('packed'),
                    c_ast.CAttribute('aligned', c_ast.CNumber(2)),
                ],
            ),
            following_fields=[],
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_nested_struct(self):
    source = """
      struct s1 {
        int x;
        struct s2 {
          float *y;
        };
      };
      """
    actual = self.parser.parse(source)
    struct_s2 = c_ast.CStruct([
        c_ast.CField(
            name='y',
            type_definition=c_ast.CPointer(c_ast.CTypeReference('float')),
        )
    ])
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='struct s1',
            type_definition=c_ast.CStruct([
                c_ast.CField('x', c_ast.CTypeReference('int')),
                c_ast.CTypeDefinition(
                    type_name='struct s2',
                    type_definition=struct_s2,
                    following_fields=[]),
            ]),
            following_fields=[],
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_nested_struct_and_attributes(self):
    source = """
      struct s1 {
        int __attribute__((aligned(16))) x;
        struct s2 {
          float *y __attribute__((packed));
        } __attribute__((packed));
      };
      """
    actual = self.parser.parse(source)
    struct_s2 = c_ast.CStruct(
        content=[
            c_ast.CField(
                name='y',
                type_definition=c_ast.CPointer(
                    c_ast.CTypeReference('float'),
                ),
                attributes=[
                    c_ast.CAttribute('packed'),
                ],
            ),
        ],
        attributes=[
            c_ast.CAttribute('packed'),
        ],
    )
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='struct s1',
            type_definition=c_ast.CStruct([
                c_ast.CField(
                    name='x',
                    type_definition=c_ast.CTypeReference('int'),
                    attributes=[
                        c_ast.CAttribute('aligned', c_ast.CNumber(16)),
                    ],
                ),
                c_ast.CTypeDefinition(
                    type_name='struct s2',
                    type_definition=struct_s2,
                    following_fields=[]),
            ]),
            following_fields=[],
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_nested_struct_with_fields(self):
    source = """
      struct s1 {
        int x;
        struct s2 {
          float *y;
        } z;
      };
      """
    actual = self.parser.parse(source)
    struct_s2 = c_ast.CStruct([
        c_ast.CField(
            name='y',
            type_definition=c_ast.CPointer(c_ast.CTypeReference('float')),
        )
    ])
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='struct s1',
            type_definition=c_ast.CStruct([
                c_ast.CField('x', c_ast.CTypeReference('int')),
                c_ast.CTypeDefinition(
                    type_name='struct s2',
                    type_definition=struct_s2,
                    following_fields=[
                        c_ast.CField('z', struct_s2),
                    ],
                )
            ]),
            following_fields=[],
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_const_struct_field(self):
    source = """
      const struct s {
      } s1;
      """
    actual = self.parser.parse(source)
    struct_s = c_ast.CStruct([])
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='struct s',
            type_definition=struct_s,
            following_fields=[
                c_ast.CField(
                    name='s1',
                    type_definition=struct_s,
                ),
            ],
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_nested_struct_with_following_fields_and_attributes(self):
    source = """
      struct s1 {
        int __attribute__((aligned(16))) x;
        struct s2 {
          float *y __attribute__((packed));
        } __attribute__((packed)) z, *v, u[42][] __attribute__((aligned(8)));
      };
      """
    actual = self.parser.parse(source)
    struct_s2 = c_ast.CStruct(
        content=[
            c_ast.CField(
                name='y',
                type_definition=c_ast.CPointer(
                    c_ast.CTypeReference('float'),
                ),
                attributes=[
                    c_ast.CAttribute('packed'),
                ],
            ),
        ],
        attributes=[
            c_ast.CAttribute('packed'),
        ],
    )
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='struct s1',
            type_definition=c_ast.CStruct([
                c_ast.CField(
                    name='x',
                    type_definition=c_ast.CTypeReference('int'),
                    attributes=[
                        c_ast.CAttribute('aligned', c_ast.CNumber(16)),
                    ],
                ),
                c_ast.CTypeDefinition(
                    type_name='struct s2',
                    type_definition=struct_s2,
                    following_fields=[
                        c_ast.CField('z', struct_s2),
                        c_ast.CField('v', c_ast.CPointer(struct_s2)),
                        c_ast.CField(
                            name='u',
                            type_definition=c_ast.CArray(
                                length=c_ast.CNumber(42),
                                type_definition=c_ast.CPointer(struct_s2),
                            ),
                            attributes=[
                                c_ast.CAttribute(
                                    'aligned',
                                    c_ast.CNumber(8),
                                ),
                            ],
                        ),
                    ],
                ),
            ]),
            following_fields=[],
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_struct_with_ifdef_attribute(self):
    source = """
        struct s {}
        //ifdef CONFIG_SOMETHING
          __attribute__((packed))
        //endif
        ;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='struct s',
            type_definition=c_ast.CStruct(
                content=[],
                attributes=[
                    pre_ast.If(
                        conditional_blocks=[
                            pre_ast.ConditionalBlock(
                                conditional_expression=c_ast.CFunctionCall(
                                    function_name='defined',
                                    arguments=[
                                        c_ast.CVariable('CONFIG_SOMETHING'),
                                    ],
                                ),
                                content=[
                                    c_ast.CAttribute('packed')
                                ],
                            ),
                        ],
                    ),
                ],
            ),
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_struct_with_ifndef_attribute(self):
    source = """
        struct s {}
        //ifndef CONFIG_SOMETHING
          __attribute__((aligned(32)))
        //endif
        ;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='struct s',
            type_definition=c_ast.CStruct(
                content=[],
                attributes=[
                    pre_ast.If(
                        conditional_blocks=[
                            pre_ast.ConditionalBlock(
                                conditional_expression=c_ast.CFunctionCall(
                                    function_name='!',
                                    arguments=[
                                        c_ast.CFunctionCall(
                                            function_name='defined',
                                            arguments=[
                                                c_ast.CVariable(
                                                    name='CONFIG_SOMETHING',
                                                ),
                                            ],
                                        ),
                                    ],
                                ),
                                content=[
                                    c_ast.CAttribute(
                                        'aligned',
                                        c_ast.CNumber(32),
                                    )
                                ],
                            ),
                        ],
                    ),
                ],
            ),
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_struct_with_if_attribute(self):
    source = """
        struct s {}
        //if CONFIG_SOMETHING >= 3
          __attribute__((packed))
        //endif
        ;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='struct s',
            type_definition=c_ast.CStruct(
                content=[],
                attributes=[
                    pre_ast.If(
                        conditional_blocks=[
                            pre_ast.ConditionalBlock(
                                conditional_expression=c_ast.CFunctionCall(
                                    function_name='>=',
                                    arguments=[
                                        c_ast.CVariable('CONFIG_SOMETHING'),
                                        c_ast.CNumber(3),
                                    ],
                                ),
                                content=[
                                    c_ast.CAttribute('packed')
                                ],
                            ),
                        ],
                    ),
                ],
            ),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_struct_with_ifdef_elif_and_else_in_attributes(self):
    source = """
        struct s {}
        //ifdef CONFIG_SOMETHING
          __attribute__((packed))
        //elif defined(CONFIG_SOMETHING_ELSE)
          __attribute__((aligned(4)))
        //else
          __attribute__((aligned(8))) __attribute__((packed))
        //endif
        ;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='struct s',
            type_definition=c_ast.CStruct(
                content=[],
                attributes=[
                    pre_ast.If(
                        conditional_blocks=[
                            pre_ast.ConditionalBlock(
                                conditional_expression=c_ast.CFunctionCall(
                                    function_name='defined',
                                    arguments=[
                                        c_ast.CVariable('CONFIG_SOMETHING'),
                                    ],
                                ),
                                content=[
                                    c_ast.CAttribute('packed')
                                ],
                            ),
                            pre_ast.ConditionalBlock(
                                conditional_expression=c_ast.CFunctionCall(
                                    function_name='defined',
                                    arguments=[
                                        c_ast.CVariable(
                                            'CONFIG_SOMETHING_ELSE',
                                        ),
                                    ],
                                ),
                                content=[
                                    c_ast.CAttribute(
                                        'aligned',
                                        c_ast.CNumber(4),
                                    ),
                                ],
                            ),
                        ],
                        else_content=[
                            c_ast.CAttribute('aligned', c_ast.CNumber(8)),
                            c_ast.CAttribute('packed'),
                        ]
                    ),
                ],
            ),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_struct_with_ifndef_elif_and_else_in_attributes(self):
    source = """
        struct s {}
        //ifndef CONFIG_SOMETHING
          __attribute__((packed))
        //elif defined(CONFIG_SOMETHING_ELSE)
          __attribute__((aligned(4)))
        //else
          __attribute__((aligned(8))) __attribute__((packed))
        //endif
        ;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='struct s',
            type_definition=c_ast.CStruct(
                content=[],
                attributes=[
                    pre_ast.If(
                        conditional_blocks=[
                            pre_ast.ConditionalBlock(
                                conditional_expression=c_ast.CFunctionCall(
                                    function_name='!',
                                    arguments=[
                                        c_ast.CFunctionCall(
                                            function_name='defined',
                                            arguments=[
                                                c_ast.CVariable(
                                                    name='CONFIG_SOMETHING',
                                                ),
                                            ],
                                        ),
                                    ],
                                ),
                                content=[
                                    c_ast.CAttribute('packed')
                                ],
                            ),
                            pre_ast.ConditionalBlock(
                                conditional_expression=c_ast.CFunctionCall(
                                    function_name='defined',
                                    arguments=[
                                        c_ast.CVariable(
                                            'CONFIG_SOMETHING_ELSE',
                                        ),
                                    ],
                                ),
                                content=[
                                    c_ast.CAttribute(
                                        'aligned',
                                        c_ast.CNumber(4),
                                    ),
                                ],
                            ),
                        ],
                        else_content=[
                            c_ast.CAttribute('aligned', c_ast.CNumber(8)),
                            c_ast.CAttribute('packed'),
                        ]
                    ),
                ],
            ),
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_struct_with_if_elif_and_else_in_attributes(self):
    source = """
        struct s {}
        //if CONFIG_SOMETHING == 42
          __attribute__((packed))
        //elif defined(CONFIG_SOMETHING_ELSE)
          __attribute__((aligned(4)))
        //else
          __attribute__((aligned(8))) __attribute__((packed))
        //endif
        ;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='struct s',
            type_definition=c_ast.CStruct(
                content=[],
                attributes=[
                    pre_ast.If(
                        conditional_blocks=[
                            pre_ast.ConditionalBlock(
                                conditional_expression=c_ast.CFunctionCall(
                                    function_name='==',
                                    arguments=[
                                        c_ast.CVariable('CONFIG_SOMETHING'),
                                        c_ast.CNumber(42),
                                    ],
                                ),
                                content=[
                                    c_ast.CAttribute('packed')
                                ],
                            ),
                            pre_ast.ConditionalBlock(
                                conditional_expression=c_ast.CFunctionCall(
                                    function_name='defined',
                                    arguments=[
                                        c_ast.CVariable(
                                            'CONFIG_SOMETHING_ELSE',
                                        ),
                                    ],
                                ),
                                content=[
                                    c_ast.CAttribute(
                                        'aligned',
                                        c_ast.CNumber(4),
                                    ),
                                ],
                            ),
                        ],
                        else_content=[
                            c_ast.CAttribute('aligned', c_ast.CNumber(8)),
                            c_ast.CAttribute('packed'),
                        ]
                    ),
                ],
            ),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_simple_typedef_with_attribute_before_type(self):
    source = """
        typedef __attribute__((packed)) struct s struct_s_packed_t;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypedef(
            name='struct_s_packed_t',
            type_definition=c_ast.CTypeReference('struct s'),
            attributes=[
                c_ast.CAttribute('packed'),
            ],
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_simple_typedef_with_attribute_after_type(self):
    source = """
        typedef struct s __attribute__((packed)) struct_s_packed_t;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypedef(
            name='struct_s_packed_t',
            type_definition=c_ast.CTypeReference('struct s'),
            attributes=[
                c_ast.CAttribute('packed'),
            ],
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_simple_typedef_with_attribute_after_name(self):
    source = """
        typedef struct s struct_s_packed_t __attribute__((packed));
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypedef(
            name='struct_s_packed_t',
            type_definition=c_ast.CTypeReference('struct s'),
            attributes=[
                c_ast.CAttribute('packed'),
            ],
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_simple_typedef_with_attribute_in_all_three_places(self):
    source = """
        typedef __attribute__((packed)) struct s __attribute__((packed))
            struct_s_packed_t  __attribute__((packed));
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypedef(
            name='struct_s_packed_t',
            type_definition=c_ast.CTypeReference('struct s'),
            attributes=[
                c_ast.CAttribute('packed'),
                c_ast.CAttribute('packed'),
                c_ast.CAttribute('packed'),
            ],
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_simple_typedef_with_packed_and_aligned_2_attributes(self):
    source = """
      typedef unsigned int unsigned_int_t_packed_aligned_2
        __attribute__((packed)) __attribute__((aligned(2)));
      """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypedef(
            name='unsigned_int_t_packed_aligned_2',
            type_definition=c_ast.CTypeReference('unsigned int'),
            attributes=[
                c_ast.CAttribute('packed'),
                c_ast.CAttribute('aligned', c_ast.CNumber(2)),
            ]
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_simple_typedef_with_aligned_2_and_packed_attributes(self):
    source = """
      typedef unsigned int unsigned_int_t_aligned_2_packed
        __attribute__((aligned(2))) __attribute__((packed));
      """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypedef(
            name='unsigned_int_t_aligned_2_packed',
            type_definition=c_ast.CTypeReference('unsigned int'),
            attributes=[
                c_ast.CAttribute('aligned', c_ast.CNumber(2)),
                c_ast.CAttribute('packed'),
            ]
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_struct_with_pointer_to_function_field(self):
    source = """
        struct s {
          unsigned (*p)(u8 x, u16 y, void *q,
              unsigned long z, unsigned u);
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='struct s',
            type_definition=c_ast.CStruct([
                c_ast.CField(
                    name='p',
                    type_definition=c_ast.CPointerToFunction(),
                ),
            ]),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_struct_with_const_pointer_to_function_field(self):
    source = """
        struct s {
          unsigned (* const p)(u8 x, u16 y, void *q,
              unsigned long z, unsigned u);
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='struct s',
            type_definition=c_ast.CStruct([
                c_ast.CField(
                    name='p',
                    type_definition=c_ast.CPointerToFunction(),
                ),
            ]),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_struct_with_volatile_field(self):
    source = """
        struct s {
          volatile int x;
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='struct s',
            type_definition=c_ast.CStruct([
                c_ast.CField(
                    name='x',
                    type_definition=c_ast.CTypeReference('int'),
                ),
            ]),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_empty_union(self):
    source = """
        union u {};
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='union u',
            type_definition=c_ast.CUnion([]),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_empty_anonymous_union(self):
    source = """
        union {};
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name=None,
            type_definition=c_ast.CUnion([]),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_union_with_fields(self):
    source = """
        union u {
            int a, b;
            union u *p;
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='union u',
            type_definition=c_ast.CUnion([
                c_ast.CField(
                    name='a',
                    type_definition=c_ast.CTypeReference('int'),
                ),
                c_ast.CField(
                    name='b',
                    type_definition=c_ast.CTypeReference('int'),
                ),
                c_ast.CField(
                    name='p',
                    type_definition=c_ast.CPointer(
                        type_definition=c_ast.CTypeReference('union u'),
                    ),
                ),
            ]),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_anonymous_union_with_fields(self):
    source = """
        union {
          struct s s1;
          struct s s2;
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name=None,
            type_definition=c_ast.CUnion([
                c_ast.CField(
                    name='s1',
                    type_definition=c_ast.CTypeReference('struct s'),
                ),
                c_ast.CField(
                    name='s2',
                    type_definition=c_ast.CTypeReference('struct s'),
                ),
            ]),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_union_with_following_fields(self):
    source = """
        union u {
            int a, b;
            union u *p;
        } u1, u2;
        """
    actual = self.parser.parse(source)
    union_u = c_ast.CUnion([
        c_ast.CField(
            name='a',
            type_definition=c_ast.CTypeReference('int'),
        ),
        c_ast.CField(
            name='b',
            type_definition=c_ast.CTypeReference('int'),
        ),
        c_ast.CField(
            name='p',
            type_definition=c_ast.CPointer(
                type_definition=c_ast.CTypeReference('union u'),
            ),
        ),
    ])
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='union u',
            type_definition=union_u,
            following_fields=[
                c_ast.CField(
                    name='u1',
                    type_definition=union_u,
                ),
                c_ast.CField(
                    name='u2',
                    type_definition=union_u,
                ),
            ],
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_anonymous_union_with_following_fields(self):
    source = """
        union {
          struct s s1;
          struct s s2;
        } u1, u2;
        """
    actual = self.parser.parse(source)
    union = c_ast.CUnion([
        c_ast.CField(
            name='s1',
            type_definition=c_ast.CTypeReference('struct s'),
        ),
        c_ast.CField(
            name='s2',
            type_definition=c_ast.CTypeReference('struct s'),
        ),
    ])
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name=None,
            type_definition=union,
            following_fields=[
                c_ast.CField(
                    name='u1',
                    type_definition=union,
                ),
                c_ast.CField(
                    name='u2',
                    type_definition=union,
                ),
            ],
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_const_union_field(self):
    source = """
      const union u {
      } u1;
      """
    actual = self.parser.parse(source)
    union_u = c_ast.CUnion([])
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='union u',
            type_definition=union_u,
            following_fields=[
                c_ast.CField(
                    name='u1',
                    type_definition=union_u,
                ),
            ],
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_nested_union(self):
    source = """
      union u1 {
        int x;
        union u2 {
          float *y;
        };
      };
      """
    actual = self.parser.parse(source)
    union_u2 = c_ast.CUnion([
        c_ast.CField(
            name='y',
            type_definition=c_ast.CPointer(c_ast.CTypeReference('float')),
        )
    ])
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='union u1',
            type_definition=c_ast.CUnion([
                c_ast.CField('x', c_ast.CTypeReference('int')),
                c_ast.CTypeDefinition(
                    type_name='union u2',
                    type_definition=union_u2,
                    following_fields=[]),
            ]),
            following_fields=[],
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_nested_union_and_attributes(self):
    source = """
      union u1 {
        int __attribute__((aligned(16))) x;
        union u2 {
          float *y __attribute__((packed));
        };
      } __attribute__((packed)) u, v __attribute__((aligned(4)));
      """
    actual = self.parser.parse(source)
    union_u2 = c_ast.CUnion([
        c_ast.CField(
            name='y',
            type_definition=c_ast.CPointer(c_ast.CTypeReference('float')),
            attributes=[
                c_ast.CAttribute('packed'),
            ],
        )
    ])
    union_u1 = c_ast.CUnion(
        content=[
            c_ast.CField(
                name='x',
                type_definition=c_ast.CTypeReference('int'),
                attributes=[
                    c_ast.CAttribute('aligned', c_ast.CNumber(16)),
                ],
            ),
            c_ast.CTypeDefinition(
                type_name='union u2',
                type_definition=union_u2,
                following_fields=[],
            ),
        ],
        attributes=[
            c_ast.CAttribute('packed'),
        ],
    )
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='union u1',
            type_definition=union_u1,
            following_fields=[
                c_ast.CField(
                    name='u',
                    type_definition=union_u1,
                ),
                c_ast.CField(
                    name='v',
                    type_definition=union_u1,
                    attributes=[
                        c_ast.CAttribute('aligned', c_ast.CNumber(4)),
                    ],
                ),
            ],
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_nested_union_with_fields(self):
    source = """
      union u1 {
        int x;
        union u2 {
          float *y;
        } z;
      };
      """
    actual = self.parser.parse(source)
    union_u2 = c_ast.CUnion([
        c_ast.CField(
            name='y',
            type_definition=c_ast.CPointer(c_ast.CTypeReference('float')),
        )
    ])
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='union u1',
            type_definition=c_ast.CUnion([
                c_ast.CField('x', c_ast.CTypeReference('int')),
                c_ast.CTypeDefinition(
                    type_name='union u2',
                    type_definition=union_u2,
                    following_fields=[
                        c_ast.CField('z', union_u2),
                    ],
                )
            ]),
            following_fields=[],
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_union_with_pointer_to_function_field(self):
    source = """
        union u {
          unsigned (*p)(u8 x, u16 y, void *q,
              unsigned long z, unsigned u);
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='union u',
            type_definition=c_ast.CUnion([
                c_ast.CField(
                    name='p',
                    type_definition=c_ast.CPointerToFunction(),
                ),
            ]),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_union_with_const_pointer_to_function_field(self):
    source = """
        union u {
          unsigned (* const p)(u8 x, u16 y, void *q,
              unsigned long z, unsigned u);
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='union u',
            type_definition=c_ast.CUnion([
                c_ast.CField(
                    name='p',
                    type_definition=c_ast.CPointerToFunction(),
                ),
            ]),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_union_with_volatile_field(self):
    source = """
        union u {
          volatile int x;
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='union u',
            type_definition=c_ast.CUnion([
                c_ast.CField(
                    name='x',
                    type_definition=c_ast.CTypeReference('int'),
                ),
            ]),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_union_with_typeof_field(self):
    source = """
        union u {
          __typeof__(struct s) s1;
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='union u',
            type_definition=c_ast.CUnion([
                c_ast.CField(
                    name='s1',
                    type_definition=c_ast.CTypeReference(
                        '__typeof__(struct s)',
                    )
                ),
            ]),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_union_with_pointer_to_typeof_field(self):
    source = """
        union u {
          __typeof__(struct s) *s1;
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='union u',
            type_definition=c_ast.CUnion([
                c_ast.CField(
                    name='s1',
                    type_definition=c_ast.CPointer(
                        type_definition=c_ast.CTypeReference(
                            type_name='__typeof__(struct s)',
                        ),
                    ),
                ),
            ]),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_empty_ifdef_block(self):
    source = """
        //ifdef CONFIG_SOMETHING
        //endif
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        pre_ast.If([
            pre_ast.ConditionalBlock(
                conditional_expression=c_ast.CFunctionCall(
                    function_name='defined',
                    arguments=[c_ast.CVariable('CONFIG_SOMETHING')],
                ),
                content=[],
            )
        ])
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_empty_ifndef_block(self):
    source = """
        //ifndef CONFIG_SOMETHING
        //endif
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        pre_ast.If([
            pre_ast.ConditionalBlock(
                conditional_expression=c_ast.CFunctionCall(
                    function_name='!',
                    arguments=[
                        c_ast.CFunctionCall(
                            function_name='defined',
                            arguments=[c_ast.CVariable('CONFIG_SOMETHING')]
                        ),
                    ],
                ),
                content=[],
            )
        ])
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_empty_ifdef_and_else_blocks(self):
    source = """
        //ifdef CONFIG_SOMETHING
        //else
        //endif
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        pre_ast.If(
            conditional_blocks=[
                pre_ast.ConditionalBlock(
                    conditional_expression=c_ast.CFunctionCall(
                        function_name='defined',
                        arguments=[c_ast.CVariable('CONFIG_SOMETHING')],
                    ),
                    content=[],
                )
            ],
            else_content=[],
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_empty_if_elif_and_else_blocks(self):
    source = """
        //if CONFIG_SOMETHING
        //elif defined(CONFIG_SOMETHING_ELSE)
        //else
        //endif
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        pre_ast.If(
            conditional_blocks=[
                pre_ast.ConditionalBlock(
                    conditional_expression=c_ast.CVariable(
                        'CONFIG_SOMETHING',
                    ),
                    content=[],
                ),
                pre_ast.ConditionalBlock(
                    conditional_expression=c_ast.CFunctionCall(
                        function_name='defined',
                        arguments=[c_ast.CVariable('CONFIG_SOMETHING_ELSE')],
                    ),
                    content=[],
                )
            ],
            else_content=[],
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_empty_if_block_and_expression(self):
    source = """
        //if CONFIG_SOMETHING == 32
        //endif
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        pre_ast.If(
            conditional_blocks=[
                pre_ast.ConditionalBlock(
                    conditional_expression=c_ast.CFunctionCall(
                        function_name='==',
                        arguments=[
                            c_ast.CVariable('CONFIG_SOMETHING'),
                            c_ast.CNumber(32),
                        ],
                    ),
                    content=[],
                ),
            ],
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_empty_if_and_elif_blocks_and_expressions(self):
    source = """
        //if CONFIG_SOMETHING == 32
        //elif CONFIG_SOMETHING == 64
        //endif
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        pre_ast.If(
            conditional_blocks=[
                pre_ast.ConditionalBlock(
                    conditional_expression=c_ast.CFunctionCall(
                        function_name='==',
                        arguments=[
                            c_ast.CVariable('CONFIG_SOMETHING'),
                            c_ast.CNumber(32),
                        ],
                    ),
                    content=[],
                ),
                pre_ast.ConditionalBlock(
                    conditional_expression=c_ast.CFunctionCall(
                        function_name='==',
                        arguments=[
                            c_ast.CVariable('CONFIG_SOMETHING'),
                            c_ast.CNumber(64),
                        ],
                    ),
                    content=[],
                )
            ],
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_top_level_ifdef_block(self):
    source = """
        int a;
        //ifdef CONFIG_SOMETHING
        struct s {
          int x;
        } y;
        int z;
        struct s t, u;
        //endif
        int b;
        """
    actual = self.parser.parse(source)
    struct_s = c_ast.CStruct([
        c_ast.CField('x', c_ast.CTypeReference('int')),
    ])
    expected = c_ast.CProgram([
        c_ast.CField('a', c_ast.CTypeReference('int')),
        pre_ast.If([
            pre_ast.ConditionalBlock(
                conditional_expression=c_ast.CFunctionCall(
                    function_name='defined',
                    arguments=[c_ast.CVariable('CONFIG_SOMETHING')],
                ),
                content=[
                    c_ast.CTypeDefinition(
                        'struct s',
                        type_definition=struct_s,
                        following_fields=[
                            c_ast.CField('y', struct_s),
                        ],
                    ),
                    c_ast.CField('z', c_ast.CTypeReference('int')),
                    c_ast.CField('t', c_ast.CTypeReference('struct s')),
                    c_ast.CField('u', c_ast.CTypeReference('struct s')),
                ],
            )
        ]),
        c_ast.CField('b', c_ast.CTypeReference('int')),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_top_level_ifndef_block(self):
    source = """
        int a;
        //ifndef CONFIG_SOMETHING
        struct s {
          int x;
        } y;
        int z;
        struct s t, u;
        //endif
        int b;
        """
    actual = self.parser.parse(source)
    struct_s = c_ast.CStruct([
        c_ast.CField('x', c_ast.CTypeReference('int')),
    ])
    expected = c_ast.CProgram([
        c_ast.CField('a', c_ast.CTypeReference('int')),
        pre_ast.If([
            pre_ast.ConditionalBlock(
                conditional_expression=c_ast.CFunctionCall(
                    function_name='!',
                    arguments=[
                        c_ast.CFunctionCall(
                            function_name='defined',
                            arguments=[c_ast.CVariable('CONFIG_SOMETHING')]
                        ),
                    ],
                ),
                content=[
                    c_ast.CTypeDefinition(
                        'struct s',
                        type_definition=struct_s,
                        following_fields=[
                            c_ast.CField('y', struct_s),
                        ],
                    ),
                    c_ast.CField('z', c_ast.CTypeReference('int')),
                    c_ast.CField('t', c_ast.CTypeReference('struct s')),
                    c_ast.CField('u', c_ast.CTypeReference('struct s')),
                ],
            )
        ]),
        c_ast.CField('b', c_ast.CTypeReference('int')),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_top_level_ifdef_and_else_blocks(self):
    source = """
        int a;
        //ifdef CONFIG_SOMETHING
        struct s {
          int x;
        } y;
        struct s t, u;
        //else
        int z;
        //endif
        int b;
        """
    actual = self.parser.parse(source)
    struct_s = c_ast.CStruct([
        c_ast.CField('x', c_ast.CTypeReference('int')),
    ])
    expected = c_ast.CProgram([
        c_ast.CField('a', c_ast.CTypeReference('int')),
        pre_ast.If(
            conditional_blocks=[
                pre_ast.ConditionalBlock(
                    conditional_expression=c_ast.CFunctionCall(
                        function_name='defined',
                        arguments=[c_ast.CVariable('CONFIG_SOMETHING')],
                    ),
                    content=[
                        c_ast.CTypeDefinition(
                            'struct s',
                            type_definition=struct_s,
                            following_fields=[
                                c_ast.CField('y', struct_s),
                            ],
                        ),
                        c_ast.CField('t', c_ast.CTypeReference('struct s')),
                        c_ast.CField('u', c_ast.CTypeReference('struct s')),
                    ],
                )
            ],
            else_content=[
                c_ast.CField('z', c_ast.CTypeReference('int')),
            ],
        ),
        c_ast.CField('b', c_ast.CTypeReference('int')),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_top_level_if_elif_and_else_blocks(self):
    source = """
        int a;
        //if CONFIG_SOMETHING
        struct s {
          int x;
        } y;
        //elif defined(CONFIG_SOMETHING_ELSE)
        struct s t, u;
        //else
        int z;
        //endif
        int b;
        """
    actual = self.parser.parse(source)
    struct_s = c_ast.CStruct([
        c_ast.CField('x', c_ast.CTypeReference('int')),
    ])
    expected = c_ast.CProgram([
        c_ast.CField('a', c_ast.CTypeReference('int')),
        pre_ast.If(
            conditional_blocks=[
                pre_ast.ConditionalBlock(
                    conditional_expression=c_ast.CVariable(
                        'CONFIG_SOMETHING',
                    ),
                    content=[
                        c_ast.CTypeDefinition(
                            'struct s',
                            type_definition=struct_s,
                            following_fields=[
                                c_ast.CField('y', struct_s),
                            ],
                        ),
                    ],
                ),
                pre_ast.ConditionalBlock(
                    conditional_expression=c_ast.CFunctionCall(
                        function_name='defined',
                        arguments=[c_ast.CVariable('CONFIG_SOMETHING_ELSE')],
                    ),
                    content=[
                        c_ast.CField('t', c_ast.CTypeReference('struct s')),
                        c_ast.CField('u', c_ast.CTypeReference('struct s')),
                    ],
                ),
            ],
            else_content=[
                c_ast.CField('z', c_ast.CTypeReference('int')),
            ],
        ),
        c_ast.CField('b', c_ast.CTypeReference('int')),
    ])
    self.assertEqual(actual, expected)

  def test_parse_ifdef_block_inside_enum(self):
    source = """
        enum e {
          OPTION_ONE = 1
          //ifdef CONFIG_SOMETHING
          OPTION_TWO = 2
          //endif
          OPTION_THREE = 3
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='enum e',
            type_definition=c_ast.CEnum(),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_ifndef_block_inside_enum(self):
    source = """
        enum e {
          OPTION_ONE = 1
          //ifndef CONFIG_SOMETHING
          OPTION_TWO = 2
          //endif
          OPTION_THREE = 3
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='enum e',
            type_definition=c_ast.CEnum(),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_if_block_inside_enum(self):
    source = """
        enum e {
          OPTION_ONE = 1
          //if defined(CONFIG_SOMETHING)
          OPTION_TWO = 2
          //endif
          OPTION_THREE = 3
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='enum e',
            type_definition=c_ast.CEnum(),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_empty_ifdef_block_inside_struct(self):
    source = """
        struct s {
          //ifdef CONFIG_SOMETHING
          //endif
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='struct s',
            type_definition=c_ast.CStruct([
                pre_ast.If(
                    conditional_blocks=[
                        pre_ast.ConditionalBlock(
                            conditional_expression=c_ast.CFunctionCall(
                                function_name='defined',
                                arguments=[
                                    c_ast.CVariable('CONFIG_SOMETHING'),
                                ],
                            ),
                            content=[],
                        ),
                    ],
                ),
            ]),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_ifdef_elif_else_block_inside_struct(self):
    source = """
        struct s {
          int x;
          //ifdef CONFIG_SOMETHING
          int y;
          struct s t[];
          //elif defined CONFIG_SOMETHING_ELSE
          int z;
          //elif !defined(CONFIG_SOMETHING_EVEN_ELSE)
          int t;
          //else
          int u;
          //endif
          struct s s1;
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='struct s',
            type_definition=c_ast.CStruct([
                c_ast.CField(
                    name='x',
                    type_definition=c_ast.CTypeReference('int')
                ),
                pre_ast.If(
                    conditional_blocks=[
                        pre_ast.ConditionalBlock(
                            conditional_expression=c_ast.CFunctionCall(
                                function_name='defined',
                                arguments=[
                                    c_ast.CVariable('CONFIG_SOMETHING'),
                                ],
                            ),
                            content=[
                                c_ast.CField(
                                    name='y',
                                    type_definition=c_ast.CTypeReference(
                                        'int',
                                    ),
                                ),
                                c_ast.CField(
                                    name='t',
                                    type_definition=c_ast.CPointer(
                                        type_definition=c_ast.CTypeReference(
                                            type_name='struct s',
                                        ),
                                    ),
                                ),
                            ],
                        ),
                        pre_ast.ConditionalBlock(
                            conditional_expression=c_ast.CFunctionCall(
                                function_name='defined',
                                arguments=[
                                    c_ast.CVariable('CONFIG_SOMETHING_ELSE')
                                ],
                            ),
                            content=[
                                c_ast.CField(
                                    name='z',
                                    type_definition=c_ast.CTypeReference(
                                        'int',
                                    ),
                                ),
                            ],
                        ),
                        pre_ast.ConditionalBlock(
                            conditional_expression=c_ast.CFunctionCall(
                                function_name='!',
                                arguments=[
                                    c_ast.CFunctionCall(
                                        function_name='defined',
                                        arguments=[
                                            c_ast.CVariable(
                                                'CONFIG_SOMETHING_EVEN_ELSE'
                                            )
                                        ],
                                    ),
                                ],
                            ),
                            content=[
                                c_ast.CField(
                                    name='t',
                                    type_definition=c_ast.CTypeReference(
                                        'int',
                                    ),
                                ),
                            ],
                        ),
                    ],
                    else_content=[
                        c_ast.CField(
                            name='u',
                            type_definition=c_ast.CTypeReference('int'),
                        ),
                    ],
                ),
                c_ast.CField(
                    name='s1',
                    type_definition=c_ast.CTypeReference('struct s')
                )
            ]),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_empty_ifndef_block_inside_struct(self):
    source = """
        struct s {
          //ifndef CONFIG_SOMETHING
          //endif
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='struct s',
            type_definition=c_ast.CStruct([
                pre_ast.If(
                    conditional_blocks=[
                        pre_ast.ConditionalBlock(
                            conditional_expression=c_ast.CFunctionCall(
                                function_name='!',
                                arguments=[
                                    c_ast.CFunctionCall(
                                        function_name='defined',
                                        arguments=[
                                            c_ast.CVariable(
                                                'CONFIG_SOMETHING',
                                            )
                                        ],
                                    ),
                                ],
                            ),
                            content=[],
                        ),
                    ],
                ),
            ]),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_ifndef_elif_else_block_inside_struct(self):
    source = """
        struct s {
          int x;
          //ifndef CONFIG_SOMETHING
          int y;
          struct s t[];
          //elif defined CONFIG_SOMETHING_ELSE
          int z;
          //elif !defined(CONFIG_SOMETHING_EVEN_ELSE)
          int t;
          //else
          int u;
          //endif
          struct s s1;
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='struct s',
            type_definition=c_ast.CStruct([
                c_ast.CField(
                    name='x',
                    type_definition=c_ast.CTypeReference('int')
                ),
                pre_ast.If(
                    conditional_blocks=[
                        pre_ast.ConditionalBlock(
                            conditional_expression=c_ast.CFunctionCall(
                                function_name='!',
                                arguments=[
                                    c_ast.CFunctionCall(
                                        function_name='defined',
                                        arguments=[
                                            c_ast.CVariable(
                                                'CONFIG_SOMETHING',
                                            ),
                                        ],
                                    ),
                                ],
                            ),
                            content=[
                                c_ast.CField(
                                    name='y',
                                    type_definition=c_ast.CTypeReference(
                                        'int',
                                    ),
                                ),
                                c_ast.CField(
                                    name='t',
                                    type_definition=c_ast.CPointer(
                                        type_definition=c_ast.CTypeReference(
                                            type_name='struct s',
                                        ),
                                    ),
                                ),
                            ],
                        ),
                        pre_ast.ConditionalBlock(
                            conditional_expression=c_ast.CFunctionCall(
                                function_name='defined',
                                arguments=[
                                    c_ast.CVariable('CONFIG_SOMETHING_ELSE')
                                ],
                            ),
                            content=[
                                c_ast.CField(
                                    name='z',
                                    type_definition=c_ast.CTypeReference(
                                        'int',
                                    ),
                                ),
                            ],
                        ),
                        pre_ast.ConditionalBlock(
                            conditional_expression=c_ast.CFunctionCall(
                                function_name='!',
                                arguments=[
                                    c_ast.CFunctionCall(
                                        function_name='defined',
                                        arguments=[
                                            c_ast.CVariable(
                                                'CONFIG_SOMETHING_EVEN_ELSE'
                                            )
                                        ],
                                    ),
                                ],
                            ),
                            content=[
                                c_ast.CField(
                                    name='t',
                                    type_definition=c_ast.CTypeReference(
                                        'int',
                                    ),
                                ),
                            ],
                        ),
                    ],
                    else_content=[
                        c_ast.CField(
                            name='u',
                            type_definition=c_ast.CTypeReference('int'),
                        ),
                    ],
                ),
                c_ast.CField(
                    name='s1',
                    type_definition=c_ast.CTypeReference('struct s')
                )
            ]),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_empty_if_block_inside_struct(self):
    source = """
        struct s {
          //if defined CONFIG_SOMETHING
          //endif
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='struct s',
            type_definition=c_ast.CStruct([
                pre_ast.If(
                    conditional_blocks=[
                        pre_ast.ConditionalBlock(
                            conditional_expression=c_ast.CFunctionCall(
                                function_name='defined',
                                arguments=[
                                    c_ast.CVariable('CONFIG_SOMETHING'),
                                ],
                            ),
                            content=[],
                        ),
                    ],
                ),
            ]),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_if_elif_else_block_inside_struct(self):
    source = """
        struct s {
          int x;
          //if defined(CONFIG_SOMETHING)
          int y;
          struct s t[];
          //elif defined CONFIG_SOMETHING_ELSE
          int z;
          //elif !defined(CONFIG_SOMETHING_EVEN_ELSE)
          int t;
          //else
          int u;
          //endif
          struct s s1;
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='struct s',
            type_definition=c_ast.CStruct([
                c_ast.CField(
                    name='x',
                    type_definition=c_ast.CTypeReference('int')
                ),
                pre_ast.If(
                    conditional_blocks=[
                        pre_ast.ConditionalBlock(
                            conditional_expression=c_ast.CFunctionCall(
                                function_name='defined',
                                arguments=[
                                    c_ast.CVariable('CONFIG_SOMETHING'),
                                ],
                            ),
                            content=[
                                c_ast.CField(
                                    name='y',
                                    type_definition=c_ast.CTypeReference(
                                        'int',
                                    ),
                                ),
                                c_ast.CField(
                                    name='t',
                                    type_definition=c_ast.CPointer(
                                        type_definition=c_ast.CTypeReference(
                                            type_name='struct s',
                                        ),
                                    ),
                                ),
                            ],
                        ),
                        pre_ast.ConditionalBlock(
                            conditional_expression=c_ast.CFunctionCall(
                                function_name='defined',
                                arguments=[
                                    c_ast.CVariable('CONFIG_SOMETHING_ELSE')
                                ],
                            ),
                            content=[
                                c_ast.CField(
                                    name='z',
                                    type_definition=c_ast.CTypeReference(
                                        'int',
                                    ),
                                ),
                            ],
                        ),
                        pre_ast.ConditionalBlock(
                            conditional_expression=c_ast.CFunctionCall(
                                function_name='!',
                                arguments=[
                                    c_ast.CFunctionCall(
                                        function_name='defined',
                                        arguments=[
                                            c_ast.CVariable(
                                                'CONFIG_SOMETHING_EVEN_ELSE'
                                            )
                                        ],
                                    ),
                                ],
                            ),
                            content=[
                                c_ast.CField(
                                    name='t',
                                    type_definition=c_ast.CTypeReference(
                                        'int',
                                    ),
                                ),
                            ],
                        ),
                    ],
                    else_content=[
                        c_ast.CField(
                            name='u',
                            type_definition=c_ast.CTypeReference('int'),
                        ),
                    ],
                ),
                c_ast.CField(
                    name='s1',
                    type_definition=c_ast.CTypeReference('struct s')
                )
            ]),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_empty_ifdef_block_inside_union(self):
    source = """
        union u {
          //ifdef CONFIG_SOMETHING
          //endif
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='union u',
            type_definition=c_ast.CUnion([
                pre_ast.If(
                    conditional_blocks=[
                        pre_ast.ConditionalBlock(
                            conditional_expression=c_ast.CFunctionCall(
                                function_name='defined',
                                arguments=[
                                    c_ast.CVariable('CONFIG_SOMETHING'),
                                ],
                            ),
                            content=[],
                        ),
                    ],
                ),
            ]),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_ifdef_elif_else_block_inside_union(self):
    source = """
        union u {
          int x;
          //ifdef CONFIG_SOMETHING
          int y;
          union u t[];
          //elif defined CONFIG_SOMETHING_ELSE
          int z;
          //elif !defined(CONFIG_SOMETHING_EVEN_ELSE)
          int t;
          //else
          int u;
          //endif
          union u u1;
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='union u',
            type_definition=c_ast.CUnion([
                c_ast.CField(
                    name='x',
                    type_definition=c_ast.CTypeReference('int')
                ),
                pre_ast.If(
                    conditional_blocks=[
                        pre_ast.ConditionalBlock(
                            conditional_expression=c_ast.CFunctionCall(
                                function_name='defined',
                                arguments=[
                                    c_ast.CVariable('CONFIG_SOMETHING'),
                                ],
                            ),
                            content=[
                                c_ast.CField(
                                    name='y',
                                    type_definition=c_ast.CTypeReference(
                                        'int',
                                    ),
                                ),
                                c_ast.CField(
                                    name='t',
                                    type_definition=c_ast.CPointer(
                                        type_definition=c_ast.CTypeReference(
                                            type_name='union u',
                                        ),
                                    ),
                                ),
                            ],
                        ),
                        pre_ast.ConditionalBlock(
                            conditional_expression=c_ast.CFunctionCall(
                                function_name='defined',
                                arguments=[
                                    c_ast.CVariable('CONFIG_SOMETHING_ELSE')
                                ],
                            ),
                            content=[
                                c_ast.CField(
                                    name='z',
                                    type_definition=c_ast.CTypeReference(
                                        'int',
                                    ),
                                ),
                            ],
                        ),
                        pre_ast.ConditionalBlock(
                            conditional_expression=c_ast.CFunctionCall(
                                function_name='!',
                                arguments=[
                                    c_ast.CFunctionCall(
                                        function_name='defined',
                                        arguments=[
                                            c_ast.CVariable(
                                                'CONFIG_SOMETHING_EVEN_ELSE'
                                            )
                                        ],
                                    ),
                                ],
                            ),
                            content=[
                                c_ast.CField(
                                    name='t',
                                    type_definition=c_ast.CTypeReference(
                                        'int',
                                    ),
                                ),
                            ],
                        ),
                    ],
                    else_content=[
                        c_ast.CField(
                            name='u',
                            type_definition=c_ast.CTypeReference('int'),
                        ),
                    ],
                ),
                c_ast.CField(
                    name='u1',
                    type_definition=c_ast.CTypeReference('union u')
                )
            ]),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_empty_ifndef_block_inside_union(self):
    source = """
        union u {
          //ifndef CONFIG_SOMETHING
          //endif
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='union u',
            type_definition=c_ast.CUnion([
                pre_ast.If(
                    conditional_blocks=[
                        pre_ast.ConditionalBlock(
                            conditional_expression=c_ast.CFunctionCall(
                                function_name='!',
                                arguments=[
                                    c_ast.CFunctionCall(
                                        function_name='defined',
                                        arguments=[
                                            c_ast.CVariable(
                                                'CONFIG_SOMETHING',
                                            )
                                        ],
                                    ),
                                ],
                            ),
                            content=[],
                        ),
                    ],
                ),
            ]),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_ifndef_elif_else_block_inside_union(self):
    source = """
        union u {
          int x;
          //ifndef CONFIG_SOMETHING
          int y;
          union u t[];
          //elif defined CONFIG_SOMETHING_ELSE
          int z;
          //elif !defined(CONFIG_SOMETHING_EVEN_ELSE)
          int t;
          //else
          int u;
          //endif
          union u u1;
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='union u',
            type_definition=c_ast.CUnion([
                c_ast.CField(
                    name='x',
                    type_definition=c_ast.CTypeReference('int')
                ),
                pre_ast.If(
                    conditional_blocks=[
                        pre_ast.ConditionalBlock(
                            conditional_expression=c_ast.CFunctionCall(
                                function_name='!',
                                arguments=[
                                    c_ast.CFunctionCall(
                                        function_name='defined',
                                        arguments=[
                                            c_ast.CVariable(
                                                'CONFIG_SOMETHING',
                                            ),
                                        ],
                                    ),
                                ],
                            ),
                            content=[
                                c_ast.CField(
                                    name='y',
                                    type_definition=c_ast.CTypeReference(
                                        'int',
                                    ),
                                ),
                                c_ast.CField(
                                    name='t',
                                    type_definition=c_ast.CPointer(
                                        type_definition=c_ast.CTypeReference(
                                            type_name='union u',
                                        ),
                                    ),
                                ),
                            ],
                        ),
                        pre_ast.ConditionalBlock(
                            conditional_expression=c_ast.CFunctionCall(
                                function_name='defined',
                                arguments=[
                                    c_ast.CVariable('CONFIG_SOMETHING_ELSE')
                                ],
                            ),
                            content=[
                                c_ast.CField(
                                    name='z',
                                    type_definition=c_ast.CTypeReference(
                                        'int',
                                    ),
                                ),
                            ],
                        ),
                        pre_ast.ConditionalBlock(
                            conditional_expression=c_ast.CFunctionCall(
                                function_name='!',
                                arguments=[
                                    c_ast.CFunctionCall(
                                        function_name='defined',
                                        arguments=[
                                            c_ast.CVariable(
                                                'CONFIG_SOMETHING_EVEN_ELSE'
                                            )
                                        ],
                                    ),
                                ],
                            ),
                            content=[
                                c_ast.CField(
                                    name='t',
                                    type_definition=c_ast.CTypeReference(
                                        'int',
                                    ),
                                ),
                            ],
                        ),
                    ],
                    else_content=[
                        c_ast.CField(
                            name='u',
                            type_definition=c_ast.CTypeReference('int'),
                        ),
                    ],
                ),
                c_ast.CField(
                    name='u1',
                    type_definition=c_ast.CTypeReference('union u')
                )
            ]),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_empty_if_block_inside_union(self):
    source = """
        union u {
          //if defined CONFIG_SOMETHING
          //endif
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='union u',
            type_definition=c_ast.CUnion([
                pre_ast.If(
                    conditional_blocks=[
                        pre_ast.ConditionalBlock(
                            conditional_expression=c_ast.CFunctionCall(
                                function_name='defined',
                                arguments=[
                                    c_ast.CVariable('CONFIG_SOMETHING'),
                                ],
                            ),
                            content=[],
                        ),
                    ],
                ),
            ]),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_if_elif_else_block_inside_union(self):
    source = """
        union u {
          int x;
          //if defined(CONFIG_SOMETHING)
          int y;
          union u t[];
          //elif defined CONFIG_SOMETHING_ELSE
          int z;
          //elif !defined(CONFIG_SOMETHING_EVEN_ELSE)
          int t;
          //else
          int u;
          //endif
          union u u1;
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='union u',
            type_definition=c_ast.CUnion([
                c_ast.CField(
                    name='x',
                    type_definition=c_ast.CTypeReference('int')
                ),
                pre_ast.If(
                    conditional_blocks=[
                        pre_ast.ConditionalBlock(
                            conditional_expression=c_ast.CFunctionCall(
                                function_name='defined',
                                arguments=[
                                    c_ast.CVariable('CONFIG_SOMETHING'),
                                ],
                            ),
                            content=[
                                c_ast.CField(
                                    name='y',
                                    type_definition=c_ast.CTypeReference(
                                        'int',
                                    ),
                                ),
                                c_ast.CField(
                                    name='t',
                                    type_definition=c_ast.CPointer(
                                        type_definition=c_ast.CTypeReference(
                                            type_name='union u',
                                        ),
                                    ),
                                ),
                            ],
                        ),
                        pre_ast.ConditionalBlock(
                            conditional_expression=c_ast.CFunctionCall(
                                function_name='defined',
                                arguments=[
                                    c_ast.CVariable('CONFIG_SOMETHING_ELSE')
                                ],
                            ),
                            content=[
                                c_ast.CField(
                                    name='z',
                                    type_definition=c_ast.CTypeReference(
                                        'int',
                                    ),
                                ),
                            ],
                        ),
                        pre_ast.ConditionalBlock(
                            conditional_expression=c_ast.CFunctionCall(
                                function_name='!',
                                arguments=[
                                    c_ast.CFunctionCall(
                                        function_name='defined',
                                        arguments=[
                                            c_ast.CVariable(
                                                'CONFIG_SOMETHING_EVEN_ELSE'
                                            )
                                        ],
                                    ),
                                ],
                            ),
                            content=[
                                c_ast.CField(
                                    name='t',
                                    type_definition=c_ast.CTypeReference(
                                        'int',
                                    ),
                                ),
                            ],
                        ),
                    ],
                    else_content=[
                        c_ast.CField(
                            name='u',
                            type_definition=c_ast.CTypeReference('int'),
                        ),
                    ],
                ),
                c_ast.CField(
                    name='u1',
                    type_definition=c_ast.CTypeReference('union u')
                )
            ]),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_structs_and_unions(self):
    source = """
        struct ftrace_branch_data {
         const char *func;
         const char *file;
         unsigned line;
         union {
          struct {
           unsigned long correct;
           unsigned long incorrect;
          };
          struct {
           unsigned long miss;
           unsigned long hit;
          };
          unsigned long miss_hit[2];
         };
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='struct ftrace_branch_data',
            type_definition=c_ast.CStruct([
                c_ast.CField(
                    name='func',
                    type_definition=c_ast.CPointer(
                        type_definition=c_ast.CTypeReference('char'),
                    ),
                ),
                c_ast.CField(
                    name='file',
                    type_definition=c_ast.CPointer(
                        type_definition=c_ast.CTypeReference('char'),
                    ),
                ),
                c_ast.CField(
                    name='line',
                    type_definition=c_ast.CTypeReference('unsigned'),
                ),
                c_ast.CTypeDefinition(
                    type_name=None,
                    type_definition=c_ast.CUnion([
                        c_ast.CTypeDefinition(
                            type_name=None,
                            type_definition=c_ast.CStruct([
                                c_ast.CField(
                                    name='correct',
                                    type_definition=c_ast.CTypeReference(
                                        'unsigned long',
                                    )
                                ),
                                c_ast.CField(
                                    name='incorrect',
                                    type_definition=c_ast.CTypeReference(
                                        'unsigned long',
                                    )
                                ),
                            ]),
                        ),
                        c_ast.CTypeDefinition(
                            type_name=None,
                            type_definition=c_ast.CStruct([
                                c_ast.CField(
                                    name='miss',
                                    type_definition=c_ast.CTypeReference(
                                        'unsigned long',
                                    )
                                ),
                                c_ast.CField(
                                    name='hit',
                                    type_definition=c_ast.CTypeReference(
                                        'unsigned long',
                                    )
                                ),
                            ]),
                        ),
                        c_ast.CField(
                            name='miss_hit',
                            type_definition=c_ast.CArray(
                                length=c_ast.CNumber(2),
                                type_definition=c_ast.CTypeReference(
                                    'unsigned long',
                                ),
                            ),
                        ),
                    ]),
                ),
            ]),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_simple_typedef(self):
    source = """
        typedef int t;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypedef(
            name='t',
            type_definition=c_ast.CTypeReference('int'),
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_typedef_to_pointer_to_struct(self):
    source = """
        typedef struct s *p;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypedef(
            name='p',
            type_definition=c_ast.CPointer(c_ast.CTypeReference('struct s')),
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_typedef_to_struct_array(self):
    source = """
        typedef struct s t[7];
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypedef(
            name='t',
            type_definition=c_ast.CArray(
                length=c_ast.CNumber(7),
                type_definition=c_ast.CTypeReference('struct s'),
            ),
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_typedef_to_pointer_to_function(self):
    source = """
        typedef void (*fun_t)(int);
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypedef(
            name='fun_t',
            type_definition=c_ast.CPointerToFunction(),
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_typedef_to_cosnt_pointer_to_function(self):
    source = """
        typedef void (* const fun_t)(int);
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypedef(
            name='fun_t',
            type_definition=c_ast.CPointerToFunction(),
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_typedef_with_struct_definition(self):
    source = """
        typedef struct s {
          int x;
          struct s *p;
        } s_t;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypedef(
            name='s_t',
            type_definition=c_ast.CTypeDefinition(
                type_name='struct s',
                type_definition=c_ast.CStruct([
                    c_ast.CField('x', c_ast.CTypeReference('int')),
                    c_ast.CField(
                        name='p',
                        type_definition=c_ast.CPointer(
                            c_ast.CTypeReference('struct s'),
                        ),
                    ),
                ])
            )
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_typedef_with_union_definition_and_pointer(self):
    source = """
        typedef union u {} *t;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypedef(
            name='t',
            type_definition=c_ast.CPointer(
                type_definition=c_ast.CTypeDefinition(
                    type_name='union u',
                    type_definition=c_ast.CUnion([]),
                )
            )
        )
    ])
    self.assertEqual(actual, expected)

  def test_typedefs_with_multi_word_numeric_types_and_conditional_blocks(self):
    source = """
        typedef __signed__ char __s8;
        typedef unsigned char __u8;

        typedef __signed__ short __s16;
        typedef unsigned short __u16;

        typedef __signed__ int __s32;
        typedef unsigned int __u32;

        //ifdef __GNUC__
        __extension__ typedef __signed__ long long __s64;
        __extension__ typedef unsigned long long __u64;
        //else
        typedef __signed__ long long __s64;
        typedef unsigned long long __u64;
        //endif

        typedef signed char s8;
        """
    actual = self.parser.parse(source)
    long_long_typedefs = [
        c_ast.CTypedef(
            name='__s64',
            type_definition=c_ast.CTypeReference(
                '__signed__ long long',
            ),
        ),
        c_ast.CTypedef(
            name='__u64',
            type_definition=c_ast.CTypeReference(
                'unsigned long long',
            ),
        ),
    ]
    expected = c_ast.CProgram([
        c_ast.CTypedef(
            name='__s8',
            type_definition=c_ast.CTypeReference('__signed__ char')
        ),
        c_ast.CTypedef(
            name='__u8',
            type_definition=c_ast.CTypeReference('unsigned char')
        ),
        c_ast.CTypedef(
            name='__s16',
            type_definition=c_ast.CTypeReference('__signed__ short')
        ),
        c_ast.CTypedef(
            name='__u16',
            type_definition=c_ast.CTypeReference('unsigned short')
        ),
        c_ast.CTypedef(
            name='__s32',
            type_definition=c_ast.CTypeReference('__signed__ int')
        ),
        c_ast.CTypedef(
            name='__u32',
            type_definition=c_ast.CTypeReference('unsigned int')
        ),
        pre_ast.If(
            conditional_blocks=[
                pre_ast.ConditionalBlock(
                    conditional_expression=c_ast.CFunctionCall(
                        function_name='defined',
                        arguments=[c_ast.CVariable('__GNUC__')],
                    ),
                    content=long_long_typedefs,
                ),
            ],
            else_content=long_long_typedefs,
        ),
        c_ast.CTypedef(
            name='s8',
            type_definition=c_ast.CTypeReference('signed char')
        ),
    ])
    self.assertEqual(actual, expected)

  def test_with_preprocessing_artifact(self):
    source = """
        # 42 "/usr/local/something.c"
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([])
    self.assertEqual(actual, expected)

  def test_with_preprocessing_artifact_with_following_naturals(self):
    source = """
        # 42 "/usr/local/something.h" 33 42
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([])
    self.assertEqual(actual, expected)

  def test_with_preprocessing_artifacts(self):
    source = """
        # 1 "/usr/local/something.c"
        # 1 "<build-in>"
        # 1 "<command-line>"
        # 1 "/usr/include/something_else.h"
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([])
    self.assertEqual(actual, expected)

  def test_parse_preprocessing_artifacts_with_following_numbers(self):
    source = """
        # 1 "/usr/local/something.c"
        # 1 "<build-in>"
        # 1 "<command-line>"
        # 1 "/usr/include/something_else.h" 1 3 4
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([])
    self.assertEqual(actual, expected)

  def test_parse_with_preprocessing_artifacts_and_actual_code(self):
    source = """
        int x: 3, y;
        # 1 "/usr/local/something.c"
        typedef struct s {
          int x;
          struct s *p;
        } s_t;
        struct s s1, s2;
        # 1 "<command-line>"
        # 1 "/usr/include/something_else.h" 1 3 4
        s_t s3, s4;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='x',
            type_definition=c_ast.CTypeReference('int'),
            bit_size=c_ast.CNumber(3),
        ),
        c_ast.CField(
            name='y',
            type_definition=c_ast.CTypeReference('int'),
        ),
        c_ast.CTypedef(
            name='s_t',
            type_definition=c_ast.CTypeDefinition(
                type_name='struct s',
                type_definition=c_ast.CStruct([
                    c_ast.CField('x', c_ast.CTypeReference('int')),
                    c_ast.CField(
                        name='p',
                        type_definition=c_ast.CPointer(
                            c_ast.CTypeReference('struct s'),
                        ),
                    ),
                ]),
            )
        ),
        c_ast.CField(
            name='s1',
            type_definition=c_ast.CTypeReference('struct s'),
        ),
        c_ast.CField(
            name='s2',
            type_definition=c_ast.CTypeReference('struct s'),
        ),
        c_ast.CField(
            name='s3',
            type_definition=c_ast.CTypeReference('s_t'),
        ),
        c_ast.CField(
            name='s4',
            type_definition=c_ast.CTypeReference('s_t'),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_preprocessing_artifacts_in_enum(self):
    source = """
        enum e {
          OPTION_ONE = 1,
        # 42 "something.h"
          OPTION_TWO = 2,
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='enum e',
            type_definition=c_ast.CEnum()
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_preprocessing_artifacts_in_struct(self):
    source = """
        struct s {
          int x;
        # 42 "something.h"
          int y;
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='struct s',
            type_definition=c_ast.CStruct([
                c_ast.CField(
                    name='x',
                    type_definition=c_ast.CTypeReference('int'),
                ),
                c_ast.CField(
                    name='y',
                    type_definition=c_ast.CTypeReference('int'),
                ),
            ]),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_preprocessing_artifacts_in_union(self):
    source = """
        union u {
          int x;
        # 42 "something.h"
          int y;
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='union u',
            type_definition=c_ast.CUnion([
                c_ast.CField(
                    name='x',
                    type_definition=c_ast.CTypeReference('int'),
                ),
                c_ast.CField(
                    name='y',
                    type_definition=c_ast.CTypeReference('int'),
                ),
            ]),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_with_c_style_comment(self):
    source = """
        /* something, something, something */
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([])
    self.assertEqual(actual, expected)

  def test_with_c_style_comments(self):
    source = r"""
        /* something, something *//* something */
        /* something `~!@#$%^&*()-_=+]}[{\|;',./:"<>? */
        /* 42 */
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([])
    self.assertEqual(actual, expected)

  def test_parse_struct_with_c_style_comment(self):
    source = """
        struct {
          /**/
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name=None,
            type_definition=c_ast.CStruct([]),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_c_style_comments_and_actual_code(self):
    source = """
        int x: 3, y;
        /* something1 something2 */
        typedef struct s {
          int x;
          struct s * /*something 3*/ p;
        } s_t;
        struct s s1 /* something 4! */, s2;
        # 1 "<command-line>"
        /* something 5 */
        # 1 "/usr/include/something_else.h" 1 3 4
        s_t s3, s4 /*something6
            something 7
        something 8
        */;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CField(
            name='x',
            type_definition=c_ast.CTypeReference('int'),
            bit_size=c_ast.CNumber(3),
        ),
        c_ast.CField(
            name='y',
            type_definition=c_ast.CTypeReference('int'),
        ),
        c_ast.CTypedef(
            name='s_t',
            type_definition=c_ast.CTypeDefinition(
                type_name='struct s',
                type_definition=c_ast.CStruct([
                    c_ast.CField('x', c_ast.CTypeReference('int')),
                    c_ast.CField(
                        name='p',
                        type_definition=c_ast.CPointer(
                            c_ast.CTypeReference('struct s'),
                        ),
                    ),
                ]),
            )
        ),
        c_ast.CField(
            name='s1',
            type_definition=c_ast.CTypeReference('struct s'),
        ),
        c_ast.CField(
            name='s2',
            type_definition=c_ast.CTypeReference('struct s'),
        ),
        c_ast.CField(
            name='s3',
            type_definition=c_ast.CTypeReference('s_t'),
        ),
        c_ast.CField(
            name='s4',
            type_definition=c_ast.CTypeReference('s_t'),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_with_function_declaration(self):
    source = """
        void some_function(struct s *s1, int x, int y);
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([])
    self.assertEqual(actual, expected)

  def test_parse_function_declaration_attributed_with_noreturn(self):
    source = """
        void some_function(struct s *s1, int x, int y)
          __attribute__((noreturn));
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([])
    self.assertEqual(actual, expected)

  def test_parse_function_declaration_attributed_with_format(self):
    source = """
        void some_function(struct s *s1, int x, int y)
          __attribute__((format(printf, 1, 6)));
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([])
    self.assertEqual(actual, expected)

  def test_parse_function_declaration_attributed_before_function_name(self):
    source = """
        extern struct clocksource *
        __attribute__ ((__section__(".init.text")))
        __attribute__((no_instrument_function))
        clocksource_default_clock(void);
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([])
    self.assertEqual(actual, expected)

  def test_parse_typedef_with_function_declaration(self):
    source = """
        typedef int wait_bit_action_f(struct wait_bit_key *);
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([])
    self.assertEqual(actual, expected)

  def test_parse_typedef_with_function_declaration_in_parentheses(self):
    source = """
        typedef
        int (pcpu_fc_cpu_distance_fn_t)(unsigned int from, unsigned int to);
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([])
    self.assertEqual(actual, expected)

  def test_parse_with_function_definition(self):
    source = """
        union u some_other_function(int x, union u u2) {
          for (int i = 0; i < 10; ++i) {
            u2.x += i;
          }
          return u2
        }
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([])
    self.assertEqual(actual, expected)

  def test_parse_with_function_returning_a_pointer_declaration(self):
    source = """
        void *some_function(struct s *s1, int x, int y);
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([])
    self.assertEqual(actual, expected)

  def test_parse_with_function_returning_a_pointer_definition(self):
    source = """
        union u **some_other_function(int x, union u u2) {
          for (int i = 0; i < 10; ++i) {
            u2.x += i;
          }
          return 0;
        }
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([])
    self.assertEqual(actual, expected)

  def test_parse_with_enum_declaration_without_definition(self):
    source = """
        enum kobj_ns_type;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([])
    self.assertEqual(actual, expected)

  def test_parse_with_struct_declaration_without_definition(self):
    source = """
        struct mm_struct;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([])
    self.assertEqual(actual, expected)

  def test_parse_with_union_declaration_without_definition(self):
    source = """
        union u;
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([])
    self.assertEqual(actual, expected)

  def test_parse_malformed_function_definition(self):
    source = """
        static inline __attribute__((no_instrument_function))
            pmd_t ((pmd_t) { ((pud_t) { __pgd(pmdval_t val) } ) } )
        {
          /* (...) */
          static struct ftrace_branch_data __attribute__((__aligned__(4)))
            __attribute__((section("_ftrace_branch"))) ______f = {
              .func = __func__,
              .file = "tmp.h",
              .line = 512,
            };
          /* (...) */
          return (pmd_t) { ret };
        }
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([])
    self.assertEqual(actual, expected)

  def test_parse_malformed_function_definition_with_additional_parentheses(
      self,
  ):
    source = """
        static inline __attribute__((no_instrument_function)) cputime_t
          ( cputime_t)((timespec_to_jiffies(const struct timespec *val))
             * (1000000000L / CONFIG_HZ))
        {
         u64 ret = val->tv_sec * 1000000000L + val->tv_nsec;
         return ( cputime_t) ret;
        }
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([])
    self.assertEqual(actual, expected)

  def test_parse_do_while_block_artifact(self):
    source = """
        extern void do {
          static struct _ddebug descriptor = { .modname = KBUILD_MODNAME };
        } while (0);
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([])
    self.assertEqual(actual, expected)

  def test_parse_do_while_block_artifact_without_semicolon(self):
    source = """
        extern void do {
          static struct _ddebug descriptor = { .modname = KBUILD_MODNAME };
        } while (0)
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([])
    self.assertEqual(actual, expected)

  def test_parse_unended_enum_keyword(self):
    source = """
      enum
      """
    with self.assertRaises(pyparsing.ParseException):
      self.parser.parse(source)

  def test_parse_enum_declaration_without_semicolon(self):
    source = """
      enum e
      """
    with self.assertRaises(pyparsing.ParseException):
      self.parser.parse(source)

  def test_parse_unended_enum_definition(self):
    source = """
      enum e {
      """
    with self.assertRaises(pyparsing.ParseException):
      self.parser.parse(source)

  def test_parse_empty_enum_definition_without_semicolon(self):
    source = """
      enum e {}
      """
    with self.assertRaises(pyparsing.ParseException):
      self.parser.parse(source)

  def test_parse_unended_enum_definition_with_content(self):
    source = """
      enum e {
        OPTION_ONE,
      """
    with self.assertRaises(pyparsing.ParseException):
      self.parser.parse(source)

  def test_parse_enum_definition_without_semicolon(self):
    source = """
      enum e {
        OPTION_ONE,
      }
      """
    with self.assertRaises(pyparsing.ParseException):
      self.parser.parse(source)

  def test_parse_unended_struct_keyword(self):
    source = """
      struct
      """
    with self.assertRaises(pyparsing.ParseException):
      self.parser.parse(source)

  def test_parse_struct_declaration_without_semicolon(self):
    source = """
      struct s
      """
    with self.assertRaises(pyparsing.ParseException):
      self.parser.parse(source)

  def test_parse_unended_struct_definition(self):
    source = """
      struct s {
      """
    with self.assertRaises(pyparsing.ParseException):
      self.parser.parse(source)

  def test_parse_empty_struct_definition_without_semicolon(self):
    source = """
      struct s {}
      """
    with self.assertRaises(pyparsing.ParseException):
      self.parser.parse(source)

  def test_parse_unended_struct_definition_with_field(self):
    source = """
      struct s {
        int x;
      """
    with self.assertRaises(pyparsing.ParseException):
      self.parser.parse(source)

  def test_parse_struct_definition_without_semicolon(self):
    source = """
      struct s {
        int x;
      }
      """
    with self.assertRaises(pyparsing.ParseException):
      self.parser.parse(source)

  def test_parse_unended_union_keyword(self):
    source = """
      union
      """
    with self.assertRaises(pyparsing.ParseException):
      self.parser.parse(source)

  def test_parse_union_declaration_without_semicolon(self):
    source = """
      union u
      """
    with self.assertRaises(pyparsing.ParseException):
      self.parser.parse(source)

  def test_parse_unended_union_definition(self):
    source = """
      union u {
      """
    with self.assertRaises(pyparsing.ParseException):
      self.parser.parse(source)

  def test_parse_empty_union_definition_without_semicolon(self):
    source = """
      union u {}
      """
    with self.assertRaises(pyparsing.ParseException):
      self.parser.parse(source)

  def test_parse_unended_union_definition_with_field(self):
    source = """
      union u {
        int x;
      """
    with self.assertRaises(pyparsing.ParseException):
      self.parser.parse(source)

  def test_parse_union_definition_without_semicolon(self):
    source = """
      union u {
        int x;
      }
      """
    with self.assertRaises(pyparsing.ParseException):
      self.parser.parse(source)

  def test_parse_struct_with_only_semicolon_inside(self):
    source = """
        struct {;};
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name=None,
            type_definition=c_ast.CStruct([]),
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_struct_with_superfluous_semicolon_after_a_field(self):
    source = """
        struct s {
          int x;;
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='struct s',
            type_definition=c_ast.CStruct([
                c_ast.CField(
                    name='x',
                    type_definition=c_ast.CTypeReference('int'),
                ),
            ]),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_union_with_only_semicolon_inside(self):
    source = """
        union {;};
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name=None,
            type_definition=c_ast.CUnion([]),
        )
    ])
    self.assertEqual(actual, expected)

  def test_parse_union_with_superfluous_semicolon_after_a_field(self):
    source = """
        union u {
          int x;;
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='union u',
            type_definition=c_ast.CUnion([
                c_ast.CField(
                    name='x',
                    type_definition=c_ast.CTypeReference('int'),
                ),
            ]),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_struct_with_sa_handler_field(self):
    source = """
        struct sigaction {
          __sighandler_t _u._sa_handler;
        };
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypeDefinition(
            type_name='struct sigaction',
            type_definition=c_ast.CStruct([
                c_ast.CField(
                    name='_u._sa_handler',
                    type_definition=c_ast.CTypeReference('__sighandler_t'),
                ),
            ]),
        ),
    ])
    self.assertEqual(actual, expected)

  def test_parse_attributed_with_format_typedef_to_pointer_to_function(self):
    source = """
        typedef __attribute__((format(printf, 1, 0)))
          int (*printk_func_t)(const char *fmt, va_list args);
        """
    actual = self.parser.parse(source)
    expected = c_ast.CProgram([
        c_ast.CTypedef(
            name='printk_func_t',
            type_definition=c_ast.CPointerToFunction(),
            attributes=[c_ast.CAttribute('format', 'printf', 1, 0)],
        )
    ])
    self.assertEqual(actual, expected)

  def assertEqual(self, actual, expected):
    message = '\n%s\n!=\n%s' % (actual, expected)
    super(TestParser, self).assertEqual(actual, expected, message)


if __name__ == '__main__':
  unittest.main()
