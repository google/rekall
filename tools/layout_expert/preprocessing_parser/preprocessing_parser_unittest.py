from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest



from rekall.layout_expert.c_ast import c_ast
from rekall.layout_expert.c_ast import pre_ast
from rekall.layout_expert.preprocessing_parser import preprocessing_parser


class TestPreprocessingParser(unittest.TestCase):

  def setUp(self):
    self.parser = preprocessing_parser.PreprocessingParser()

  def test_creation(self):
    self.assertIsNotNone(self.parser)

  def test_parse_empty_program(self):
    source = ''
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([]),
    )
    self.assertEqual(actual, expected)

  def test_parse_c_style_comment(self):
    source = '/* Foo 42. */'
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([]),
    )
    self.assertEqual(actual, expected)

  def test_parse_cpp_style_comment(self):
    source = '// Bar 33.'
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([]),
    )
    self.assertEqual(actual, expected)

  def test_parse_cpp_style_inside_text_block(self):
    source = '\n'.join([
        'foo // bar',
        'baz'
    ])
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.TextBlock('foo \nbaz'),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_include_with_angle_brackets(self):
    source = '# include <some/path/to/file_1.h>'
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.Include(
                path='some/path/to/file_1.h',
                quotes_type=pre_ast.Include.QuotesType.ANGLE_BRACKETS,
            )
        ])
    )
    self.assertEqual(actual, expected)

  def test_parse_include_with_double_quotes(self):
    source = '#include "some/path/to/file_2.h"'
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.Include(
                path='some/path/to/file_2.h',
                quotes_type=pre_ast.Include.QuotesType.DOUBLE_QUOTES,
            )
        ])
    )
    self.assertEqual(actual, expected)

  def test_parse_pragma(self):
    source = '#pragma foo'
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.Pragma([
                pre_ast.PragmaArgument('foo'),
            ])
        ])
    )
    self.assertEqual(actual, expected)

  def test_parse_pragma_with_string_argument(self):
    source = '#pragma "-foo"'
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.Pragma([
                pre_ast.PragmaArgument('"-foo"'),
            ])
        ])
    )
    self.assertEqual(actual, expected)

  def test_parse_pragma_with_three_simple_arguments(self):
    source = '#pragma foo bar baz'
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.Pragma([
                pre_ast.PragmaArgument('foo'),
                pre_ast.PragmaArgument('bar'),
                pre_ast.PragmaArgument('baz'),
            ]),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_pragma_with_argument_with_empty_arguments_list(self):
    source = '#pragma foo()'
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.Pragma([
                pre_ast.PragmaArgument(
                    name='foo',
                    arguments=[],
                ),
            ]),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_pragma_with_argument_with_arguments(self):
    source = '#pragma foo(bar, baz)'
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.Pragma([
                pre_ast.PragmaArgument(
                    name='foo',
                    arguments=[
                        c_ast.CVariable('bar'),
                        c_ast.CVariable('baz'),
                    ],
                ),
            ]),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_pragma_with_argument_with_natural_number_argument(self):
    source = '#pragma foo(42)'
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.Pragma([
                pre_ast.PragmaArgument(
                    name='foo',
                    arguments=[
                        c_ast.CNumber(42),
                    ],
                ),
            ]),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_pragma_with_argument_with_value_assigned(self):
    source = '#pragma foo=bar'
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.Pragma([
                pre_ast.PragmaArgument(
                    name='foo',
                    value=c_ast.CVariable('bar'),
                ),
            ]),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_text_block(self):
    source = 'int x;'
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.TextBlock('int x;'),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_pragma_and_text_block(self):
    source = '\n'.join((
        '#pragma foo bar',
        'int x;',
    ))
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.Pragma([
                pre_ast.PragmaArgument('foo'),
                pre_ast.PragmaArgument('bar'),
            ]),
            pre_ast.TextBlock('int x;'),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_error(self):
    source = '#error foo bar 42 baz'
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.Error('foo bar 42 baz'),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_define_empty_object_like(self):
    source = '#define foo'
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.DefineObjectLike(
                name='foo',
                replacement=None,
                string_replacement='',
            ),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_define_object_like(self):
    source = '#define foo bar'
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.DefineObjectLike(
                name='foo',
                replacement=c_ast.CVariable('bar'),
                string_replacement=' bar',
            ),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_define_object_like_as_numeric_constant(self):
    source = '#define foo 42'
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.DefineObjectLike(
                name='foo',
                replacement=c_ast.CNumber(42),
                string_replacement=' 42',
            ),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_define_object_with_two_expressions(self):
    source = '#define foo bar baz'
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.DefineObjectLike(
                name='foo',
                replacement=pre_ast.CompositeBlock([
                    c_ast.CVariable('bar'),
                    c_ast.CVariable('baz'),
                ]),
                string_replacement=' bar baz',
            ),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_define_object_with_string_concatenation(self):
    source = '#define foo bar ## baz'
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.DefineObjectLike(
                name='foo',
                replacement=c_ast.CFunctionCall(
                    function_name='##',
                    arguments=[
                        c_ast.CVariable('bar'),
                        c_ast.CVariable('baz'),
                    ],
                ),
                string_replacement=' bar ## baz',
            ),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_define_object_with_multiple_expressions_and_concatenation(
      self,
  ):
    source = '#define foo x y ## u v'
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.DefineObjectLike(
                name='foo',
                replacement=pre_ast.CompositeBlock([
                    c_ast.CVariable('x'),
                    c_ast.CFunctionCall(
                        function_name='##',
                        arguments=[
                            c_ast.CVariable('y'),
                            c_ast.CVariable('u'),
                        ],
                    ),
                    c_ast.CVariable('v')
                ]),
                string_replacement=' x y ## u v',
            ),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_define_object_with_statement_concatenation(
      self,
  ):
    source = '#define foo bar ## baz;'
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.DefineObjectLike(
                name='foo',
                replacement=pre_ast.CompositeBlock([
                    c_ast.CFunctionCall(
                        function_name='##',
                        arguments=[
                            c_ast.CVariable('bar'),
                            c_ast.CVariable('baz'),
                        ],
                    ),
                    c_ast.CLiteral(';'),
                ]),
                string_replacement=' bar ## baz;',
            ),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_define_with_multiple_expression_and_statement_concatenation(
      self,
  ):
    source = '#define x foo bar ## baz;'
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.DefineObjectLike(
                name='x',
                replacement=pre_ast.CompositeBlock([
                    c_ast.CVariable('foo'),
                    c_ast.CFunctionCall(
                        function_name='##',
                        arguments=[
                            c_ast.CVariable('bar'),
                            c_ast.CVariable('baz'),
                        ],
                    ),
                    c_ast.CLiteral(';'),
                ]),
                string_replacement=' foo bar ## baz;',
            ),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_define_object_like_as_numeric_constant_with_comment(self):
    source = '#define foo 42 /* bar */'
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.DefineObjectLike(
                name='foo',
                replacement=c_ast.CNumber(42),
                string_replacement=' 42 ',
            ),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_define_object_like_as_numeric_constant_with_multiline_comment(
      self,
  ):
    source = """
        #define foo 42 /* bar
                baz */
        """
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.DefineObjectLike(
                name='foo',
                replacement=c_ast.CNumber(42),
                string_replacement=' 42 ',
            ),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_define_object_like_with_parentheses_expression(self):
    source = '#define foo (bar)'
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.DefineObjectLike(
                name='foo',
                replacement=c_ast.CNestedExpression(
                    opener='(',
                    content=c_ast.CVariable('bar'),
                    closer=')',
                ),
                string_replacement=' (bar)',
            ),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_define_string(self):
    source = '#define foo "bar"'
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.DefineObjectLike(
                name='foo',
                replacement=c_ast.CLiteral('"bar"'),
                string_replacement=' "bar"',
            ),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_define_object_like_as_function_call(self):
    source = '#define foo bar(x)'
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.DefineObjectLike(
                name='foo',
                replacement=c_ast.CFunctionCall(
                    function_name='bar',
                    arguments=[
                        c_ast.CVariable('x'),
                    ],
                ),
                string_replacement=' bar(x)',
            ),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_define_object_like_as_attribute(self):
    source = '#define foo __attribute__((packed))'
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.DefineObjectLike(
                name='foo',
                replacement=c_ast.CFunctionCall(
                    function_name='__attribute__',
                    arguments=[
                        c_ast.CNestedExpression(
                            opener='(',
                            content=c_ast.CVariable('packed'),
                            closer=')',
                        ),
                    ],
                ),
                string_replacement=' __attribute__((packed))',
            ),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_define_funcion_like_without_arguments(self):
    source = '#define foo() bar'
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.DefineFunctionLike(
                name='foo',
                arguments=[],
                replacement=c_ast.CVariable('bar'),
                string_replacement=' bar',
            ),
        ])
    )
    self.assertEqual(actual, expected)

  def test_parse_define_empty_funcion_like(self):
    source = '#define foo()'
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.DefineFunctionLike(
                name='foo',
                arguments=[],
                replacement=None,
                string_replacement='',
            ),
        ])
    )
    self.assertEqual(actual, expected)

  def test_parse_define_function_like_with_multiple_expressions(self):
    source = '#define foo() bar baz'
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.DefineFunctionLike(
                name='foo',
                arguments=[],
                replacement=pre_ast.CompositeBlock([
                    c_ast.CVariable('bar'),
                    c_ast.CVariable('baz'),
                ]),
                string_replacement=' bar baz',
            ),
        ])
    )
    self.assertEqual(actual, expected)

  def test_parse_define_statement_as_functional_like(self):
    source = '#define module_init(x)  __initcall(x);'
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.DefineFunctionLike(
                name='module_init',
                arguments=['x'],
                replacement=pre_ast.CompositeBlock([
                    c_ast.CFunctionCall(
                        function_name='__initcall',
                        arguments=[c_ast.CVariable('x')],
                    ),
                    c_ast.CLiteral(';'),
                ]),
                string_replacement='  __initcall(x);',
            )
        ])
    )
    self.assertEqual(actual, expected)

  def test_parse_multiline_define(self):
    source = '\n'.join([
        '#define foo bar\\',
        '    baz',
        '    42',
    ])
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.DefineObjectLike(
                name='foo',
                replacement=pre_ast.CompositeBlock([
                    c_ast.CVariable('bar'),
                    c_ast.CVariable('baz'),
                ]),
                string_replacement=' bar    baz',
            ),
            pre_ast.TextBlock('\n    42'),
        ])
    )
    self.assertEqual(actual, expected)

  def test_parse_undef(self):
    source = '#undef foo'
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.Undef('foo'),
        ])
    )
    self.assertEqual(actual, expected)

  def test_parse_with_empty_ifdef_block(self):
    source = """
        #ifdef CONFIG_SOMETHING
        #endif
        """
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        pre_ast.CompositeBlock([
            pre_ast.If([
                pre_ast.ConditionalBlock(
                    conditional_expression=c_ast.CFunctionCall(
                        function_name='defined',
                        arguments=[c_ast.CVariable('CONFIG_SOMETHING')],
                    ),
                    content=pre_ast.CompositeBlock([]),
                ),
            ]),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_with_empty_ifndef_block(self):
    source = """
        #ifndef CONFIG_SOMETHING
        #endif
        """
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        pre_ast.CompositeBlock([
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
                    content=pre_ast.CompositeBlock([]),
                ),
            ]),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_with_empty_ifndef_block_and_endif_with_comment(self):
    source = """
        #ifndef _SOMETHING_H
        #endif /* _SOMETHING_H */
        """
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        pre_ast.CompositeBlock([
            pre_ast.If([
                pre_ast.ConditionalBlock(
                    conditional_expression=c_ast.CFunctionCall(
                        function_name='!',
                        arguments=[
                            c_ast.CFunctionCall(
                                function_name='defined',
                                arguments=[c_ast.CVariable('_SOMETHING_H')]
                            ),
                        ],
                    ),
                    content=pre_ast.CompositeBlock([]),
                ),
            ]),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_with_empty_ifndef_header_guard(self):
    source = """
        #ifndef _SOMETHING_H
        #define _SOMETHING_H
        #endif
        """
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        pre_ast.CompositeBlock([
            pre_ast.If([
                pre_ast.ConditionalBlock(
                    conditional_expression=c_ast.CFunctionCall(
                        function_name='!',
                        arguments=[
                            c_ast.CFunctionCall(
                                function_name='defined',
                                arguments=[c_ast.CVariable('_SOMETHING_H')]
                            ),
                        ],
                    ),
                    content=pre_ast.CompositeBlock([
                        pre_ast.DefineObjectLike(
                            name='_SOMETHING_H',
                            replacement=None,
                            string_replacement='',
                        ),
                    ]),
                ),
            ]),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_with_empty_ifdef_and_else_blocks(self):
    source = """
        #ifdef CONFIG_SOMETHING
        #else
        #endif
        """
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        pre_ast.CompositeBlock([
            pre_ast.If(
                conditional_blocks=[
                    pre_ast.ConditionalBlock(
                        conditional_expression=c_ast.CFunctionCall(
                            function_name='defined',
                            arguments=[c_ast.CVariable('CONFIG_SOMETHING')],
                        ),
                        content=pre_ast.CompositeBlock([]),
                    )
                ],
                else_content=pre_ast.CompositeBlock([]),
            ),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_with_empty_if_elif_and_else_blocks(self):
    source = """
        #if CONFIG_SOMETHING
        #elif defined(CONFIG_SOMETHING_ELSE)
        #else
        #endif
        """
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        pre_ast.CompositeBlock([
            pre_ast.If(
                conditional_blocks=[
                    pre_ast.ConditionalBlock(
                        conditional_expression=c_ast.CVariable(
                            name='CONFIG_SOMETHING',
                        ),
                        content=pre_ast.CompositeBlock([]),
                    ),
                    pre_ast.ConditionalBlock(
                        conditional_expression=c_ast.CFunctionCall(
                            function_name='defined',
                            arguments=[
                                c_ast.CVariable('CONFIG_SOMETHING_ELSE'),
                            ],
                        ),
                        content=pre_ast.CompositeBlock([]),
                    )
                ],
                else_content=pre_ast.CompositeBlock([]),
            ),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_with_empty_if_block_and_expression(self):
    source = """
        #if CONFIG_SOMETHING == 32
        #endif
        """
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
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
                        content=pre_ast.CompositeBlock([]),
                    ),
                ],
            ),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_if_with_comments(self):
    source = """
        #if 0 /* foo bar */
        /* 42 */
        #endif
        """
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.If(
                conditional_blocks=[
                    pre_ast.ConditionalBlock(
                        conditional_expression=c_ast.CNumber(0),
                        content=pre_ast.CompositeBlock([]),
                    ),
                ],
            ),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_with_empty_if_and_elif_blocks_and_expressions(self):
    source = """
        #if CONFIG_SOMETHING == 32
        #elif CONFIG_SOMETHING == 64
        #endif
        """
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        pre_ast.CompositeBlock([
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
                        content=pre_ast.CompositeBlock([]),
                    ),
                    pre_ast.ConditionalBlock(
                        conditional_expression=c_ast.CFunctionCall(
                            function_name='==',
                            arguments=[
                                c_ast.CVariable('CONFIG_SOMETHING'),
                                c_ast.CNumber(64),
                            ],
                        ),
                        content=pre_ast.CompositeBlock([]),
                    ),
                ],
            ),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_with_top_level_ifdef_block(self):
    source = '\n'.join((
        'int a;',
        '#ifdef CONFIG_SOMETHING',
        'struct s {',
        '  int x;',
        '} y;',
        'int z;',
        'struct s t, u;',
        '#endif',
        'int b;',
    ))
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        pre_ast.CompositeBlock([
            pre_ast.TextBlock('int a;'),
            pre_ast.If([
                pre_ast.ConditionalBlock(
                    conditional_expression=c_ast.CFunctionCall(
                        function_name='defined',
                        arguments=[c_ast.CVariable('CONFIG_SOMETHING')],
                    ),
                    content=pre_ast.CompositeBlock([
                        pre_ast.TextBlock(
                            '\n'.join((
                                'struct s {',
                                '  int x;',
                                '} y;',
                                'int z;',
                                'struct s t, u;',
                            )),
                        ),
                    ]),
                ),
            ]),
            pre_ast.TextBlock('int b;')
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_with_top_level_ifndef_block(self):
    source = '\n'.join((
        'int a;',
        '#ifndef CONFIG_SOMETHING',
        'struct s {',
        '  int x;',
        '} y;',
        'int z;',
        'struct s t, u;',
        '#endif',
        'int b;',
    ))
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        pre_ast.CompositeBlock([
            pre_ast.TextBlock('int a;'),
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
                    content=pre_ast.CompositeBlock([
                        pre_ast.TextBlock(
                            '\n'.join((
                                'struct s {',
                                '  int x;',
                                '} y;',
                                'int z;',
                                'struct s t, u;',
                            )),
                        ),
                    ]),
                ),
            ]),
            pre_ast.TextBlock('int b;'),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_with_top_level_ifdef_and_else_blocks(self):
    source = '\n'.join((
        'int a;',
        '#ifdef CONFIG_SOMETHING',
        'struct s {',
        '  int x;',
        '} y;',
        'struct s t, u;',
        '#else',
        'int z;',
        '#endif',
        'int b;',
    ))
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.TextBlock('int a;'),
            pre_ast.If(
                conditional_blocks=[
                    pre_ast.ConditionalBlock(
                        conditional_expression=c_ast.CFunctionCall(
                            function_name='defined',
                            arguments=[c_ast.CVariable('CONFIG_SOMETHING')],
                        ),
                        content=pre_ast.CompositeBlock([
                            pre_ast.TextBlock(
                                '\n'.join((
                                    'struct s {',
                                    '  int x;',
                                    '} y;',
                                    'struct s t, u;',
                                )),
                            ),
                        ]),
                    ),
                ],
                else_content=pre_ast.CompositeBlock([
                    pre_ast.TextBlock('int z;')
                ])
            ),
            pre_ast.TextBlock('int b;')
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_with_top_level_if_elif_and_else_blocks(self):
    source = '\n'.join((
        'int a;',
        '#if CONFIG_SOMETHING',
        'struct s {',
        '  int x;',
        '} y;',
        '#elif defined(CONFIG_SOMETHING_ELSE)',
        'struct s t, u;',
        '#else',
        'int z;',
        '#endif',
        'int b;',
    ))
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.TextBlock('int a;'),
            pre_ast.If(
                conditional_blocks=[
                    pre_ast.ConditionalBlock(
                        conditional_expression=c_ast.CVariable(
                            name='CONFIG_SOMETHING',
                        ),
                        content=pre_ast.CompositeBlock([
                            pre_ast.TextBlock(
                                '\n'.join((
                                    'struct s {',
                                    '  int x;',
                                    '} y;',
                                )),
                            ),
                        ]),
                    ),
                    pre_ast.ConditionalBlock(
                        conditional_expression=c_ast.CFunctionCall(
                            function_name='defined',
                            arguments=[
                                c_ast.CVariable('CONFIG_SOMETHING_ELSE'),
                            ],
                        ),
                        content=pre_ast.CompositeBlock([
                            pre_ast.TextBlock('struct s t, u;')
                        ]),
                    ),
                ],
                else_content=pre_ast.CompositeBlock([
                    pre_ast.TextBlock('int z;')
                ]),
            ),
            pre_ast.TextBlock('int b;'),
        ]),
    )
    self.assertEqual(actual, expected)

  def test_parse_with_ifdef_with_comment(self):
    source = '\n'.join((
        '#ifdef CONFIG_SOMETHING /* foo 42 */',
        '#endif',
    ))
    actual = self.parser.parse(source)
    expected = pre_ast.File(
        content=pre_ast.CompositeBlock([
            pre_ast.If(
                conditional_blocks=[
                    pre_ast.ConditionalBlock(
                        conditional_expression=c_ast.CFunctionCall(
                            function_name='defined',
                            arguments=[c_ast.CVariable('CONFIG_SOMETHING')],
                        ),
                        content=pre_ast.CompositeBlock([]),
                    ),
                ],
            ),
        ]),
    )
    self.assertEqual(actual, expected)

  def assertEqual(self, actual, expected):
    message = '\n%s\n!=\n%s' % (actual, expected)
    super(TestPreprocessingParser, self).assertEqual(actual, expected, message)


if __name__ == '__main__':
  unittest.main()
