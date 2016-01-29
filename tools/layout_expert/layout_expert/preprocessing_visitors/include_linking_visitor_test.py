from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import unittest


import mock
from layout_expert.c_ast import pre_ast

from layout_expert.preprocessing_visitors import include_linking_visitor


class TestIncludeLinkingVisitor(unittest.TestCase):

    def setUp(self):
        self.include_linking_visitor = (
            include_linking_visitor.IncludeLinkingVisitor()
        )
        self.files = {
            'path_1': 'content_1',
            'path_2': 'content_2',
            'path_3': 'content_3',
        }

    def test_resolve_with_file(self):
        mock_node = mock.MagicMock()
        node = pre_ast.File(mock_node)
        self.include_linking_visitor.resolve(node, self.files)
        mock_node.accept.assert_called_once_with(
            self.include_linking_visitor,
            self.files,
        )

    def test_resolve_with_inlcude_and_path_exists(self):
        node = pre_ast.Include(
            path='some_path',
            quotes_type='some_quotes_type',
            absolute_path='path_2',
        )
        self.include_linking_visitor.resolve(node, self.files)
        self.assertEqual(node.content, 'content_2')

    def test_resolve_with_inlcude_and_path_not_exists(self):
        node = pre_ast.Include(
            path='some_path',
            quotes_type='some_quotes_type',
            absolute_path='path_4',
        )
        self.include_linking_visitor.resolve(node, self.files)
        self.assertIsNone(node.content)

    def test_resolve_with_if(self):
        mock_conditional_block_1 = mock.MagicMock()
        mock_conditional_block_2 = mock.MagicMock()
        mock_conditional_block_3 = mock.MagicMock()
        node = pre_ast.If(
            conditional_blocks=[
                mock_conditional_block_1,
                mock_conditional_block_2,
                mock_conditional_block_3,
            ],
        )
        self.include_linking_visitor.resolve(node, self.files)
        for mock_node in (
                mock_conditional_block_1,
                mock_conditional_block_2,
                mock_conditional_block_3,
        ):
            mock_node.accept.assert_called_once_with(
                self.include_linking_visitor,
                self.files,
            )

    def test_resolve_with_composite_block(self):
        mock_conditional_block_1 = mock.MagicMock()
        mock_conditional_block_2 = mock.MagicMock()
        mock_conditional_block_3 = mock.MagicMock()
        node = pre_ast.CompositeBlock([
            mock_conditional_block_1,
            mock_conditional_block_2,
            mock_conditional_block_3,
        ])
        self.include_linking_visitor.resolve(node, self.files)
        for mock_node in (
                mock_conditional_block_1,
                mock_conditional_block_2,
                mock_conditional_block_3,
        ):
            mock_node.accept.assert_called_once_with(
                self.include_linking_visitor,
                self.files,
            )


if __name__ == '__main__':
    unittest.main()
