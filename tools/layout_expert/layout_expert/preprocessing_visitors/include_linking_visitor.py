"""A module containing a visitor that links includes with their content.

This visitor connects include nodes in the AST with the AST forest that we
already have - it could be done during computation but its easier to mutate
the AST to directly link each include node's AST.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals


class IncludeLinkingVisitor(object):
    """A visitor class that links includes with their content."""

    def resolve(self, node, files):
        node.accept(self, files)

    def visit_file(self, file_, files):
        self.resolve(file_.content, files)

    def visit_include(self, include, files):
        include.content = files.get(include.absolute_path)

    def visit_pragma(self, pragma, files):
        _ = pragma
        _ = files

    def visit_error(self, error, files):
        _ = error
        _ = files

    def visit_define_object_like(self, define_object_like, files):
        _ = define_object_like
        _ = files

    def visit_define_function_like(self, define_function_like, files):
        _ = define_function_like
        _ = files

    def visit_undef(self, undef, files):
        _ = undef
        _ = files

    def visit_if(self, if_, files):
        for conditional_block in if_.conditional_blocks:
            self.resolve(conditional_block, files)

    def visit_conditional_block(self, conditional_block, files):
        for node in conditional_block.content:
            node.accept(self, files)

    def visit_composite_block(self, compositie_block, files):
        for element in compositie_block.content:
            self.resolve(element, files)

    def visit_text_block(self, text_block, files):
        _ = text_block
        _ = files
