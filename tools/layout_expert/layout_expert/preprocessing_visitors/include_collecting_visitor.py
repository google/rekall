"""A module containing a visitor that collects all the includes from a tree.

It is used to visit all the nodes of the AST to detect includes and therefore
load all files. We ignore any ifdef here because we dont have config variables
yet - so we end up with a fully expanded forest of ast for each parsed file.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals


class IncludeCollectingVisitor(object):
    """A visitor class that collects all the includes from a tree."""

    def collect_includes(self, node):
        return node.accept(self)

    def visit_file(self, file_):
        return file_.content.accept(self)

    def visit_include(self, include):
        return [include]

    def visit_pragma(self, pragma):
        _ = pragma
        return []

    def visit_error(self, error):
        _ = error
        return []

    def visit_define_object_like(self, define_object_like):
        _ = define_object_like
        return []

    def visit_define_function_like(self, define_function_like):
        _ = define_function_like
        return []

    def visit_undef(self, undef):
        _ = undef
        return []

    def visit_if(self, if_):
        includes = self._get_results(if_.conditional_blocks)
        return includes

    def visit_conditional_block(self, conditional_block):
        return self._get_results(conditional_block.content)

    def visit_composite_block(self, composite_block):
        return self._get_results(composite_block.content)

    def visit_text_block(self, text_block):
        _ = text_block
        return []

    def _get_results(self, nodes):
        results = []
        for node in nodes:
            results.extend(node.accept(self))
        return results
