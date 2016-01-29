"""A module containing a class for evaluating macros given as AST tree."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import re

from layout_expert.c_ast import c_ast


class MacroExpressionEvaluatorVisitor(object):
    """A class for evaluating macros given as AST tree."""

    _C_IDENTIFIER_OR_LITERAL_PATTERN = re.compile('^[a-zA-Z0-9_]+$')
    _C_INT_PATTERN = re.compile(
        '^(?P<number>(0x)?[0-9]+)(u|U)?(l|ll|L|LL)?$',
    )

    def __init__(self, macros):
        self.macros = macros

    def evaluate(self, node):
        """Evaluates a macro expression. (from AST form to a boolean).

        Note that we can only evaluate literal expressions since we do not see any
        function definitions. In theory the macro expander has completely reduced
        the original expression to a simple numeric form. If it has not and we have
        residual functions left over we wont be able to evaluate the expression, and
        therefore will raise an exception here.

        The purpose of the macro expression evaluator is to evaluate the result of a
        conditional expression (i.e. an #if block). Therefore we just return True or
        False.
        """
        return node.accept(self)

    def visit_c_function_call(self, function_call):
        # Macros should have been handled by the macro expander.
        function = self.macros.functions.get(function_call.function_name)
        if function is None:
            raise c_ast.IrreducibleFunction(
                "Function %s not known." % function_call.function_name)

        # Call arithmetic functions.
        return function(self.evaluate, *function_call.arguments)

    def visit_c_nested_expression(self, expression):
        return expression.content.accept(self)

    def visit_c_number(self, number):
        return number.value

    def visit_c_variable(self, variable):
        # This should never happen - the macro expander should take care of all the
        # macros so if we get here the macro is not defined. Since this function is
        # only ever called during expression evaluation we return 0 to indicate the
        # macro is not defined.
        return 0
