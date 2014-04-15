import ast
import codegen
import StringIO
import sys


class Error(Exception):
    """PythonShell-specific error."""


class ParseError(Error):
    """Thrown when supplied code can't be parsed."""

    def __init__(self, original_error):
        super(ParseError, self).__init__()
        self.original_error = original_error


class ExecError(Error):
    """Thrown when supplied code raises exception during execution."""

    def __init__(self, stdout, stderr, original_error):
        super(ExecError, self).__init__()
        self.stdout = stdout
        self.stderr = stderr
        self.original_error = original_error


class PythonShell(object):
    """Implementation of the python shell."""

    def __init__(self, global_context=None, local_context=None,
                 filename="<unknown>"):
        super(PythonShell, self).__init__()
        self.global_context = global_context or {}
        self.local_context = local_context or {}
        self.filename = filename
        self.execution_count = 0

    def Exec(self, source):
        self.execution_count += 1

        try:
            nodes = ast.parse(source, self.filename)
        except IndentationError as e:
            raise ParseError(e)
        except (OverflowError, SyntaxError, ValueError,
                TypeError, MemoryError) as e:
            raise ParseError(e)

        stdout = StringIO.StringIO()
        stderr = StringIO.StringIO()
        prev_stdout = sys.stdout
        prev_stderr = sys.stderr
        sys.stdout = stdout
        sys.stderr = stderr

        try:
            if isinstance(nodes.body[-1], ast.Expr):
                exec_nodes = nodes.body[:-1]
                interactive_nodes = nodes.body[-1:]
            else:
                exec_nodes, interactive_nodes = nodes.body, []

            for node in exec_nodes:
                mod = ast.Module([node])
                code = compile(mod, self.filename, "exec")
                exec(code, self.global_context, self.local_context)

            result = None
            for node in interactive_nodes:
                source = codegen.to_source(node)
                new_node = ast.parse(source, self.filename, mode="eval")
                mod = ast.Expression(new_node.body)
                code = compile(mod, self.filename, "eval")
                result = eval(code, self.global_context, self.local_context)

            sys.stdout = prev_stdout
            sys.stderr = prev_stderr

            return stdout.getvalue(), stderr.getvalue(), result
        except Exception as e:
            raise ExecError(stdout.getvalue(), stderr.getvalue(), e)

        finally:
            sys.stdout = prev_stdout
            sys.stderr = prev_stderr
