import subprocess


class Error(Exception):
    """shell-specific error."""


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


class Shell(object):
    """Implementation of a shell cell."""

    def __init__(self, global_context=None, local_context=None,
                 filename="<unknown>"):
        super(Shell, self).__init__()
        self.global_context = global_context or {}
        self.local_context = local_context or {}
        self.filename = filename
        self.execution_count = 0

    def Exec(self, source, cwd=None):
        self.execution_count += 1

        process = subprocess.Popen(
            ["bash"], stdout=subprocess.PIPE, cwd=cwd,
            stderr=subprocess.PIPE, stdin=subprocess.PIPE)

        result = process.communicate(source)
        return result[0], result[1], str(process.returncode)
