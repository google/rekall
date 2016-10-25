"""Add a magic handler for select, describe and explain plugins."""
import shlex
from IPython.core import magic
from rekall import ipython_support


def Parser(line):
    result = shlex.shlex(line)
    result.whitespace_split = True

    return result


@magic.magics_class
class RekallAgentMagics(magic.Magics):

    def _syntax_error(self, text, offset, message):
        result = SyntaxError(message)
        result.text = text
        result.offset = offset
        raise result

    def _parse_value(self, value):
        # Value encoded with quotes.
        if (value[0] == value[-1] == '"' or
            value[0] == value[-1] == "'"):
            value = value[1:]
            value = value[:-1]
            value = value.decode("unicode_escape")
        else:
            try:
                if value.startswith("0x"):
                    value = int(value, 16)
                else:
                    value = int(value)
            except ValueError:
                pass

        return value

    def _parsel_line(self, line):
        items = list(Parser(line))
        args = []
        kwargs = {}
        if ":" not in items[0]:
            self._syntax_error(
                line, None, "Expected to run a magic command with :.")
        items[0] = items[0].split(":", 1)[-1]

        while items:
            next_item = items.pop(0)
            # This is key value pair
            if "=" in next_item:
                key, value = next_item.split("=", 1)
                kwargs[key] = self._parse_value(value)

            # This is an argv.
            else:
                args.append(self._parse_value(next_item))

        return args, kwargs

    def _RunPlugin(self, plugin_name, line):
        session = self.shell.user_global_ns["session"]
        if line.endswith("?"):
            runner = getattr(self.shell.user_ns["plugins"],
                             plugin_name, None)
            self.shell.inspector.pinfo(runner)
            return

        args, kwargs = self._parsel_line(line)
        return session.RunPlugin(plugin_name, *args, **kwargs)

    @magic.line_cell_magic
    def gs(self, line, cell=None):
        return self._RunPlugin("view", line)

    @magic.line_cell_magic
    def f(self, line, cell=None):
        return self._RunPlugin("inspect_flow", line)

    @magic.line_cell_magic
    def h(self, line, cell=None):
        return self._RunPlugin("inspect_hunt", line)

    @magic.line_cell_magic
    def vfs(self, line, cell=None):
        return self._RunPlugin("vfs_ls", line)

    @magic.line_cell_magic
    def fetch(self, line, cell=None):
        """Start FileFinder with download and view results."""
        return self._RunPlugin("fetch", line)


ipython_support.REGISTERED_MAGICS.append(RekallAgentMagics)
