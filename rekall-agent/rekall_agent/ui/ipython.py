"""Add a magic handler for select, describe and explain plugins."""
from IPython.core import magic
from rekall import ipython_support


@magic.magics_class
class RekallAgentMagics(magic.Magics):
    def _RunPlugin(self, plugin_name, line):
        session = self.shell.user_global_ns["session"]
        if ":" in line:
            parameter = line.split(":", 1)[1].strip()

        return session.RunPlugin(plugin_name, parameter)

    @magic.line_cell_magic
    def gs(self, line, cell=None):
        return self._RunPlugin("view", line)

    @magic.line_cell_magic
    def f(self, line, cell=None):
        return self._RunPlugin("inspect_flow", line)

    @magic.line_cell_magic
    def h(self, line, cell=None):
        return self._RunPlugin("inspect_hunt", line)


ipython_support.REGISTERED_MAGICS.append(RekallAgentMagics)
