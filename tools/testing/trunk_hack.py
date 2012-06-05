"""This is a hack to make trunk volatility output data in a way suitable for
machine parsing.

Prior to running make_suite.py this file should be dropped into the trunk plugin
directory. This will change the table column separator to ||. This is required when parsing some table rows where space (which is normally the column separator) can appear within the column context (e.g. the path name).

Volatility trunk also corrupts output by forcing it into a maximum width (called
eliding). This makes it hard to test for the correct output.
"""
from volatility import commands

# As per IRC discussions this is the recommended way to override table renderer
# behaviour in trunk.

# Monkey patch to separate columns
old_table_header = commands.Command.table_header

def table_header(self, outfd, title_format_list = None):
    self.tablesep = "||"
    old_table_header(self, outfd, title_format_list=title_format_list)

commands.Command.table_header = table_header


def table_row(self, outfd, *args):
    """Outputs a single row of a table"""
    reslist = []

    if len(args) > len(self._formatlist):
        debug.error("Too many values for the table")

    for index in range(len(args)):
        spec = self._formatlist[index]
        result = ("{0:" + spec.to_string() + "}").format(args[index])
        reslist.append(result)

    outfd.write(self.tablesep.join(reslist) + "\n")

commands.Command.table_row = table_row
