"""This is a hack to make trunk volatility output data in a way suitable for
machine parsing.

Prior to running make_suite.py this file should be dropped into the trunk plugin
directory. This will change the table column separator to ||. This is required
when parsing some table rows where space (which is normally the column
separator) can appear within the column context (e.g. the path name).

We also switch off eliding to ensure we see an uncorrupted view of the data.
"""
from volatility import commands

# As per IRC discussions this is the recommended way to override table renderer
# behaviour in trunk.
commands.Command.elide_data = False
commands.Command.tablesep = "||"
