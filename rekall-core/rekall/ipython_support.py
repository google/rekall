#!/usr/bin/python

# Rekall Memory Forensics
# Copyright 2013 Google Inc. All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

"""Support IPython 4.0."""

# pylint: disable=protected-access

__author__ = "Michael Cohen <scudette@gmail.com>"

import logging
import re
import readline

from rekall import constants
from rekall import config
from rekall import session as session_module

import IPython
from IPython.core import page
from IPython.core import oinspect
from IPython.core.interactiveshell import InteractiveShell
from IPython.terminal import embed

try:
    from traitlets.config.loader import Config
except ImportError:
    from IPython.config.loader import Config


def RekallCompleter(self, text):
    """Sophisticated command line completer for Rekall."""
    try:
        command_parts = self.line_buffer.split(" ")
        command = command_parts[0]

        if command.startswith("plugins."):
            command = command[len("plugins."):]

        global_matches = set(self.global_matches(command))

        # Complete strings which look like symbol names.
        m = re.match("\"([^!]+![^\"]*)$", command_parts[-1])
        if m:
            session = self.namespace.get("session")

            # If this is the only match, close the quotes to save typing.
            result = session.address_resolver.search_symbol(m.group(1) + "*")
            if len(result) == 1:
                result = [result[0] + "\""]

            result = [x.split("!", 1)[1] for x in result]
            return result

        # Only complete if there is exactly one object which matches and a space
        # was typed after it. e.g.: pslist <cursor>
        if (command in global_matches and len(command_parts) > 1):
            # Get the object and ask it about the list of args that it supports.
            obj = self.namespace.get(command)
            if obj:
                try:
                    matches = [
                        "%s=" % x["name"] for x in obj.Metadata()["arguments"]]
                    return [x for x in matches if x.startswith(text)]
                except Exception:
                    pass

        return []

    # Wide exception is necessary here because otherwise the completer will
    # swallow all errors.
    except Exception as e:
        logging.debug(e)

    return []


class RekallObjectInspector(oinspect.Inspector):
    """Rekall specific object inspector.

    Rekall populates the environment with "plugin runners" which are proxies of
    the actual plugin that will be invoked. The exact plugin will be invoked
    depending on the profile availability.

    In order to make ipython's ? and ?? operators work, we need to implement
    specialized inspection to present the doc strings and arg list of the actual
    plugin.
    """

    def _format_parameter(self, displayfields, arg):
        desc = arg["help"]
        try:
            desc += " (type: %s)" % arg["type"]
        except KeyError:
            pass

        displayfields.append(("  " + arg["name"], desc))

    def format_parameters(self, plugin_class, positional=True):
        displayfields = []
        command_metadata = config.CommandMetadata(plugin_class).Metadata()

        # First format positionals:
        for arg in command_metadata["arguments"]:
            if arg.get("positional", False) == positional:
                self._format_parameter(displayfields, arg)

        if displayfields:
            return self._format_fields(displayfields)

        return ""

    def plugin_pinfo(self, runner, detail_level=0):
        """Generate info dict for a plugin from a plugin runner."""
        plugin_class = getattr(
            runner.session.plugins, runner.plugin_name)._target

        display_fields = [
            ("file", oinspect.find_file(plugin_class)),
            ("Plugin", "%s (%s)" % (plugin_class.__name__, plugin_class.name)),
            ("Positional Args",
             self.format_parameters(plugin_class, True)),
            ("Keyword Args",
             self.format_parameters(plugin_class, False)),
            ("Docstring", oinspect.getdoc(plugin_class) or ""),
            ("Link", (
                "http://www.rekall-forensic.com/epydocs/%s.%s-class.html" % (
                    plugin_class.__module__, plugin_class.__name__))),
        ]

        # Include the source if required.
        if detail_level > 0:
            info = self.info(plugin_class, detail_level=detail_level)
            display_fields.append(("source", self.format(info["source"])))

        return self._format_fields(display_fields)

    def pinfo(self, obj, oname='', formatter=None, info=None, detail_level=0):
        if isinstance(obj, session_module.PluginRunner):
            # Delegate info generation for PluginRunners.
            result = self.plugin_pinfo(obj, detail_level=detail_level)
            if result:
                page.page(result)

        else:
            oinspect.Inspector.pinfo(
                self, obj, oname=oname, formatter=formatter,
                info=info, detail_level=detail_level)


class RekallShell(embed.InteractiveShellEmbed):
    display_banner = constants.BANNER

    def atexit_operations(self):
        self.user_global_ns.session.Flush()

    def init_inspector(self):
        super(RekallShell, self).init_inspector()

        # This is a hack but seems the only way to make get_ipython() work
        # properly.
        InteractiveShell._instance = self
        ipython_version = IPython.__version__

        # IPython 4 is the one we standardize on right now. This means we
        # support earlier ones but turn off the bells and whistles.
        if "4.0.0" <= ipython_version < "5.0.0":
            self.inspector = RekallObjectInspector()

        else:
            self.user_ns.session.logging.warn(
                "Warning: IPython version %s not fully supported. "
                "We recommend installing ipython version 4.",
                ipython_version)


def Shell(user_session):
    # This should bring back the old autocall behaviour. e.g.:
    # In [1]: pslist
    cfg = Config()
    cfg.InteractiveShellEmbed.autocall = 2

    cfg.PromptManager.in_template = (
        r'{color.LightCyan}'
        r'[{session.session_id}] '
        r'{session.session_name}'
        r'{color.LightBlue}{color.Green} \T> ')

    cfg.PromptManager.in2_template = (
        r'{color.Green}|{color.LightGreen}\D{color.Green}> ')

    cfg.PromptManager.out_template = r'Out<\#> '
    cfg.InteractiveShell.separate_in = ''
    cfg.InteractiveShell.separate_out = ''
    cfg.InteractiveShell.separate_out2 = ''

    shell = RekallShell(config=cfg, user_ns=user_session.locals)

    shell.Completer.merge_completions = False
    shell.exit_msg = constants.GetQuote()
    shell.set_custom_completer(RekallCompleter, 0)

    # Do we need to pre-run something?
    if user_session.run != None:
        execfile(user_session.run, user_session.locals)

    user_session.shell = shell

    # Set known delimeters for the completer. This varies by OS so we need to
    # set it to ensure consistency.
    readline.set_completer_delims(' \t\n`!@#$^&*()=+[{]}\\|;:\'",<>?')

    shell(global_ns=user_session.locals)

    return True
