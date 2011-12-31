# Volatility
# Copyright (C) 2008 Volatile Systems
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


import sys, textwrap
from volatility import registry


class command(object):
    """ Base class for each plugin command """
    op = ""
    opts = ""
    args = ""

    # The name of this command
    __name = ""

    # This class will not be registered. Note that this attribute is not
    # inherited.
    __abstract = True

    # meta_info will be removed
    meta_info = {}

    __metaclass__ = registry.MetaclassRegistry

    @classmethod
    def name(cls):
        """Retrieve the class name."""
        return getattr(cls, "_%s__name" % cls.__name__, cls.__name__.lower())

    def __init__(self, config, *_args, **_kwargs):
        """ Constructor uses args as an initializer. It creates an instance
        of OptionParser, populates the options, and finally parses the 
        command line. Options are stored in the self.opts attribute.
        """
        self._config = config

    @staticmethod
    def register_options(config):
        """Registers options into a config object provided"""
        config.add_option("OUTPUT", default = 'text',
                          cache_invalidator = False,
                          help = "Output in this format (format support is module specific)")

        config.add_option("OUTPUT-FILE", default = None,
                          cache_invalidator = False,
                          help = "write output in this file")

        config.add_option("VERBOSE", default = 0, action = 'count',
                          cache_invalidator = False,
                          short_option = 'v', help = 'Verbose information')

    @classmethod
    def help(cls):
        """ This function returns a string that will be displayed when a
        user lists available plugins.

        By default we return the doc string and a list of module
        specific options.
        """
        docstring = ""
        try:
            docstring = textwrap.dedent(cls.__doc__)
        except (AttributeError, TypeError):
            pass

        class HelpRegistrator(object):
            """gives help about specific module parameters."""
            def __init__(self):
                self.options = {}

            def add_option(self, name, default = None, help = "",**kwargs):
                attr = name.lower().replace("-", "_")
                self.options[attr] = "%s (default %s)" % (help, default)

            def remove_option(self, option):
                self.options.pop(option, None)

            def parse_options(self, final=False):
                pass

            def __getattr__(self, attr):
                return None

        # Generate a line for each module specific option.
        help_registrator = HelpRegistrator()

        # TODO: Remove the need for this line by forbidding add_option in the
        # constructor.
        cls(help_registrator)
        cls.register_options(help_registrator)

        if help_registrator.options:
            docstring += "\n\nModule specific parameters\n--------------------------"
            for attr, help in sorted(help_registrator.options.items()):
                docstring += "\n%s:\t\t%s" % (attr, help)

        return docstring

    @classmethod
    def is_active(cls, config):
        """Returns True if this command is compatible with the current config.

        e.g. current choice of profiles.
        """
        return True

    def calculate(self):
        """ This function is responsible for performing all calculations

        We should not have any output functions (e.g. print) in this
        function at all.

        If this function is expected to take a long time to return
        some data, the function should return a generator.
        """


    def execute(self):
        """ Executes the plugin command."""
        ## Executing plugins is done in two stages - first we calculate
        data = self.calculate()

        ## Then we render the result in some way based on the
        ## requested output mode:
        function_name = "render_{0}".format(self._config.OUTPUT)
        if self._config.OUTPUT_FILE:
            outfd = open(self._config.OUTPUT_FILE, 'w')
            # TODO: We should probably check that this won't blat over an
            # existing file.
        else:
            outfd = sys.stdout

        try:
            func = getattr(self, function_name)
        except AttributeError:
            ## Try to find out what formats are supported
            result = []
            for x in dir(self):
                if x.startswith("render_"):
                    _a, b = x.split("_", 1)
                    result.append(b)

            print ("Plugin {0} is unable to produce output in format {1}. "
                   "Supported formats are {2}. Please send a feature "
                   "request".format(self.__class__.__name__, 
                                    self._config.OUTPUT, result))
            return

        func(outfd, data)

    @classmethod
    def GetActiveClasses(cls, config):
        """Return the active commands."""
        for name, command_cls in cls.classes.items():
            if command_cls.is_active(config):
                yield getattr(command_cls, "_%s__name" % name, name.lower()), command_cls
