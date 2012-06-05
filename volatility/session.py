# Volatility
# Copyright (C) 2012 Michael Cohen
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

"""This module implements the volatility session.

The session stores information about the a specific user interactive
session. Sessions can be saved and loaded between runs and provide a convenient
way for people to save their own results.
"""

__author__ = "Michael Cohen <scudette@gmail.com>"
import logging
import pdb
import os
import sys
import time

from volatility import addrspace
from volatility import fmtspec
from volatility import plugin
from volatility import obj
from volatility import registry
from volatility import utils


class ProfileContainer(object):
    """A utility class for intantiating profiles."""

    def __init__(self, session=None):
        self.session = session

    def __dir__(self):
        """Show all available profiles."""
        return obj.Profile.classes.keys()

    def __getattr__(self, attr):
        if attr not in obj.Profile.classes:
            raise AttributeError("%s is not a valid profile" % attr)

        return attr


class PluginContainer(object):
    """A container for holding plugins."""

    def __init__(self, session):
        self.plugins = {}
        self.session = session

        # Now add the commands that are available based on self.session
        for command_cls in plugin.Command.GetActiveClasses(self.session):
            if command_cls.name:
                self.plugins[command_cls.name] = command_cls

        logging.debug("Reloading active plugins %s",
                      ["%s <- %s" % (x, y.__name__) for x,y in self.plugins.items()])

    def reset(self):
        self.__init__(self.session)

    def __dir__(self):
        """Support ipython command expansion."""
        return self.plugins.keys()

    def __getattr__(self, attr):
        try:
            return self.plugins[attr]
        except KeyError:
            raise AttributeError(attr)


class Pager(object):
    """A file like object which can be swapped with a pager."""
    # Default encoding is utf8
    encoding = "utf8"

    def __init__(self, session=None, default_fd=None):
        # Default fd if not pager can be found.
        self.default_fd = default_fd or sys.stdout
        self.make_pager(session)


    def make_pager(self, session):
        # More is the least common denominator of pagers :-(. Less is better,
        # but most is best!
        pager = session.pager or os.environ.get("PAGER")
        try:
            self.pager = os.popen(pager, 'w', 0)
        except Exception, e:
            self.pager = self.default_fd

        # Determine the output encoding
        try:
            encoding = self.pager.encoding
            if encoding: self.encoding = encoding
        except AttributeError:
            pass

    def write(self, data):
        # Encode the data according to the output encoding.
        data = data.encode(self.encoding)
        try:
            self.pager.write(data)
        except IOError:
            # In case the pipe closed we just write to stdout
            self.pager = sys.stdout
            self.pager.write(data)


class TextRenderer(object):
    """Plugins can receive a renderer object to assist formatting of output."""

    __metaclass__ = registry.MetaclassRegistry

    tablesep = " "
    elide = True

    def __init__(self, session=None, fd=None):
        self.session = session
        self.fd = fd

    def start(self):
        """The method is called when new output is required."""
        self.pager = self.fd or Pager(session=self.session)

    def write(self, data):
        self.pager.write(data)

    def _elide(self, string, length):
        """Adds three dots in the middle of a string if it is longer than length"""
        if length == -1:
            return string

        if len(string) < length:
            return (" " * (length - len(string))) + string

        elif len(string) == length:
            return string

        else:
            if length < 5:
                logging.error("Cannot elide a string to length less than 5")

            even = ((length + 1) % 2)
            length = (length - 3) / 2
            return string[:length + even] + "..." + string[-length:]

    def _formatlookup(self, code):
        """Code to turn profile specific values into format specifications"""
        code = code or ""
        if not code.startswith('['):
            return code

        # Strip off the square brackets
        code = code[1:-1].lower()
        if code.startswith('addr'):
            spec = fmtspec.FormatSpec("#10x")
            if self.session.profile.metadata('memory_model') == '64bit':
                spec.minwidth += 8

            if 'pad' in code:
                spec.fill = "0"
                spec.align = spec.align if spec.align else "="

            else:
                # Non-padded addresses will come out as numbers,
                # so titles should align >
                spec.align = ">"
            return spec.to_string()

        # Something went wrong
        debug.warning("Unknown table format specification: " + code)
        return ""

    def table_header(self, title_format_list = None):
        """Table header renders the title row of a table.

        This also stores the header types to ensure everything is formatted
        appropriately.  It must be a list of tuples rather than a dict for
        ordering purposes.
        """
        titles = []
        rules = []
        self._formatlist = []

        for (k, v) in title_format_list:
            spec = fmtspec.FormatSpec(self._formatlookup(v))

            # If spec.minwidth = -1, this field is unbounded length
            if spec.minwidth != -1:
                spec.minwidth = max(spec.minwidth, len(k))

            # Get the title specification to follow the alignment of the field
            titlespec = fmtspec.FormatSpec(formtype='s',
                                           minwidth=max(spec.minwidth, len(k)))

            titlespec.align = spec.align if spec.align in "<>^" else "<"

            # Add this to the titles, rules, and formatspecs lists
            titles.append((u"{0:" + titlespec.to_string() + "}").format(k))
            rules.append("-" * titlespec.minwidth)
            self._formatlist.append(spec)

        # Write out the titles and line rules
        self.write(self.tablesep.join(titles) + "\n")
        self.write(self.tablesep.join(rules) + "\n")

    def table_row(self, *args):
        """Outputs a single row of a table"""
        reslist = []
        if len(args) > len(self._formatlist):
            logging.error("Too many values for the table")

        for index in range(len(args)):
            spec = self._formatlist[index]
            result = (u"{0:" + spec.to_string() + "}").format(args[index])
            if self.elide:
                result = self._elide(result, spec.minwidth)

            reslist.append(result)
        self.write(self.tablesep.join(reslist) + "\n")

    def end(self):
        """Tells the renderer that we finished using it for a while."""


class Session(object):
    """The session allows for storing of arbitrary values and configuration."""

    # This is used for setattr in __init__.
    _ready = False

    def __init__(self, env=None, **kwargs):
        # These are the command plugins which we exported to the local
        # namespace.
        self._start_time = time.time()
        self._locals = env or {}

        # Fill the session with helpful defaults.
        self.__dict__['logging'] = self.logging or "INFO"
        self.pager = obj.NoneObject("Set this to your favourite pager.")
        self.profile = obj.NoneObject("Set this a valid profile (e.g. type profiles. and tab).")
        self.profile_file = obj.NoneObject("Some profiles accept a data file (e.g. Linux).")
        self.filename = obj.NoneObject("Set this to the image filename.")
        self.renderer = TextRenderer(session=self)

        self.plugins = PluginContainer(self)
        self._ready = True

        # Merge in defaults.
        for k, v in kwargs.items():
            setattr(self, k, v)

    def reset(self):
        """Reset the current session by making a new session."""
        self._prepare_local_namespace()

    def _prepare_local_namespace(self):
        session = self._locals['session'] = Session(self._locals)

        # Prepopulate the namespace with our most important modules.
        self._locals['addrspace'] = addrspace
        self._locals['obj'] = obj
        self._locals['plugins'] = session.plugins
        self._locals['profiles'] = ProfileContainer(self)

        # The handler for the vol command.
        self._locals['dump'] = session.dump
        self._locals['vol'] = session.vol
        self._locals['info'] = session.info
        self._locals['help'] = session.help

    def dump(self, target, offset=0, width=16, rows=10):
        # Its an object
        if isinstance(target, obj.BaseObject):
            data = target.obj_vm.zread(target.obj_offset, target.size())
            base = target.obj_offset
        # Its an address space
        elif isinstance(target, addrspace.BaseAddressSpace):
            data = target.zread(offset, width*rows)
            base = int(offset)
        # Its a string or something else:
        else:
            data = utils.SmartStr(data)
            base = 0

        utils.WriteHexdump(sys.stdout, data, width=width, base=base)

    def info(self, plugin_cls=None, fd=None):
        self.vol(self.plugins.info, item=plugin_cls, fd=fd)

    def vol(self, plugin_cls=None, renderer=None, fd=None, debug=False, output=None,
            **kwargs):
        """Launch a plugin and its render() method automatically.

        We use the pager specified in session.pager.

        Args:
          plugin_cls: A string naming the plugin, or the plugin class itself.
          renderer: An optional renderer to use.
          debug: If set we break into the debugger if anything goes wrong.

          output: If set we open and write the output to this filename. If
            session.overwrite is set to True, we will overwrite this
            file. Otherwise the output is redirected to stdout.
        """
        if isinstance(plugin_cls, basestring):
            plugin_cls = getattr(self.plugins, plugin_cls)

        renderer = renderer or self.renderer

        if output is not None:
            if os.access(output, os.F_OK) and not self.overwrite:
                logging.error("Output file '%s' exists but session.overwrite is "
                              "not set." % output)
            else:
                renderer = TextRenderer(session=self, fd=open(output, "w"))

        # Allow per call overriding of the output file descriptor.
        if fd is not None:
            renderer = TextRenderer(session=self, fd=fd)

        try:
            renderer.start()

            kwargs['session'] = self
            result = plugin_cls(**kwargs)
            result.render(renderer)

            renderer.end()
            return result

        except plugin.Error, e:
            logging.error("Failed running plugin %s: %s", plugin_cls.__name__, e)
        except Exception, e:
            logging.error("Error: %s", e)
            # If anything goes wrong, we break into a debugger here.
            if debug:
                pdb.post_mortem()
            else:
                raise

    def __str__(self):
        result = """Volatility session Started on %s.

Config:
""" % (time.ctime(self.start_time))
        for name in dir(self):
            value = getattr(self, name)
            result += " %s:  %r\n" % (name, value)

        return result

    def __setattr__(self, attr, value):
        """Allow the user to set configuration information directly."""
        # Allow for hooks to override special options.
        hook = getattr(self, "_set_%s" % attr, None)
        if hook:
            hook(value)
        else:
            object.__setattr__(self, attr, value)

        # This may affect which plugins are available for the user.
        if self.plugins:
            self.plugins.reset()

    def __getattr__(self, attr):
        """This will only get called if the attribute does not exist."""
        return None

    def __dir__(self):
        items = self.__dict__.keys() + dir(self.__class__)

        return [x for x in items if not x.startswith("_")]

    def _set_profile(self, profile):
        """A Hook for setting profiles."""
        if profile == None:
            self.__dict__['profile'] = profile
            return

        # Profile is a string - we try to make a profile object.
        if isinstance(profile, basestring):
            # First try to find this profile.
            try:
                profile = obj.Profile.classes[profile](session=self)
            except KeyError:
                logging.error("Profile %s is not known." % profile)
                logging.info("Known profiles are:")

                for profile in obj.Profile.classes:
                    logging.info("  %s" % profile)

                return

        if isinstance(profile, obj.Profile):
            self.__dict__['profile'] = profile
            self.plugins.reset()
        else:
            raise RuntimeError("A profile must be a string.")

    def _set_logging(self, value):
        if value is None: return

        level = value
        if isinstance(value, basestring):
            level = getattr(logging, value, logging.INFO)

        logging.log(level, "Logging level set to %s", value)
        logging.getLogger().setLevel(int(level))

    def help(self, item=None):
        """Prints some helpful information."""
        if item is None:
            print """Welocome to Volatility.

You can get help on any module or object by typing:

help object

Some interesting topics to get you started, explaining some volatility specific
concepts:

help addrspace - The address space.
help obj       - The volatility objects.
help profile   - What are Profiles?
"""
