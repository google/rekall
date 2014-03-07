# Rekall Memory Forensics
# Copyright 2014 Google Inc. All Rights Reserved.
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

"""This module implements profile indexing.

Rekall relies on accurate profiles for reliable analysis of memory artifacts. We
depend on selecting the correct profile from the profile repository, but
sometimes its hard to determine the exact profile to use. For windows, the
profile must match exactly the GUID in the driver.

However, sometimes, the GUID is unavailable or it could be manipulated. In that
case we would like to determine the profile version by applying the index.

The profile repository has an index for each kernel module stored. We can use
this index to determine the exact version of the profile very quickly - even if
the RSDS GUID is not available or incorrect.
"""

__author__ = "Michael Cohen <scudette@google.com>"

import logging
from rekall import obj
from rekall.plugins.windows import common


class Index(obj.Profile):
    """A profile which contains an index to locate other profiles."""
    index = None

    def _SetupProfileFromData(self, data):
        super(Index, self)._SetupProfileFromData(data)
        self.index = data.get("$INDEX")

    def copy(self):
        result = super(Index, self).copy()
        result.index = self.index.copy()

        return result

    def _TestSymbols(self, data, offset, possible_symbols):
        """Match any of the possible_symbols at offset.

        Return True if there is a match.
        """
        for symbol in possible_symbols:
            symbol = symbol.decode("hex")

            if data.startswith(symbol, offset):
                return True

    def _TestProfile(self, data, image_base, profile, symbols):
        """Match _all_ the symbols against this data."""
        for offset, possible_symbols in symbols:
            # The possible_symbols can be a single string which means there is
            # only one option. If it is a list, then any of the symbols may
            # match at this offset to be considered a match.
            if isinstance(possible_symbols, basestring):
                possible_symbols = [possible_symbols]

            if self._TestSymbols(data, offset, possible_symbols):
                logging.debug(
                    "%s matched offset %#x+%#x=%#x",
                    profile, offset, image_base, offset+image_base)
            else:
                return False

        # If we get here _all_ symbols matched.
        return True

    def LookupIndex(self, image_base):
        address_space = self.session.GetParameter("default_address_space")
        data = address_space.read(
            image_base, self.metadata("max_offset", 5*1024*1024))

        for profile, symbols in self.index.iteritems():
            if self._TestProfile(data, image_base, profile, symbols):
                yield profile


class GuessGUID(common.WindowsCommandPlugin):
    """Try to guess the exact version of a kernel module by using an index."""

    name = "guess_guid"

    @classmethod
    def args(cls, parser):
        super(GuessGUID, cls).args(parser)
        parser.add_argument("module", default=None,
                            help="The name of the module to guess.")

    def __init__(self, module=None, **kwargs):
        super(GuessGUID, self).__init__(**kwargs)
        self.module = module

    def ScanProfile(self):
        """Scan for module using version_scan for RSDS scanning."""
        module_name = self.module.split(".")[0]
        for _, guid in self.session.plugins.version_scan(
            name_regex="^%s.pdb" % module_name).ScanVersions():
            yield obj.NoneObject(), "GUID/%s" % guid

    def LookupIndex(self):
        """Loookup the profile from an index."""
        try:
            index = self.session.LoadProfile("%s/index" % self.module)
        except ValueError:
            return

        for session in self.session.plugins.sessions().session_spaces():
            # Switch the process context to this session so the address
            # resolver can find the correctly mapped driver.
            cc = self.session.plugins.cc(eprocess=session.processes())
            with cc:
                cc.SwitchContext()

                # Get the image base of the win32k module.
                image_base = self.session.address_resolver.get_address_by_name(
                    self.module)

                for profile in index.LookupIndex(image_base):
                    yield self.session.GetParameter("process_context"), profile

    def GuessProfiles(self):
        """Search for suitable profiles using a variety of methods."""
        # Usually this plugin is invoked from ParameterHooks which will take the
        # first hit. So we try to do the fast methods first, then fall back to
        # the slower methods.
        for x in self.LookupIndex():
            yield x

        # Looking up the index failed because it was not there, or the index did
        # not contain the right profile - fall back to RSDS scanning.
        for x in self.ScanProfile():
            yield x


    def render(self, renderer):
        renderer.table_header([
            ("PID", "context", "20"),
            ("Session", "context", "20"),
            ("Profile", "profile", ""),
            ])
        for context, possibility in self.GuessProfiles():
            renderer.table_row(context.pid, context.SessionId, possibility)
