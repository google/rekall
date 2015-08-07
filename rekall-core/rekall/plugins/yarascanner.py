# Rekall Memory Forensics
# Copyright (c) 2012, Michael Cohen <scudette@gmail.com>
# Copyright (c) 2010, 2011, 2012 Michael Ligh <michael.ligh@mnin.org>
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


"""A Rekall Memory Forensics scanner which uses yara."""
from rekall import scan


class BaseYaraASScanner(scan.BaseScanner):
    """An address space scanner for Yara signatures."""
    overlap = 1024

    def __init__(self, rules=None, **kwargs):
        super(BaseYaraASScanner, self).__init__(**kwargs)
        self.rules = rules
        self.hits = []
        self.base_offset = None

    def _match_rules(self, buffer_as):
        """Compatibility for yara modules.

        Unfortunately there are two different implementations of the yara python
        bindings:

        # The original upstream source.
        http://plusvic.github.io/yara/

        # The version which is installed using pip install.
        https://github.com/mjdorma/yara-ctypes

        These do not work the same and so we need to support both.

        Yields:
          a tuple of (offset, rule_name, name, value)
        """
        matches = self.rules.match(data=buffer_as.data)
        # yara-cpython bindings from pip.
        if type(matches) is dict:
            for _, matches in matches.items():
                for match in matches:
                    for string in match["strings"]:
                        hit_offset = string["offset"] + buffer_as.base_offset

                        yield (match["rule"], hit_offset,
                               string["identifier"], string["data"])

        else:
            # native bindings from http://plusvic.github.io/yara/
            for match in matches:
                for buffer_offset, name, value in match.strings:
                    hit_offset = buffer_offset + buffer_as.base_offset
                    yield (match.rule, hit_offset, name, value)

    def check_addr(self, scan_offset, buffer_as=None):
        # The buffer was changed - we scan the entire buffer and record the
        # hits - then we can feed it to the Rekall scan framework.
        if self.base_offset != buffer_as.base_offset:
            self.base_offset = buffer_as.base_offset
            self.hits = []

            for rule, offset, name, value in self._match_rules(buffer_as):
                self.hits.append((rule, offset, name, value))

        if self.hits and scan_offset == self.hits[0][1]:
            return self.hits.pop(0)

    def skip(self, buffer_as, offset):
        # Skip the entire buffer.
        if not self.hits:
            return len(buffer_as.data)

        next_hit = self.hits[0][1]
        return next_hit - offset
