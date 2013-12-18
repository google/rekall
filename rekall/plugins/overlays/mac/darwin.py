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

__author__ = "Michael Cohen <scudette@gmail.com>"

"""Implement OSX support."""


from rekall import obj
from rekall.plugins.overlays import basic

darwin_overlay = {

    }


class Darwin32(basic.Profile32Bits, basic.BasicWindowsClasses):
    """A Darwin profile."""
    _md_os = "darwin"
    _md_memory_model = "32bit"
    _md_type = "Kernel"

    def __init__(self, **kwargs):
        super(Darwin32, self).__init__(**kwargs)
        self.add_classes(dict(
                ))
        self.add_overlay(darwin_overlay)
        self.add_constants(default_text_encoding="utf8")

class Darwin64(basic.ProfileLP64, Darwin32):
    """Support for 64 bit darwin systems."""
