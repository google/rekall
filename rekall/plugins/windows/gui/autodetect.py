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

"""Autodetect struct layout of various Win32k GUI structs.

Many win32k structs are undocumented (i.e. are not present in pdb
symbols). These structures do change a lot between versions of windows. This
module autodetects the struct layout using various heuristics.
"""
import logging
from rekall import kb


class Win32kStructs(kb.ParameterHook):
    """Return vtype definitions for various win32k structs."""

    name = "win32k_structs"

    def calculate(self):
        self.analyze_struct = self.session.plugins.analyze_struct()
        profile = self.session.address_resolver.LoadProfileForName("win32k")
        self.profile = profile.copy()
        overlay = dict(tagDESKTOP=[None, {}],
                       tagWINDOWSTATION=[None, {}])

        self.profile.add_types(overlay)
        self.Get_tagWINDOWSTATION_overlay(overlay, self.wndstation())
        self.profile.add_types(overlay)

        for x in self.wndstation().walk_list("rpwinstaNext"):
            self.Get_tagWINDOWSTATION_overlay(overlay, x)
            self.Get_tagDESKTOP_overlay(overlay, x.rpdeskList)

        self.profile.add_types(overlay)

        for w in self.wndstation().walk_list("rpwinstaNext"):
            for d in w.rpdeskList.walk_list("rpdeskNext"):
                self.Get_tagDESKTOP_overlay(overlay, d)

        return overlay

    def wndstation(self):
        return self.profile.get_constant_object(
            "grpWinStaList",
            target="Pointer",
            target_args=dict(
                target="tagWINDOWSTATION")
            ).deref()

    def Get_tagWINDOWSTATION_overlay(self, overlay, offset):
        """Derive the tagWINDOWSTATION overlay."""
        overlay.setdefault("tagWINDOWSTATION", [None, {}])
        fields = overlay["tagWINDOWSTATION"][1]

        logging.debug("Checking tagWINDOWSTATION at %#x", offset)
        for o, info in self.analyze_struct.GuessMembers(offset, size=0x400):
            if "Tag:Wind" in info or "Tag:Win\xe4" in info:
                fields["rpwinstaNext"] = [o, ["Pointer", dict(
                    target="tagWINDOWSTATION"
                    )]]

            elif "Tag:Desk" in info or "Tag:Des\xeb" in info:
                fields["rpdeskList"] = [o, ["Pointer", dict(
                    target="tagDESKTOP"
                    )]]

            elif "Tag:AtmT" in info:
                fields["pGlobalAtomTable"] = [o, ["Pointer", dict(
                    target="_RTL_ATOM_TABLE"
                    )]]

            else:
                logging.debug("Unhandled field %s" % (info,))

    def Get_tagDESKTOP_overlay(self, overlay, offset):
        overlay.setdefault("tagDESKTOP", [None, {}])
        fields = overlay["tagDESKTOP"][1]

        logging.debug("Checking tagDESKTOP at %#x", offset)
        for o, info in self.analyze_struct.GuessMembers(offset, size=0x400):
            if "Tag:Desk" in info or "Tag:Des\xeb" in info:
                fields["rpdeskNext"] = [o, ["Pointer", dict(
                    target="tagDESKTOP"
                    )]]

            elif "Tag:Wind" in info or "Tag:Win\xe4" in info:
                fields["rpwinstaParent"] = [o, ["Pointer", dict(
                    target="tagWINDOWSTATION"
                    )]]

            elif "Tag:Sect" in info:
                fields["hsectionDesktop"] = [o, ["Pointer", dict(
                    target="_SECTION_OBJECT"
                    )]]

            elif "_LIST_ENTRY" in info:
                fields["PtiList"] = [o, ["_LIST_ENTRY"]]

            else:
                logging.debug("Unhandled field %s" % (info,))
