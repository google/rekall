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
import re

from rekall.plugins.windows import common


class Win32kAutodetect(common.WindowsCommandPlugin):
    """Automatically detect win32k struct layout."""

    name = "win32k_autodetect"

    table_header = [
        dict(name="divider", type="Divider"),
        dict(name="field", width=20),
        dict(name="offset", style="address"),
        dict(name="definition")
    ]


    def collect(self):
        win32k_module = self.session.address_resolver.GetModuleByName(
            "win32k")
        win32k_profile = win32k_module.profile

        overlay = self.GetWin32kOverlay(win32k_profile)

        for struct, definition in overlay.items():
            yield dict(divider="Struct %s" % struct)

            for field, (offset, field_def) in sorted(definition[1].items(),
                                                     key=lambda x: x[1]):
                yield dict(field=field, offset=offset,
                           definition=str(field_def))

    def GetWin32kOverlay(self, win32k_profile):
        # Make a temporary profile to work with.
        self.temp_profile = win32k_profile
        self.analyze_struct = self.session.plugins.analyze_struct(0)

        # Start off with an empty overlay.
        overlay = dict(tagDESKTOP=[None, {}],
                       tagWINDOWSTATION=[None, {}],
                       tagTHREADINFO=[None, {}],
                      )

        with self.session.plugins.cc() as cc:
            for task in self.session.plugins.pslist().filter_processes():
                cc.SwitchProcessContext(task)

                # Find a process context which makes the symbol valid.
                if not self.wndstation():
                    continue

                try:
                    self.Get_tagWINDOWSTATION_overlay(overlay)
                    self.Get_tagDESKTOP_overlay(overlay)
                    self.Get_tagTHREADINFO_overlay(overlay)

                    return overlay
                except RuntimeError:
                    continue

        return overlay

    def wndstation(self):
        return self.temp_profile.get_constant_object(
            "grpWinStaList",
            target="Pointer",
            target_args=dict(
                target="tagWINDOWSTATION")
            ).deref()

    def _Match(self, regex, info):
        for item in info:
            if re.match(regex, item):
                return True

    def _AddField(self, regex, info, field_name, fields, description):
        if field_name not in fields and self._Match(regex, info):
            fields[field_name] = description
            self.session.logging.debug(
                "Detected field %s: %s @ %#x", field_name, info, description[0])
            return True

    def Get_tagWINDOWSTATION_overlay(self, overlay):
        """Derive the tagWINDOWSTATION overlay."""
        fields = {}
        offset = self.wndstation()

        required_fields = set([
            "rpwinstaNext", "rpdeskList", "pGlobalAtomTable"])

        stations = set()

        while not offset == None and offset not in stations:
            stations.add(offset)

            self.session.logging.debug("Checking tagWINDOWSTATION at %#x",
                                       offset)
            for o, info in self.analyze_struct.GuessMembers(offset, size=0x200):
                if self._AddField(
                        "Tag:Win", info, "rpwinstaNext", fields,
                        [o, ["Pointer", dict(
                            target="tagWINDOWSTATION"
                        )]]):
                    continue

                elif self._AddField(
                        "Tag:Des", info, "rpdeskList", fields,
                        [o, ["Pointer", dict(
                            target="tagDESKTOP"
                        )]]):
                    continue

                elif self._AddField(
                        "Tag:AtmT", info, "pGlobalAtomTable", fields,
                        [o, ["Pointer", dict(
                            target="_RTL_ATOM_TABLE"
                        )]]):
                    continue

                elif self._AddField(
                        "Const:win32k!gTerm", info, "pTerm", fields,
                        [o, ["Pointer", dict(
                            target="tagTERMINAL"
                        )]]):
                    continue

                else:
                    self.session.logging.debug(
                        "Unhandled field %#x, %s" % (o, info))
                    continue

                # Add the derived overlay to the profile so we can walk the list
                # of window stations.
                self.temp_profile.add_overlay(overlay)

            offset = self.temp_profile.tagWINDOWSTATION(offset).rpwinstaNext

            # We worked out all the fields, return the overlay.
            if required_fields.issubset(fields):
                overlay["tagWINDOWSTATION"][1].update(fields)
                return overlay

            self.session.logging.debug(
                "tagWINDOWSTATION: Missing required fields %s",
                required_fields.difference(fields))

        raise RuntimeError("Unable to guess tagWINDOWSTATION")

    def Get_tagDESKTOP_overlay(self, overlay):
        fields = {}
        required_fields = set([
            "rpdeskNext", "rpwinstaParent", "hsectionDesktop"])

        # Iterate over all tagDESKTOP objects.
        desktops = set()

        offset = self.wndstation().rpdeskList.v()

        while not offset == None and offset not in desktops:
            self.session.logging.debug("Checking tagDESKTOP at %#x", offset)
            desktops.add(offset)

            for o, info in self.analyze_struct.GuessMembers(
                    offset, search=0x400):

                if self._AddField("Tag:Des", info, "rpdeskNext", fields,
                                  [o, ["Pointer", dict(
                                      target="tagDESKTOP"
                                      )]]):
                    continue

                elif self._AddField("Tag:Win", info, "rpwinstaParent", fields,
                                    [o, ["Pointer", dict(
                                        target="tagWINDOWSTATION"
                                        )]]):
                    continue

                elif self._AddField("Tag:Sec", info, "hsectionDesktop", fields,
                                    [o, ["Pointer", dict(
                                        target="_SECTION_OBJECT"
                                        )]]):
                    continue

                # The PtiList is a _LIST_ENTRY to a tagTHREADINFO (Usti tag).
                elif ("_LIST_ENTRY" in info and
                      self._AddField("Tag:Usti", info, "PtiList", fields,
                                     [o, ["_LIST_ENTRY"]])):
                    continue

                # On WinXP a tagTHREADINFO allocation contains ProcessBilled.
                elif ("_LIST_ENTRY" in info and not self._Match("Tag:", info)
                      and self._AddField(
                          "ProcessBilled:", info, "PtiList", fields,
                          [o, ["_LIST_ENTRY"]])):
                    continue

                else:
                    self.session.logging.debug(
                        "Unhandled field %#x %s" % (o, info))
                    continue

            # Add the derived overlay to the profile so we can walk the list
            # of window stations.
            self.temp_profile.add_overlay(overlay)

            offset = self.temp_profile.tagDESKTOP(offset).rpdeskNext

            # We worked out all the fields, return the overlay.
            if required_fields.issubset(fields):
                overlay["tagDESKTOP"][1].update(fields)
                return overlay

            self.session.logging.debug(
                "tagDESKTOP: Missing required fields %s",
                required_fields.difference(fields))

        raise RuntimeError("Unable to guess tagDESKTOP")

    def _Check_tagPROCESSINFO(self, offset):
        """Checks if a pointer points to tagPROCESSINFO."""
        pointer = self.profile.Pointer(offset)
        pool = self.analyze_struct.SearchForPoolHeader(pointer.v())
        if pool.Tag == "Uspi":
            return True

        # Its definitely not a tagPROCESSINFO if it is a tagTHREADINFO.
        if pool.Tag in ["Usti"]:
            return False

        # In windows XP tagPROCESSINFO allocations contain the _EPROCESS
        # address in the ProcessBilled field of the allocation.
        if pool.m("ProcessBilled").Peb:
            return True

        return False

    def _AnalyzeTagTHREADINFO(self, offset, fields):
        self.session.logging.debug("Checking tagTHREADINFO at %#x", offset)
        for o, info in self.analyze_struct.GuessMembers(
                offset, size=0x400, search=0x600):

            if self._AddField("Tag:Thr", info, "pEThread", fields,
                              [o, ["Pointer", dict(
                                  target="_ETHREAD"
                                  )]]):
                continue

            elif self._AddField("Tag:Usqu", info, "pq", fields,
                                [o, ["Pointer", dict(
                                    target="tagQ"
                                    )]]):
                continue

            elif self._AddField("Tag:Uskb", info, "spklActive", fields,
                                [o, ["Pointer", dict(
                                    target="tagKL"
                                    )]]):
                continue

            elif self._AddField("Tag:Des", info, "rpdesk", fields,
                                [o, ["Pointer", dict(
                                    target="tagDESKTOP"
                                    )]]):
                continue

            elif ("_LIST_ENTRY" in info and
                  self._AddField("Tag:Usti", info, "GdiTmpTgoList", fields,
                                 [o, ["_LIST_ENTRY"]])):
                continue

            elif (self._Check_tagPROCESSINFO(offset + o) and
                  self._AddField(".", info, "ppi", fields,
                                 [o, ["Pointer", dict(
                                     target="tagPROCESSINFO"
                                     )]])):
                continue

            else:
                self.session.logging.debug("Unhandled field %#x %s" % (o, info))
                continue

    def Get_tagTHREADINFO_overlay(self, overlay):
        fields = {}
        required_fields = set([
            "pEThread", "pq", "spklActive", "rpdesk", "PtiLink", "ppi"
            ])

        # Iterate over all tagTHREADINFO objects.
        thread_infos = set()
        for wndstation in self.wndstation().rpwinstaNext.walk_list(
                "rpwinstaNext"):
            for desktop in wndstation.rpdeskList.walk_list("rpdeskNext"):
                thread_info_pool = self.analyze_struct.SearchForPoolHeader(
                    desktop.PtiList.Flink.v(), search=0x600)

                if thread_info_pool and thread_info_pool not in thread_infos:
                    thread_infos.add(thread_info_pool)

                    # We can already determine the tagTHREADINFO's PtiLink:
                    PtiLink_offset = (desktop.PtiList.Flink.v() -
                                      thread_info_pool.obj_end)
                    fields["PtiLink"] = [PtiLink_offset, ["_LIST_ENTRY"]]

                    self._AnalyzeTagTHREADINFO(thread_info_pool.obj_end, fields)
                    self.temp_profile.add_overlay(overlay)

                # We worked out all the fields, return the overlay.
                if required_fields.issubset(fields):
                    overlay["tagTHREADINFO"][1].update(fields)
                    return overlay

                self.session.logging.debug(
                    "tagTHREADINFO: Missing required fields %s",
                    required_fields.difference(fields))

        raise RuntimeError("Unable to guess tagTHREADINFO")
