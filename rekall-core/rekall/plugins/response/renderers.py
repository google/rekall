# Rekall Memory Forensics
# Copyright 2016 Google Inc. All Rights Reserved.
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

__author__ = "Michael Cohen <scudette@google.com>"


from rekall import utils
from rekall.ui import text
from rekall.plugins.renderers import data_export


class FileSpec_Text(text.TextObjectRenderer):
    renders_type = "FileSpec"

    def render_row(self, target, width=None, **_):
        if target.filesystem == "API":
            return text.Cell(unicode(target.name), width=width)

        else:
            return text.Cell(u"%s (%s)" % (target.name, target.filesystem),
                             width=width)


class FileInformation_TextObjectRenderer(text.TextObjectRenderer):
    renders_type = "FileInformation"

    def render_row(self, target, **options):
        return FileSpec_Text(
            renderer=self.renderer, session=self.session).render_row(
                target.filename, **options)


class UserTextObjectRenderer(text.TextObjectRenderer):
    renders_type = "User"

    def render_row(self, item, **_):
        if item.username:
            return text.Cell(u"%s (%s)" % (item.username, item.uid))
        return text.Cell(unicode(item.uid))


class DataExportFileSpecObjectRenderer(
        data_export.DataExportBaseObjectRenderer):
    renders_type = "FileSpec"

    def Summary(self, item, **_):
        return utils.SmartStr(item)

    def GetState(self, item, **options):
        return dict(filesystem=item.filesystem, name=item.name)


class PermissionsFileSpecObjectRenderer(
        data_export.DataExportBaseObjectRenderer):
    renders_type = "Permissions"

    def Summary(self, item, **_):
        return utils.SmartStr(item)

    def GetState(self, item, **options):
        return dict(perm=str(item), int_perm=int(item))
