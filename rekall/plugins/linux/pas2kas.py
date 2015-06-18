# Rekall Memory Forensics
#
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Authors:
# Michael Cohen <scudette@users.sourceforge.net>
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
from rekall.plugins.common import pas2kas
from rekall.plugins.linux import common


class LinPas2Vas(pas2kas.Pas2VasMixin, common.LinProcessFilter):
    """Resolves a physical address to a virtual addrress in a process."""


class LinPas2VasResolver(pas2kas.Pas2VasResolver):
    def GetTaskStruct(self, address):
        return self.session.profile.task_struct(address)


class LinPas2VasResolverHook(common.AbstractLinuxParameterHook):
    """Provide the Pas2Vas resolver."""

    name = "physical_address_resolver"

    def calculate(self):
        return LinPas2VasResolver(session=self.session)
