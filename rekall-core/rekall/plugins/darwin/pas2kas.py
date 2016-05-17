# Rekall Memory Forensics
#
# Copyright 2015 Google Inc. All Rights Reserved.
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

# pylint: disable=protected-access

from rekall.plugins.common import pas2kas
from rekall.plugins.darwin import common


class DarwinPas2Vas(pas2kas.Pas2VasMixin, common.ProcessFilterMixin,
                    common.AbstractDarwinCommand):
    """Resolves a physical address to a virtual addrress in a process."""


class DarwinPas2VasResolver(pas2kas.Pas2VasResolver):
    def GetTaskStruct(self, addrress):
        return self.session.profile.proc(addrress)


class DarwinPas2VasResolverHook(common.AbstractDarwinParameterHook):
    """Provide the Pas2Vas resolver."""

    name = "physical_address_resolver"

    def calculate(self):
        return DarwinPas2VasResolver(session=self.session)
