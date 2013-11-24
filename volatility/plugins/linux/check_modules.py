# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General
# Public License.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0
@contact:      atcuno@gmail.com
@organization:
"""

from volatility import args
from volatility.plugins.linux import common


class CheckModules(common.LinuxPlugin):
    """Compares module list to sysfs info, if available."""

    __name = "check_modules"

    @classmethod
    def is_active(cls, config):
        if super(CheckModules, cls).is_active(config):
            return config.profile.get_constant("module_kset")

    def get_kset_modules(self):
        module_kset = self.profile.get_constant_object(
            "module_kset", target="kset", vm=self.kernel_address_space)

        for kobj in module_kset.list.list_of_type("kobject", "entry"):
            if kobj.name and kobj.kref.refcount.counter > 2:
                yield kobj

    def render(self, renderer):
        renderer.table_header([("Module Name", "module", "")])
        lsmod = self.session.plugins.lsmod(session=self.session)
        module_names = set([m.name for m in lsmod.get_module_list()])

        for kobj in self.get_kset_modules():
            name = kobj.name.deref()

            if name not in module_names:
                renderer.table_row(name)

