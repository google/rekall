#!/usr/bin/python

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

"""Inspect the privileges in each process's tokens.

These sets of plugins are designed around the blog post "Windows Access Tokens -
!token and _TOKEN"::
https://bsodtutorials.wordpress.com/2014/08/09/windows-access-tokens-token-and-_token/
"""

__author__ = "Michael Cohen <scudette@gmail.com>"

from rekall import plugin
from rekall.plugins.windows import common


class PrivilegesHook(common.AbstractWindowsParameterHook):
    """Fetch the PrivilegesHook table.

    In Windows, privilege values are not constant, they are actually stored in
    kernel globals. We can see this kind of privilege check:

    0xf800027b4e10 mov rcx, qword ptr [rip + 0x3a42a1] 0x7 nt!SeTcbPrivilege
    0xf800027b4e17 call 0xf80002956a58                 nt!SeSinglePrivilegeCheck

    Demonstrating that the kernel reads the values in these locations (i.e. they
    are not hard coded). Although in reality they are never changed in runtime
    and probably do not really change between systems or versions.

    This hook collects these values from the image.
    """
    name = "privilege_table"

    def calculate(self):
        result = {}
        for symbol in self.session.address_resolver.search_symbol(
                "nt!Se*Privilege"):

            value = self.session.address_resolver.get_constant_object(
                symbol, "unsigned int")

            if value != None and value < 100:
                result[int(value)] = symbol.split("!")[-1]

        return result


class Privileges(common.WinProcessFilter):
    """Prints process privileges."""

    name = "privileges"

    table_header = [
        dict(name="Process", type="_EPROCESS"),
        dict(name="Value", width=3, align="r"),
        dict(name="Privileges", width=40),
        dict(name="Attributes", type="list")
    ]

    def collect(self):
        privilege_table = self.session.GetParameter("privilege_table")

        for task in self.filter_processes():
            for value, flags in task.Token.GetPrivileges():
                # By default skip the privileges that are not present.
                if self.plugin_args.verbosity <= 1 and "Present" not in flags:
                    continue

                yield (task,
                       value,
                       privilege_table.get(value),
                       flags)
