# Volatility
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

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0 or later
@contact:      atcuno@gmail.com
@organization: Digital Forensics Solutions
"""

import volatility.obj as obj
import linux_common
import linux_task_list_ps as ltps

mn = linux_common.mask_number

class linux_list_open_files(ltps.linux_task_list_ps):

    ''' lists open files '''

    def calculate(self):
        tasks = ltps.linux_task_list_ps.calculate(self)

        for task in tasks:

            fds     = task.files.get_fds()
            max_fds = task.files.get_max_fds()

            fds = obj.Object(theType = 'Array', offset = fds.obj_offset, vm = self.addr_space, targetType = 'Pointer', count = max_fds)

            for i in xrange(0, max_fds):

                if fds[i]:
                    filp = obj.Object('file', offset = fds[i], vm = self.addr_space)

                    yield (task, filp, i, self.addr_space)

    def render_text(self, outfd, data):
        for (task, filp, fd, _addr_space) in data:
            outfd.write("{0:5d} -> {1:s}\n".format(fd, linux_common.get_path(task, filp, self.addr_space)))
