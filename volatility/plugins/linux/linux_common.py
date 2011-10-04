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

import volatility.commands as commands
import volatility.utils    as utils
import volatility.obj      as obj
from volatility import profile


def mask_number(num):
    return num & 0xffffffff


class AbstractLinuxCommand(commands.command):

    def __init__(self, *args, **kwargs):
        commands.command.__init__(self, *args, **kwargs)
        self.addr_space = utils.load_as(self._config)
        self.profile = self.addr_space.profile
        vmagic = obj.Object('VOLATILITY_MAGIC', vm = self.addr_space, offset = 0x00)
        self.smap = vmagic.SystemMap.v()

    @classmethod
    def is_active(cls, config):
        """We are only active if the profile is windows."""
        try:
            p = profile.get_profile_class(config)
            return p._md_os == 'linux'
        except profile.Error:
            return True


def sizeofstruct(struct_name, profile):

    return profile.typeDict[struct_name][0]

def offsetof(struct_name, list_member, profile):

    offset = profile.typeDict[struct_name][1][list_member][0]
    return offset

def bit_is_set(bmap, pos):

    mask = 1 << pos
    return bmap & mask
    
# returns a list of online cpus (the processor numbers)
def online_cpus(smap, addr_space):

    #later kernels..
    if "cpu_online_bits" in smap:
        bmap = obj.Object("unsigned long", offset=smap["cpu_online_bits"], vm=addr_space)

    elif "cpu_present_map" in smap:
        bmap = obj.Object("unsigned long",  offset=smap["cpu_present_map"], vm=addr_space)

    else:
        raise AttributeError, "Unable to determine number of online CPUs for memory capture"

    cpus = []
    for i in xrange(0, 8):
        if bit_is_set(bmap, i):
            cpus.append(i)
            
    return cpus    

def walk_per_cpu_var(obj_ref, per_var, var_type):
        
    cpus = online_cpus(obj_ref.smap, obj_ref.addr_space)
    
    # get the highest numbered cpu
    max_cpu = cpus[-1]
 
    per_offsets = obj.Object(theType='Array', targetType='unsigned long', count=max_cpu, offset=obj_ref.smap["__per_cpu_offset"], vm=obj_ref.addr_space)
    i = 0

    for i in cpus:
           
        offset = per_offsets[i]

        addr = obj_ref.smap["per_cpu__" + per_var] + offset.v()
        var = obj.Object(var_type, offset=addr, vm=obj_ref.addr_space)

        yield i, var
 
 

# similar to for_each_process for this usage
def walk_list_head(struct_name, list_member, list_head_ptr, addr_space):

    list_ptr = list_head_ptr.next
    offset = offsetof(struct_name, list_member, addr_space.profile)

    # this happens in rare instances where list_heads get pre-initlized
    # the caller needs to check for not return value
    # currently only needed by linux_mount when walking mount_hashtable
    if list_ptr == list_head_ptr or not list_ptr:
        return

    while 1:

        # return the address of the beginning of the strucutre, similar to list.h in kernel
        yield obj.Object(struct_name, offset = list_ptr - offset, vm = addr_space)

        list_ptr = list_ptr.next

        if list_ptr == list_head_ptr or not list_ptr:
            break


def walk_internal_list(struct_name, list_member, list_start, addr_space):

    while 1:

        list_struct = obj.Object(struct_name, vm = addr_space, offset = list_start)

        yield list_struct

        list_start = list_struct.__getattribute__(list_member)
        
        if not list_start:
            break

def get_string(addr, addr_space, maxlen = 256):

    name = addr_space.read(addr, maxlen)
    ret = ""

    for n in name:
        if ord(n) == 0:
            break
        ret = ret + n

    return ret


def format_path(path_list):

    path = '/'.join(path_list)

    return path

def IS_ROOT(dentry):

    return dentry == dentry.d_parent

# based on __d_path
# TODO: (deleted) support
def do_get_path(rdentry, rmnt, dentry, vfsmnt, addr_space):
    ret_path = []

    inode = dentry.d_inode

    while 1:

        dname = get_string(dentry.d_name.name, addr_space)

        if dname != '/':
            ret_path.append(dname)

        if dentry == rdentry and vfsmnt == rmnt:
            break

        if dentry == vfsmnt.mnt_root or IS_ROOT(dentry):
            if vfsmnt.mnt_parent == vfsmnt:
                break
            dentry = vfsmnt.mnt_mountpoint
            vfsmnt = vfsmnt.mnt_parent
            continue

        parent = dentry.d_parent

        dentry = parent

    ret_path.reverse()

    ret_val = format_path(ret_path)

    if ret_val.startswith(("socket:", "pipe:")):
        if ret_val.find("]") == -1:
            ret_val = ret_val[:-1] + "[{0}]".format(inode.i_ino)
        else:
            ret_val = ret_val.replace("/","")

    elif ret_val != "inotify":
        ret_val = '/' + ret_val

    return ret_val

def get_path(task, filp, addr_space):

    rdentry  = task.fs.get_root_dentry()
    rmnt     = task.fs.get_root_mnt()
    dentry = filp.get_dentry()
    vfsmnt = filp.get_vfsmnt()

    return do_get_path(rdentry, rmnt, dentry, vfsmnt, addr_space)

# this is here b/c python is retarded and its inet_ntoa can't handle integers...
def ip2str(ip):

    a = ip & 0xff
    b = (ip >> 8) & 0xff
    c = (ip >> 16) & 0xff
    d = (ip >> 24) & 0xff

    return "%d.%d.%d.%d" % (a, b, c, d)

def ip62str(in6addr):

    ret     = ""
    ipbytes = in6addr.in6_u.u6_addr8
    ctr     = 0

    for byte in ipbytes:
        ret = ret + "%.02x" % byte
                
        # make it the : notation
        if ctr % 2 and ctr != 15:
            ret = ret + ":"

        ctr = ctr + 1

    return ret          
