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
import linux_common, linux_flags
import sys, os

class linux_aufs(linux_common.AbstractLinuxCommand):

    ''' gathers information about aufs '''

    def __init__(self, config, *args):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args)
        self._config.add_option('TARGET_DIR', short_option = 'D', default = None, help = 'filter output for aufs directory listing', action = 'store', type = 'str')
        self._config.add_option('EVIDENCE_DIR', short_option = 'o', default = None, help = 'output directory for recovered files', action = 'store', type = 'str')

        # used to keep correct time for directories
        self.dir_times = {}

    def get_aufs_sb(self):

        sbptr = obj.Object("Pointer", offset = self.smap["super_blocks"], vm = self.addr_space)

        sb_list = obj.Object("list_head", offset = sbptr.v(), vm = self.addr_space)

        for sb in linux_common.walk_list_head("super_block", "s_list", sb_list, self.addr_space):
       
            if sb.s_id.startswith("aufs"):
                return sb.s_root

        # TODO - raise ERROR
        print "Unable to find aufs superblock for memory image"
        sys.exit(1)

    def get_h_dentry(self, dentry, index):

        index = 0

        dinfo = obj.Object("au_dinfo", offset=dentry.d_fsdata, vm=self.addr_space)

        #if not dinfo:
        #    print "null dinfo??"

        # get the hidden directory entry
        dentry_array = obj.Object(theType="Array", offset=dinfo.di_hdentry, vm=self.addr_space, targetType="au_hdentry", count=2)
        h_dentry = dentry_array[index].hd_dentry

        return h_dentry

    def SHMEM_I(self, inode):
    
        structsize = linux_common.sizeofstruct("shmem_inode_info", self.profile)
        myoffset   = linux_common.offsetof("shmem_inode_info", "vfs_inode", self.profile) 
        
        addr = inode - structsize + (structsize - myoffset)

        return obj.Object("shmem_inode_info", offset=addr, vm=self.addr_space)
 

    def process_entry(self, h_dentry, tab_level, dir_hash):
        pass
      
    # fix metadata for new files
    def fix_md(self, new_file, perms, atime, mtime, isdir=0):

        atime = atime.tv_sec + 18000
        mtime = mtime.tv_sec + 18000

        if isdir:
            self.dir_times[new_file] = (atime, mtime)
        else:
            os.utime(new_file, (atime, mtime))

        os.chmod(new_file, perms)

    def au_ii(self, inode):

        offset = linux_common.offsetof("au_icntnr", "vfs_inode", self.addr_space.profile)   

        aui = obj.Object("au_iinfo", offset=inode - offset, vm=self.addr_space)

        return aui 

    def au_h_iptr(self, inode, index):

        au = self.au_ii(inode)

        if au:
            inode_array = obj.Object(theType="Array", offset=au.ii_hinode, vm=self.addr_space, targetType="au_hinode", count=2)
            off = inode_array[0 + index].hi_inode 
            ret = obj.Object("inode", offset=off, vm=self.addr_space)
        
        else:
            ret = None
        
        return ret

    def process_directory(self, h_dentry, recursive=0, parent=""):

        dname = linux_common.get_string(h_dentry.d_name.name, self.addr_space)
        #print "------>processing %s" % dname
 
        if recursive:
            h_dentry  = self.get_h_dentry(h_dentry, 0)

        if not h_dentry:
            dname = linux_common.get_string(h_dentry.d_name.name, self.addr_space)
            #print "no h_dentry for %s" % dname
            return

        for dentry in linux_common.walk_list_head("dentry", "d_u", h_dentry.d_subdirs, self.addr_space):

            name = linux_common.get_string(dentry.d_name.name, self.addr_space)
            #print "name: %s" % name

            inode = dentry.d_inode
            
            #inode = self.au_h_iptr(inode, 0)
 
            if inode:
                #sinfo = self.SHMEM_I(inode) 
                               
                new_file = os.path.join(parent, name)
              
                (perms, size, atime, mtime) = (inode.i_mode, inode.i_size, inode.i_atime, inode.i_mtime)
 
                if linux_common.S_ISDIR(inode.i_mode):
                    #print "Directory: %s" % name
                    # since the directory may already exist
                    try:
                        os.mkdir(new_file)
                    except:
                        pass
                    self.fix_md(new_file, perms, atime, mtime, 1)
                    self.process_directory(dentry, 1, new_file)
                    
                elif linux_common.S_ISREG(inode.i_mode):
        
                    #contents = self.get_file_contents(inode)

                    f = open(new_file, "w")
                    f.write(' ' * inode.i_size)
                    f.close()
                    self.fix_md(new_file, perms, atime, mtime)

                # TODO add support for symlinks
                else:
                    pass
                    #print "skipped: %s" % name
            else:
                pass
                #print "no inode for %s" % name


    def calculate(self):

        root_dentry = self.get_aufs_sb()

        for dentry in linux_common.walk_list_head("dentry", "d_u", root_dentry.d_subdirs, self.addr_space):

            h_dentry = self.get_h_dentry(dentry, 0)

            name = linux_common.get_string(h_dentry.d_name.name, self.addr_space)

            #print "name: %s" % name

            if not h_dentry:
                #print "no h_dentry"
                continue
              
            hinode = h_dentry.d_inode

            if not hinode:
                #print "no hinode"
                continue

            if linux_common.S_ISDIR(hinode.i_mode):
                
                if not self._config.TARGET_DIR or name == self._config.TARGET_DIR:
                    edir = self._config.EVIDENCE_DIR
                    if len(edir) == 0:
                        print "Bad edir"
                        sys.exit(1)

                    edir = os.path.join(edir, name)
                    
                    os.mkdir(edir)

                    self.process_directory(dentry, parent=edir)

            elif linux_common.S_ISREG(hinode.i_mode):
                #print "file: %s" % name 
                pass
            else:
                #print "other: %s" % name
                pass

        
        # post processing
        for new_file in self.dir_times:
            (atime, mtime) = self.dir_times[new_file]

            os.utime(new_file, (atime, mtime))

    def render_text(self, outfd, data):

        pass

    def get_file_contents(self, inode):

        ppos = 0
        PAGE_SHIFT = 12
        PAGE_MASK = 0xfffff000

        i_size = inode.i_size
        index  = ppos >> PAGE_SHIFT
        offset = ppos & ~PAGE_MASK
        end_index = i_size >> PAGE_SHIFT

        root = obj.Object("radix_tree_root", offset=inode.i_mapping.page_tree.obj_offset, vm=self.addr_space)

        #pageaddr = self.radix_tree_lookup(root, index)

        pageaddr = 0xc09c61a0
        print "first page %d %x" % (pageaddr, pageaddr)
        
        #pageaddr = obj.Object("unsigned long", offset=pageaddr, vm=self.addr_space)

        #print "pre page %d %x" % (pageaddr, pageaddr)

        diff = (pageaddr - self.smap["mem_map"]) / 0x24

        print "diff: pageaddr %d %x | %d %x" % (pageaddr, pageaddr, diff, diff)

        physaddr = (diff << 12) & 0xffffffff

        print "physaddr %d %x" % (physaddr, physaddr)

        buf = self.addr_space.read(physaddr, 16)

        for b in buf:
            print "%x " % ord(b),
        print ""

        
        '''
        page = obj.Object("page", offset=pageaddr, vm=self.addr_space)

        # fix when anon unions are fixed
        mapcount = obj.Object("unsigned long", offset=pageaddr+8, vm=self.addr_space) 

        # if its mapped
        if mapcount >= 0:
       
            print "is mapped: %d %x" % (mapcount, mapcount)
        '''
             
            

        sys.exit(1) 
        return "" 
 
    # root = radix_tree_root
    def radix_tree_lookup(self, root, index):

        return self.radix_tree_lookup_element(root, index, 1)

    def radix_tree_lookup_element(self, root, index, is_slot):

        node = obj.Object("radix_tree_node", offset=root.rnode.v(), vm=self.addr_space)

        if not node:
            print "no node.."
            return None

        if not self.radix_tree_is_indirect_ptr(node):
            
            if index > 0:
                print "> 0"
                return None

            elif is_slot:
                ret1 = root.obj_offset + linux_common.offsetof("radix_tree_root", "rnode", self.addr_space.profile) 
                ret = root.rnode
                print "is_slit root: %x %x" % (ret1, ret)
                return ret1
            
            else:
                print "Ret node"
                return node
                
        node = self.radix_tree_indirect_to_ptr(node)

        height = node.height

        print "height %d" % height

        if index > self.radix_tree_maxindex(index, height):
            print "index %d is too big" % index
            return None

        shift = (height - 1) * 6
                    
        while 1:
            
            print "index %d shift %d" % (index, shift)

            idx = (index>>shift & 0x3f) & 0xff

            print "loop: %d" % idx

            slot = node.slots[idx]

            node = obj.Object("radix_tree_node", offset=slot.dereference(), vm=self.addr_space)

            if not node:
                return None

            shift = shift - 6

            height = height - 1

            if height == 0:
                break

        if is_slot:
            ret = slot
        else:
            ret = node

        print "returning %s" % str(ret)

    def radix_tree_maxindex(self, index, height):

        height_to_maxindex = obj.Object(theType="Array", targetType="unsigned long", count=7, offset=self.smap["height_to_maxindex"], vm=self.addr_space)

        return height_to_maxindex[height]

    def radix_tree_is_indirect_ptr(self, node):
        
        print "check indirect: %d %d %d" % (node.v(), node.obj_offset, node.dereference())
        ret = node.v() & 1
        print "is indirect: %d" % ret
        return ret

    def radix_tree_indirect_to_ptr(self, node):

        return obj.Object("radix_tree_node", offset=(node.v() & ~1) & 0xffffffff, vm=self.addr_space)













