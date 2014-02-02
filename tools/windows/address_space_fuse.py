# Rekall Memory Forensic Framework.
#
# Authors: Michael Cohen <scudette@gmail.com>
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

"""This program mounts an image as a fuse filesystem so each process's address
space is available for inspection via e.g. a hex editor.
"""
import re
import os
import stat
import sys

from rekall import session
from rekall import plugins
from errno import *

# pull in some spaghetti to make this stuff work without fuse-py being installed
try:
    import _find_fuse_parts
except ImportError:
    pass
import fuse
from fuse import Fuse

if not hasattr(fuse, '__version__'):
    raise RuntimeError, \
        "your fuse-py doesn't know of fuse.__version__, probably it's too old."

fuse.fuse_python_api = (0, 2)

fuse.feature_assert('stateful_files', 'has_init')


def make_stat(pid):
    """ Return a stat structure from TSK metadata struct """

    s = fuse.Stat()
    try:
        s.st_ino = int(pid)
    except ValueError:
        s.st_ino = 0

    s.st_dev = 0
    s.st_nlink = 1
    s.st_uid = 0
    s.st_gid = 0
    s.st_size = 1
    s.st_atime = 0
    s.st_mtime = 0
    s.st_ctime = 0
    s.st_blocks = 2
    s.st_rdev = 0

    return s


class AddressSpaceFuse(Fuse):
    """ A class that makes all address spaces appear in a fuse filesystem.
    """
    offset = '0'

    def __init__(self, *args, **kw):
        Fuse.__init__(self, *args, **kw)

    def main(self):
      options, args = self.parser.parse_args()
      if not args:
          print "No image file specied."
          return

      self.session = session.Session(
          filename=args[0], logging=2, profile=options.profile)

      # List all processes and hold on to their address spaces.
      self.tasks = {}
      for task in self.session.plugins.pslist(session=self.session).list_eprocess():
          address_space = task.get_process_address_space()
          process_name = u"%s_%s" % (task.UniqueProcessId, task.ImageFileName)

          # Remove funky chars from the filename
          process_name = re.sub("[^a-zA-Z0-9._]", "_", process_name)

          if address_space:
              self.tasks[process_name] = address_space

      # Make a special entry for the kernel here.
      self.tasks['kernel'] = self.session.kernel_address_space

      ## Prepare the file class - this will be used to read specific
      ## files:
      self.file_class = self.ASFuseFile
      self.file_class.fs = self

      if self.session.profile.metadata("memory_model") == "64bit":
          self.address_space_size = 0xfffffffffffffff
      else:
          self.address_space_size = 0xffffffff

      return Fuse.main(self)

    def getattr(self, path):
        # The path represents a pid.
        components = os.path.split(path)
        if len(components) > 2:
            return

        if len(components) == 2 and components[1] in self.tasks:
            s = make_stat(components[1])
            s.st_mode = stat.S_IFREG
            s.st_size = self.address_space_size

            return s

        elif components[0] == "/":
            s = make_stat(2)
            s.st_mode = stat.S_IFDIR

            return s

    def readdir(self, path, offset):
        if path == "/":
            for pid in self.tasks:
                result = fuse.Direntry(str(pid))
                result.type = stat.S_IFREG
                result.st_size = self.address_space_size

                yield result

    def unlink(self, path):
        pass

    def rmdir(self, path):
        pass

    def symlink(self, path, path1):
        pass

    def rename(self, path, path1):
        pass

    def link(self, path, path1):
        pass

    def chmod(self, path, mode):
        pass

    def chown(self, path, user, group):
        pass

    def truncate(self, path, len):
        pass

    def mknod(self, path, mode, dev):
        pass

    def mkdir(self, path, mode):
        pass

    def utime(self, path, times):
        pass

    def access(self, path, mode):
        pass

    def statfs(self):
        """
        Should return an object with statvfs attributes (f_bsize, f_frsize...).
        Eg., the return value of os.statvfs() is such a thing (since py 2.2).
        If you are not reusing an existing statvfs object, start with
        fuse.StatVFS(), and define the attributes.

        To provide usable information (ie., you want sensible df(1)
        output, you are suggested to specify the following attributes:

            - f_bsize - preferred size of file blocks, in bytes
            - f_frsize - fundamental size of file blcoks, in bytes
                [if you have no idea, use the same as blocksize]
            - f_blocks - total number of blocks in the filesystem
            - f_bfree - number of free blocks
            - f_files - total number of file inodes
            - f_ffree - nunber of free file inodes
        """
        s=fuse.StatVfs()
        info = self.fs.info

        s.f_bsize = 4096
        s.f_frsize = 0
        s.f_blocks = sys.maxint
        s.f_bfree = 0
        s.f_files = len(self.tasks)
        s.f_ffree = 0

        return s

    def fsinit(self):
        pass


    class ASFuseFile(object):
        """ This is a file created on the AFF4 universe """
        direct_io = False
        keep_cache = True

        def __init__(self, path, flags, *mode):
            self.path = path
            components = os.path.split(path)
            if len(components) != 2:
                raise IOError("File not found")

            try:
                self.address_space = self.fs.tasks[components[1]]
            except KeyError:
                raise IOError("unable to open %s" % path)

        def read(self, length, offset):
            return self.address_space.read(offset, length)

        def _fflush(self):
            pass

        def fsync(self, isfsyncfile):
            pass

        def flush(self):
            pass

        def fgetattr(self):
            s = make_stat(self.path)
            s.st_blksize = 4096
            s.st_size = self.fs.address_space_size
            return s

        def ftruncate(self, len):
            pass

        def write(self, *args, **kwargs):
            return -EOPNOTSUPP

        def lock(self, cmd, owner, **kw):
            return -EOPNOTSUPP

        def close(self):
            pass


def main():
    global server

    usage = """
Userspace address_space_fuse: mount all process address spaces.

%prog [options] image_name mount_point
"""

    server = AddressSpaceFuse(version="%prog " + fuse.__version__,
                     usage=usage,
                     dash_s_do='setsingle')

    # Disable multithreading: if you want to use it, protect all method of
    # XmlFile class with locks, in order to prevent race conditions
    server.multithreaded = False

    server.parser.add_option("-p", "--profile", default="Win7SP1x64",
                             help="Profile to use [default: %default]")

    server.parse(values = server, errex=1)

    ## Try to fix up the mount point if it was given relative to the
    ## CWD
    if server.fuse_args.mountpoint and not os.access(os.path.join("/",server.fuse_args.mountpoint), os.W_OK):
        server.fuse_args.mountpoint = os.path.join(os.getcwd(), server.fuse_args.mountpoint)

    server.main()

if __name__ == '__main__':
    main()
