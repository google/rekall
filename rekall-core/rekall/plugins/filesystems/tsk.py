import hashlib
from time import sleep

import pytsk3 as pytsk3
import sys

import plugin
from rekall import obj
from rekall.plugin import TypedProfileCommand, PhysicalASMixin, ProfileCommand
from rekall.plugins import guess_profile


class FSEntry(object):
    def __init__(self, tsk_file):
        self._tsk_file = tsk_file

    @property
    def type(self):
        return str(self._tsk_file.info.meta.type)[17:]

    @property
    def name(self):
        return self._tsk_file.info.name.name

    @property
    def size(self):
        return self._tsk_file.info.meta.size

    def read(self, start, size):
        if self.size > 0:
            return self._tsk_file.read_random(start, size)
        else:
            return ""

    def __iter__(self):
        if self.type == "DIR":
            for directory_entry in self._tsk_file.as_directory():
                if directory_entry.info.meta is None:
                    continue
                name = directory_entry.info.name.name
                if name in [".", ".."]:
                    continue
                yield FSEntry(directory_entry)


class FS(object):
    def __init__(self, tsk_fs):
        self._tsk_fs = tsk_fs

    def get_fs_entry_by_path(self, path):
        path = path.replace('\\', '/')
        tsk_file = self._tsk_fs.open(path)
        return FSEntry(tsk_file)


class VolumeSystem(object):
    def __init__(self, disk, tsk_vs):
        self._disk = disk
        self._tsk_vs = tsk_vs
        self.type = str(self._tsk_vs.info.vstype)[12:]
        self.partitions = []
        for partition in self._tsk_vs:
            if partition.flags == pytsk3.TSK_VS_PART_FLAG_ALLOC:
                try:
                    tsk_fs = pytsk3.FS_Info(self._disk, offset=partition.start * self._tsk_vs.info.block_size)
                    self.partitions.append(FS(tsk_fs))
                except IOError:
                    self.partitions.append(None)


class Disk(object):
    def __init__(self, img_info):
        self._img_info = img_info
        try:
            # open as disk image
            tsk_vs = pytsk3.Volume_Info(self._img_info)
            self.volume_system = VolumeSystem(self._img_info, tsk_vs)
            self.partitions = self.volume_system.partitions
        except IOError:
            # open as partition image
            self.volume_system = None
            self.partitions = []
            try:
                tsk_fs = pytsk3.FS_Info(self._img_info)
                self.partitions.append(FS(tsk_fs))
            except IOError:
                pass

    def read(self, offset, size):
        return self._img_info.read(offset, size)


class AS_Img_Info(pytsk3.Img_Info):
    def __init__(self, address_space):
        self._as = address_space
        pytsk3.Img_Info.__init__(self, "")

    def close(self):
        self._as.close()

    def read(self, offset, size):
        return self._as.read(offset, size)

    def get_size(self):
        return self._as.end()


class TSKProfile(obj.Profile):
    pass


class TSKDetector(guess_profile.DetectionMethod):
    name = "tsk"

    def Offsets(self):
        return [0]

    def DetectFromHit(self, hit, offset, address_space):
        img_info = AS_Img_Info(address_space)
        disk = Disk(img_info)
        if len(disk.partitions) > 0:
            self.session.SetParameter("disk", disk)
            return TSKProfile(session=self.session)
        return None


class TSKILS(PhysicalASMixin, TypedProfileCommand, ProfileCommand):
    name = "ils"

    __args = [
        dict(name="part_num", default="0", positional=False,
             help="Partition number of the directory of interest"),
        dict(name="dir_path", default="/", positional=True,
             help="Directory path to print content of")
    ]

    table_header = plugin.PluginHeader(
        dict(name="Name", cname="name", width=50),
        dict(name="Type", cname="type", width=10),
        dict(name="Size", cname="size", width=10),
        dict(name="MD5", cname="md5", width=32)
    )

    @classmethod
    def is_active(cls, session):
        return isinstance(session.profile, TSKProfile)

    def collect(self):
        part_num = int(self.plugin_args.part_num)
        dir_path = self.plugin_args.dir_path
        partition = self.session.GetParameter("disk").partitions[part_num]
        for entry in partition.get_fs_entry_by_path(dir_path):
            if entry.type == "DIR":
                size = 0
                md5 = ""
            else:
                size = entry.size
                md5 = hashlib.md5(entry.read(0, size)).hexdigest()
            yield entry.name, entry.type, size, md5
