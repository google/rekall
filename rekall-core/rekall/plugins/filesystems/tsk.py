import hashlib

import pytsk3 as pytsk3
import sys

from rekall import obj
from rekall.plugin import TypedProfileCommand, PhysicalASMixin, ProfileCommand
from rekall.plugins import guess_profile

TYPE_DIR = 0
TYPE_FILE = 1


class FSEntry(object):
    def __init__(self, tsk_file):
        self._tsk_file = tsk_file

    @property
    def type(self):
        if self._tsk_file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
            return TYPE_DIR
        else:
            return TYPE_FILE

    @property
    def name(self):
        return self._tsk_file.info.name.name

    @property
    def size(self):
        return self._tsk_file.info.meta.size

    def __iter__(self):
        if self.type == TYPE_DIR:
            for directory_entry in self._tsk_file.as_directory():
                if directory_entry.info.meta is None:
                    continue
                name = directory_entry.info.name.name
                if name in [".", ".."]:
                    continue
                yield FSEntry(directory_entry)
        else:
            return

    def __str__(self):
        if self.size > 0:
            return self._tsk_file.read_random(0, self.size)
        else:
            return ""


class FS(object):
    def __init__(self, tsk_fs):
        self._tsk_fs = tsk_fs

    @property
    def id(self):
        return self._tsk_fs.info.fs_id

    def __iter__(self):
        entries = []
        root = FSEntry(self._tsk_fs.open('/'))
        entries.append(root)
        while len(entries) > 0:
            entry = entries.pop()
            yield entry
            for sub_entry in entry:
                entries.append(sub_entry)

    def get_fs_entry_by_path(self, path):
        tsk_file = self._tsk_fs.open(path)
        return FSEntry(tsk_file)


class AS_Img_Info(pytsk3.Img_Info):
    def __init__(self, address_space):
        self._as = address_space
        pytsk3.Img_Info.__init__(self, "")

    def close(self):
        pass

    def read(self, offset, size):
        return self._as.read(offset, size)

    def get_size(self):
        return sys.maxint


class TSKProfile(obj.Profile):
    pass


class TSKDetector(guess_profile.DetectionMethod):
    name = "tsk"

    def Offsets(self):
        return [0]

    def DetectFromHit(self, hit, offset, address_space):
        img = AS_Img_Info(address_space)
        partitions = []
        # first we try to open the image as partition
        try:
            tsk_fs = pytsk3.FS_Info(img)
            partitions.append(FS(tsk_fs))
        except IOError:
            # now let's try to open it as disk
            try:
                vs = pytsk3.Volume_Info(img)
            except IOError:
                return None

            for partition in vs:
                if partition.flags == pytsk3.TSK_VS_PART_FLAG_ALLOC:
                    try:
                        tsk_fs = pytsk3.FS_Info(img, offset=partition.start * vs.info.block_size)
                        partitions.append(FS(tsk_fs))
                    except IOError as e:
                        partitions.append(None)

        if len(partitions) > 0:
            self.session.partitions = partitions
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

    @classmethod
    def is_active(cls, session):
        return isinstance(session.profile, TSKProfile)

    def render(self, renderer):
        renderer.table_header([
            ("Name", "name", "50>"),
            ("Type", "type", "10"),
            ("Size", "size", "10"),
            ("MD5", "md5", "32"),
        ])
        part_num = int(self.plugin_args.part_num)
        path = self.plugin_args.dir_path

        for entry in self.session.partitions[part_num].get_fs_entry_by_path(path):
            name = entry.name
            if entry.type == TYPE_DIR:
                entry_type = "directory"
                size = 0
                md5 = ""
            else:
                entry_type = "file"
                size = entry.size
                md5 = hashlib.md5(str(entry)).hexdigest()
            renderer.table_row(name, entry_type, size, md5)
