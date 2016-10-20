import pytsk3

from rekall import addrspace
from rekall import plugin
from rekall import obj
from rekall import utils
from rekall.plugins import guess_profile
from rekall.plugins.overlays import basic


class FSEntry(object):
    def __init__(self, tsk_file):
        self.tsk_file = tsk_file

    @property
    def type(self):
        return str(self.tsk_file.info.meta.type)[17:]

    @property
    def name(self):
        return self.tsk_file.info.name.name

    @property
    def size(self):
        return self.tsk_file.info.meta.size

    def read(self, start, size):
        if self.size > 0:
            return self.tsk_file.read_random(start, size)
        else:
            return ""

    def __iter__(self):
        if self.type == "DIR":
            for directory_entry in self.tsk_file.as_directory():
                if directory_entry.info.meta is None:
                    continue
                name = directory_entry.info.name.name
                if name in [".", ".."]:
                    continue
                yield FSEntry(directory_entry)


class FS(object):
    def __init__(self, tsk_fs):
        self.tsk_fs = tsk_fs

    def get_fs_entry_by_path(self, path):
        path = path.replace('\\', '/')
        tsk_file = self.tsk_fs.open(path)
        return FSEntry(tsk_file)


class VolumeSystem(object):
    """Wrap a TSK_VS_INFO struct."""

    def __init__(self, disk, tsk_vs, session=None):
        self.session = session
        self._disk = disk
        self.tsk_vs = tsk_vs
        self.type = str(self.tsk_vs.info.vstype)[12:]

    @utils.safe_property
    def partitions(self):
        return [Partition(self._disk, x, session=self.session, id=i)
                for i, x in enumerate(self.tsk_vs)]


class PartitionAddressSpace(addrspace.RunBasedAddressSpace):
    """Create a mapping into the partition."""

    def __init__(self, partition, **kwargs):
        super(PartitionAddressSpace, self).__init__(**kwargs)
        self.partition = partition
        self.add_run(0, partition.start, partition.length,
                     partition.disk.address_space)

    def __repr__(self):
        return "<Partition %s @ %#x>" % (self.partition.id,
                                         self.partition.start)



class Partition(object):
    """Wrap a TSK_VS_PART_INFO object."""

    def __init__(self, disk, partition=None, id=0, session=None,
                 filesystem=None):
        self.tsk_part = partition or obj.NoneObject()
        self.id = id
        self.disk = disk
        self.session = session
        self.filesystem = filesystem or obj.NoneObject("No filesystem")
        if (filesystem == None and
            self.tsk_part.flags == pytsk3.TSK_VS_PART_FLAG_ALLOC):
            try:
                address_space = self.get_partition_address_space()
                filesystem = pytsk3.FS_Info(AS_Img_Info(address_space))
                self.filesystem = FS(filesystem)
            except IOError:
                pass

    def get_partition_address_space(self):
        return PartitionAddressSpace(
            session=self.session, partition=self)

    @utils.safe_property
    def start(self):
        return (self.tsk_part.start * self.disk.block_size)

    @utils.safe_property
    def length(self):
        return (self.tsk_part.len * self.disk.block_size)


class Disk(object):
    def __init__(self, address_space, session=None):
        self.session = session
        self.block_size = 512

        # The address space of the entire disk.
        self.address_space = address_space
        self._img_info = AS_Img_Info(address_space)
        try:
            # open as disk image
            tsk_vs = pytsk3.Volume_Info(self._img_info)
            self.volume_system = VolumeSystem(
                self, tsk_vs, session=self.session)
            self.block_size = tsk_vs.info.block_size
            self.partitions = self.volume_system.partitions
        except IOError:
            # open as partition image
            self.volume_system = obj.NoneObject("No Volume")
            self.partitions = []
            try:
                fake_partition = Partition(
                    self, filesystem=FS(pytsk3.FS_Info(self._img_info)),
                    session=self.session)
                self.partitions.append(fake_partition)
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
        _ = offset
        disk = Disk(address_space, session=self.session)
        if len(disk.partitions) > 0:
            # Select a partition to make the default. Users can change
            # partitions using the cc plugin.
            self.session.SetParameter("disk", disk)
            profile = TSKProfile(session=self.session)
            for partition in disk.partitions:
                if partition.filesystem.tsk_fs.info.ftype:
                    self.session.logging.debug(
                        "Switching to first partition with filesystem.")
                    cc = SetPartitionContext(session=self.session,
                                             profile=profile)
                    cc.SwitchPartition(partition)
                    break

            return profile
        return None


class AbstractTSKCommandPlugin(plugin.PhysicalASMixin,
                               plugin.TypedProfileCommand,
                               plugin.ProfileCommand):
    """Baseclass for all TSK related plugins."""
    __abstract = True

    mode = "mode_tsk"


class SetPartitionContext(AbstractTSKCommandPlugin):
    name = "cc"
    interactive = True

    __args = [
        dict(name="partition_number", type="IntParser", positional=True,
             help="The partition to switch to.")
    ]

    table_header = [
        dict(name="message"),
    ]

    suppress_headers = True

    def __enter__(self):
        self.partition_context = self.session.GetParameter("partition_context")
        return self

    def __exit__(self, unused_type, unused_value, unused_traceback):
        self.SwitchPartition(self.partition_context)

    def SwitchPartition(self, partition=None):
        disk = self.session.GetParameter("disk")
        if isinstance(partition, (int, long)):
            partition = disk.partitions[partition]

        message = ("Switching to partition context: {0} "
                   "(Starts at {1:#x})").format(
                       partition.id, partition.start)

        self.session.SetCache(
            "default_address_space",
            partition.get_partition_address_space(),
            volatile=False)

        # Reset the address resolver for the new context.
        self.session.SetCache("partition_context", partition,
                              volatile=False)
        self.session.logging.debug(message)

        return message

    def collect(self):
        yield dict(
            message=self.SwitchPartition(self.plugin_args.partition_number))


class TskMmls(AbstractTSKCommandPlugin):
    name = "mmls"

    table_header = [
        dict(name="Partition", hidden=True),
        dict(name="PartId"),
        dict(name="Type", width=20),
        dict(name="Filesystem", width=20),
        dict(name="Offset", style="address"),
        dict(name="Size", style="address"),
    ]

    def collect(self):
        disk = self.session.GetParameter("disk")
        block_size = disk.block_size

        for i, partition in enumerate(disk.partitions):
            yield dict(Partition=partition,
                       PartId=i,
                       Type=partition.tsk_part.desc,
                       Filesystem=partition.filesystem.tsk_fs.info.ftype,
                       Offset=partition.tsk_part.start * block_size,
                       Size=partition.tsk_part.len * block_size,
                   )


class TSKFls(AbstractTSKCommandPlugin):
    name = "fls"

    __args = [
        dict(name="dir_path", default="/", positional=True,
             help="Directory path to print content of")
    ]

    table_header = [
        dict(name="name", width=50),
        dict(name="inode", width=20),
        dict(name="type", width=10),
        dict(name="size", width=10),
        dict(name="mtime", hidden=True, width=20),
        dict(name="atime", hidden=True, width=20),
        dict(name="ctime"),
    ]

    def collect(self):
        dir_path = self.plugin_args.dir_path
        partition = self.session.GetParameter("partition_context")
        try:
            for entry in partition.filesystem.get_fs_entry_by_path(dir_path):
                yield dict(name=entry.name,
                           inode=entry.tsk_file.info.meta.addr,
                           type=entry.type,
                           size=entry.size,
                           ctime=basic.UnixTimeStamp(
                               session=self.session,
                               name="ctime",
                               value=entry.tsk_file.info.meta.ctime),
                           mtime=basic.UnixTimeStamp(
                               session=self.session,
                               name="mtime",
                               value=entry.tsk_file.info.meta.mtime),
                           atime=basic.UnixTimeStamp(
                               session=self.session,
                               name="atime",
                               value=entry.tsk_file.info.meta.atime),
                           )
        except IOError as e:
            raise plugin.PluginError(e)
