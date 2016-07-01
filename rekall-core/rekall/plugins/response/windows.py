"""Windows specific response plugins."""
import itertools
import win32api
import pythoncom
import win32com.client

from rekall import plugin
from rekall import obj
from rekall import utils
from rekall.plugins.response import common


def get_drives():
    drives = win32api.GetLogicalDriveStrings()
    return [x.rstrip("\\") for x in drives.split('\000') if x]


class WmiResult(utils.AttributeDict):
    """Represent WMI result."""

    # Properties to remove from results sent to the server.
    # These properties are included with nearly every WMI object and use space.
    IGNORE_PROPS = ["CSCreationClassName", "CreationClassName", "OSName",
                    "OSCreationClassName", "WindowsVersion", "CSName",
                    "__NAMESPACE", "__SERVER", "__PATH"]

    def __init__(self, result):
        super(WmiResult, self).__init__()
        for prop in itertools.chain(
                result.Properties_, result.SystemProperties_):
            if prop.Name not in self.IGNORE_PROPS:
                self[prop.Name] = prop.Value


class Wmi(common.AbstractIRCommandPlugin):
    """Executes a WMI query and returns results."""
    name = "wmi"

    __args = [
        dict(name="query", positional=True,
             help="WMI query to execute"),
        dict(name="baseobj", default=r"winmgmts:\root\cimv2",
             help="The base object to query")
    ]

    table_header = [
        dict(name="Result")
    ]

    def column_types(self):
        return dict(Result=utils.AttributeDict())

    def collect(self):
        # Needs to be called if using com from a thread.
        pythoncom.CoInitialize()

        wmi_obj = win32com.client.GetObject(self.plugin_args.baseobj)

        # This allows our WMI to do some extra things, in particular
        # it gives it access to find the executable path for all processes.
        wmi_obj.Security_.Privileges.AddAsString("SeDebugPrivilege")

        # Run query
        try:
            query_results = wmi_obj.ExecQuery(self.plugin_args.query)
        except pythoncom.com_error as e:
            raise plugin.PluginError(
                "Failed to run WMI query \'%s\' err was %s" % (
                    self.plugin_args.query, e))

        # Extract results from the returned COMObject and return dicts.
        try:
            for result in query_results:
                yield dict(Result=WmiResult(result))

        except pythoncom.com_error as e:
            raise plugin.PluginError(
                "WMI query data error on query \'%s\' err was %s" %
                (e, self.plugin_args.query))


class WindowsRootFileInformation(common.FileInformation):
    """A special FileInformation class to handle windows drives.

    In windows the root directory (/) is not real, it contains a
    listing of drive letters. So listing the "/" directory should
    return a list of FileInformation("/c:"), FileInformation("/d:")
    etc.
    """

    def __init__(self, **kwargs):
        super(WindowsRootFileInformation, self).__init__(**kwargs)
        self.st_mode = common.Permissions(0755)
        self.st_ino = 0
        self.st_size = 0
        self.st_uid = self.st_gid = 0
        self.st_mtime = self.st_atime = self.st_ctime = obj.NoneObject("No set")

    def open(self):
        return obj.NoneObject("Not set")

    def list(self):
        for drive in get_drives():
            yield self.from_stat(
                common.FileSpec(
                    filename="%s%s" % (self.filename.path_sep, drive),
                    path_sep=self.filename.path_sep,
                    filesystem=self.filename.filesystem),
                session=self.session)


class WindowsFileInformation(common.FileInformation):
    @classmethod
    def from_stat(cls, filespec, session=None):
        filespec = common.FileSpec(filespec)

        # The root path.
        if filespec.name == filespec.path_sep:
            return WindowsRootFileInformation(
                session=session, filename=filespec)

        return super(WindowsFileInformation, cls).from_stat(
            filespec, session=session)


# Register a specialized implementation of FileInformation
common.FILE_SPEC_DISPATCHER["API"] = WindowsFileInformation
