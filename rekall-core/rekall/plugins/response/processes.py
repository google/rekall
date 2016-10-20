"""Rekall plugins for displaying processes in live triaging."""

import psutil
from efilter.protocols import structured

from rekall import utils

from rekall.plugins import core
from rekall.plugins.response import common
from rekall.plugins.overlays import basic

from rekall.plugins import yarascanner


class _LiveProcess(utils.SlottedObject):
    """An object to represent a live process.

    This is the live equivalent of _EPROCESS.
    """
    __slots__ = ("_proc", "_obj_profile", "session",
                 "start_time", "pid")

    def __init__(self, proc, session=None):
        """Construct a representation of the live process.

        Args:
          proc: The psutil.Process instance.
        """
        # Hold on to the original psutil object.
        self._proc = proc
        self._obj_profile = None
        self.session = session
        super(_LiveProcess, self).__init__()

        self.start_time = basic.UnixTimeStamp(
            name="create_time", value=self.create_time, session=self.session)

    @utils.safe_property
    def obj_profile(self):
        # Delay creation of the profile because it needs to look in the
        # environment which is slow.
        if self._obj_profile is None:
            self._obj_profile = common.APIProfile(
                session=self.session, proc=self)

        return self._obj_profile

    def __int__(self):
        return self.pid

    def _get_field(self, field_name):
        try:
            result = getattr(self._proc, field_name)
            if callable(result):
                result = result()

            return result
        except psutil.Error:
            # Some processes do not have environ defined.
            if field_name == "environ":
                return {}

            return None
        except AttributeError:
            return None

    def __format__(self, formatspec):
        """Support the format() protocol."""
        if not formatspec:
            formatspec = "s"

        if formatspec[-1] in "xdXD":
            return format(int(self), formatspec)

        return object.__format__(self, formatspec)

    def __repr__(self):
        return "<Live Process pid=%s>" % self.pid

    def get_process_address_space(self):
        return common.APIProcessAddressSpace(self.pid, session=self.session)

    def as_dict(self):
        try:
            return self._proc.as_dict()
        except Exception:
            # This can happen if the process no longer exists.
            return {}

# Automatically add accessors for psutil fields.
psutil_fields = ['cmdline', 'connections', 'cpu_affinity',
                 'cpu_percent', 'cpu_times', 'create_time',
                 'cwd', 'environ', 'exe', 'gids', 'io_counters',
                 'ionice', 'memory_full_info', 'memory_info',
                 'memory_info_ex', 'memory_maps', 'memory_percent',
                 'name', 'nice', 'num_ctx_switches', 'num_fds',
                 'num_threads', 'open_files', 'pid', 'ppid',
                 'status', 'terminal', 'threads', 'uids', 'username',
                 'num_handles']

# Generate accessors for psutil derived properties.
properties = dict(__slots__=())
for field in psutil_fields:
    properties[field] = property(
        lambda self, field=field: self._get_field(field))

LiveProcess = type("LiveProcess", (_LiveProcess, ), properties)


structured.IStructured.implement(
    for_type=LiveProcess,
    implementations={
        structured.resolve: lambda d, m: getattr(d, m, None),
        structured.getmembers_runtime: lambda d: psutil_fields + d.keys(),
    }
)


class APIProcessFilter(common.AbstractAPICommandPlugin):
    """A live process filter using the system APIs."""

    __abstract = True

    __args = [
        dict(name="pids", positional=True, type="ArrayIntParser", default=[],
             help="One or more pids of processes to select."),

        dict(name="proc_regex", default=None, type="RegEx",
             help="A regex to select a process by name."),
    ]

    @utils.safe_property
    def filtering_requested(self):
        return (self.plugin_args.pids or self.plugin_args.proc_regex)

    def filter_processes(self):
        """Filters eprocess list using pids lists."""
        for proc in self.list_process():
            if not self.filtering_requested:
                yield proc

            else:
                if int(proc.pid) in self.plugin_args.pids:
                    yield proc

                elif (self.plugin_args.proc_regex and
                      self.plugin_args.proc_regex.match(
                          utils.SmartUnicode(proc.name))):
                    yield proc

    def list_process(self):
        result = [LiveProcess(x, session=self.session)
                  for x in psutil.process_iter()]

        return result


class APIPslist(APIProcessFilter):
    """A live pslist plugin using the APIs."""

    name = "pslist"

    table_header = [
        dict(name="proc", hidden=True),
        dict(name="Name", width=30),
        dict(name="pid", width=6, align="r"),
        dict(name="ppid", width=6, align="r"),
        dict(name="Thds", width=6, align="r"),
        dict(name="Hnds", width=8, align="r"),
        dict(name="wow64", width=6),
        dict(name="start", width=24),
        dict(name="binary"),
    ]

    def column_types(self):
        return self._row(LiveProcess(psutil.Process(), session=self.session))

    def is_wow64(self, proc):
        """Determine if the proc is Wow64."""
        # Not the most accurate method but very fast.
        return (proc.environ.get("PROCESSOR_ARCHITECTURE") == 'x86' and
                proc.environ.get("PROCESSOR_ARCHITEW6432") == 'AMD64')

    def _row(self, proc):
        return dict(proc=proc,
                    Name=proc.name,
                    pid=proc.pid,
                    ppid=proc.ppid,
                    Thds=proc.num_threads,
                    Hnds=proc.num_handles,
                    wow64=self.is_wow64(proc),
                    start=proc.start_time,
                    binary=proc.exe)

    def collect(self):
        for proc in self.filter_processes():
            yield self._row(proc)


class APISetProcessContext(core.SetProcessContextMixin,
                           APIProcessFilter):
    """A cc plugin for setting process context to live mode."""
    name = "cc"


class APIProcessScanner(APIProcessFilter):
    """Scanner for scanning processes using the ReadProcessMemory() API."""

    __abstract = True

    def generate_memory_ranges(self):
        with self.session.plugins.cc() as cc:
            for task in self.filter_processes():
                comment = "%s (%s)" % (task.name, task.pid)

                cc.SwitchProcessContext(task)

                process_address_space = self.session.GetParameter(
                    "default_address_space")

                for _, _, run in process_address_space.runs:
                    vad = run.data["vad"]
                    self.session.logging.info(
                        "Scanning %s (%s) in: %s [%#x-%#x]",
                        task.name, task.pid, vad.filename or "",
                        vad.start, vad.end)

                    run.data["comment"] = comment
                    run.data["task"] = task
                    yield run


class ProcessYaraScanner(yarascanner.YaraScanMixin, APIProcessScanner):
    """Yara scan process memory using the ReadProcessMemory() API."""
    name = "yarascan"
