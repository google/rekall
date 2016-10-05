from rekall import kb

from rekall.plugins.filesystems import ntfs
from rekall.plugins.filesystems import tsk


class NTFSMode(kb.ParameterHook):
    name = "mode_ntfs"

    def calculate(self):
        return isinstance(self.session.profile, ntfs.NTFSProfile)



class TSKMode(kb.ParameterHook):
    name = "mode_tsk"

    def calculate(self):
        return isinstance(self.session.profile, tsk.TSKProfile)



class WinXPMode(kb.ParameterHook):
    name = "mode_xp"

    def calculate(self):
        return self.session.profile.metadata("major") == 5


class AMD64Mode(kb.ParameterHook):
    name = "mode_amd64"

    def calculate(self):
        return self.session.profile.metadata("arch") == "AMD64"


class WinMode(kb.ParameterHook):
    name = "mode_windows"

    def calculate(self):
        return self.session.profile.metadata("os") == "windows"


class LinMode(kb.ParameterHook):
    name = "mode_linux"

    def calculate(self):
        return self.session.profile.metadata("os") == "linux"


class DarwinMode(kb.ParameterHook):
    name = "mode_darwin"

    def calculate(self):
        return self.session.profile.metadata("os") == "darwin"


class LiveMode(kb.ParameterHook):
    name = "mode_live"

    def calculate(self):
        return bool(self.session.GetParameter("live_mode"))



class LiveMemoryMode(kb.ParameterHook):
    name = "mode_live_memory"

    def calculate(self):
        return self.session.GetParameter("live_mode") == "Memory"


class LiveAPIMode(kb.ParameterHook):
    name = "mode_live_api"

    def calculate(self):
        return self.session.GetParameter("live_mode") == "API"


class ImageMode(kb.ParameterHook):
    name = "mode_image"

    def calculate(self):
        return (self.session.physical_address_space and
                self.session.physical_address_space.metadata("image"))


class VistaMode(kb.ParameterHook):
    name = "mode_vista_plus"

    def calculate(self):
        return self.session.profile.metadata("major") >= 6


class WinMemoryMode(kb.ParameterHook):
    """Windows memory image or live windows."""
    name = "mode_windows_memory"

    def calculate(self):
        return (self.session.GetParameter("mode_live_memory") or
                self.session.GetParameter("mode_image")) and (
                    self.session.GetParameter("mode_windows"))


class LinMemoryMode(kb.ParameterHook):
    """Windows memory image or live windows."""
    name = "mode_linux_memory"

    def calculate(self):
        return (self.session.GetParameter("mode_live_memory") or
                self.session.GetParameter("mode_image")) and (
                    self.session.GetParameter("mode_linux"))


class DarwinMemoryMode(kb.ParameterHook):
    """Windows memory image or live windows."""
    name = "mode_darwin_memory"

    def calculate(self):
        return (self.session.GetParameter("mode_live_memory") or
                self.session.GetParameter("mode_image")) and (
                    self.session.GetParameter("mode_darwin"))


class MountainLionMode(kb.ParameterHook):
    """Windows memory image or live windows."""
    name = "mode_darwin_mountain_lion_plus"

    def calculate(self):
        return (self.session.profile.get_constant("_BootPML4", False) and
                self.session.GetParameter("mode_darwin_memory"))
