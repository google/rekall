"""Support the windows registry.

This code is borrowed from GRR.
"""

import ctypes
import ctypes.wintypes
import exceptions
import stat
import StringIO
import _winreg

from rekall import obj
from rekall import utils
from rekall.plugins.overlays import basic
from rekall.plugins.response import common


# Difference between 1 Jan 1601 and 1 Jan 1970.
WIN_UNIX_DIFF_MSECS = 11644473600

# KEY_READ = STANDARD_RIGHTS_READ | KEY_QUERY_VALUE |
#            KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY
# Also see: http://msdn.microsoft.com/en-us/library/windows/desktop/
# ms724878(v=vs.85).aspx
KEY_READ = 0x20019


# _winreg is broken on Python 2.x and doesn't support unicode registry values.
# We provide some replacement functions here.

advapi32 = ctypes.windll.advapi32

LPDWORD = ctypes.POINTER(ctypes.wintypes.DWORD)
LPBYTE = ctypes.POINTER(ctypes.wintypes.BYTE)

ERROR_SUCCESS = 0
ERROR_MORE_DATA = 234


class FileTime(ctypes.Structure):
    _fields_ = [("dwLowDateTime", ctypes.wintypes.DWORD),
                ("dwHighDateTime", ctypes.wintypes.DWORD)]


RegCloseKey = advapi32.RegCloseKey
RegCloseKey.restype = ctypes.c_long
RegCloseKey.argtypes = [ctypes.c_void_p]

RegEnumKeyEx = advapi32.RegEnumKeyExW
RegEnumKeyEx.restype = ctypes.c_long
RegEnumKeyEx.argtypes = [ctypes.c_void_p, ctypes.wintypes.DWORD,
                         ctypes.c_wchar_p, LPDWORD, LPDWORD, ctypes.c_wchar_p,
                         LPDWORD, ctypes.POINTER(FileTime)]

RegEnumValue = advapi32.RegEnumValueW
RegEnumValue.restype = ctypes.c_long
RegEnumValue.argtypes = [ctypes.c_void_p, ctypes.wintypes.DWORD,
                         ctypes.c_wchar_p, LPDWORD, LPDWORD, LPDWORD, LPBYTE,
                         LPDWORD]

RegOpenKeyEx = advapi32.RegOpenKeyExW
RegOpenKeyEx.restype = ctypes.c_long
RegOpenKeyEx.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_ulong,
                         ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p)]

RegQueryInfoKey = advapi32.RegQueryInfoKeyW
RegQueryInfoKey.restype = ctypes.c_long
RegQueryInfoKey.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, LPDWORD, LPDWORD,
                            LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD,
                            LPDWORD, LPDWORD, ctypes.POINTER(FileTime)]

RegQueryValueEx = advapi32.RegQueryValueExW
RegQueryValueEx.restype = ctypes.c_long
RegQueryValueEx.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, LPDWORD, LPDWORD,
                            LPBYTE, LPDWORD]


class KeyHandle(object):
    """A wrapper class for a registry key handle."""

    def __init__(self, value=0, close=True):
        if value:
            self.handle = ctypes.c_void_p(value)
        else:
            self.handle = ctypes.c_void_p()
        self._close = close

    def __enter__(self):
        return self

    def __exit__(self, exc_type=None, exc_val=None, exc_tb=None):
        self.Close()
        return False

    def Close(self):
        if not self.handle or not self._close:
            return
        if RegCloseKey is None:
            return    # Globals become None during exit.
        rc = RegCloseKey(self.handle)
        self.handle = ctypes.c_void_p()
        if rc != ERROR_SUCCESS:
            raise ctypes.WinError(2)

    def __del__(self):
        self.Close()


def OpenKey(key, sub_key):
    """This calls the Windows OpenKeyEx function in a Unicode safe way."""
    if not sub_key:
        result = KeyHandle(close=False)
        result.handle = key.handle
        return result

    new_key = KeyHandle()
    # Don't use KEY_WOW64_64KEY (0x100) since it breaks on Windows 2000
    rc = RegOpenKeyEx(key.handle, sub_key, 0, KEY_READ, ctypes.cast(
            ctypes.byref(new_key.handle), ctypes.POINTER(ctypes.c_void_p)))
    if rc != ERROR_SUCCESS:
        raise ctypes.WinError(2)

    return new_key


def CloseKey(key):
    rc = RegCloseKey(key)
    if rc != ERROR_SUCCESS:
        raise ctypes.WinError(2)


def QueryInfoKey(key):
    """This calls the Windows RegQueryInfoKey function in a Unicode safe way."""
    null = LPDWORD()
    num_sub_keys = ctypes.wintypes.DWORD()
    num_values = ctypes.wintypes.DWORD()
    ft = FileTime()
    rc = RegQueryInfoKey(key.handle, ctypes.c_wchar_p(), null, null,
                         ctypes.byref(num_sub_keys), null, null,
                         ctypes.byref(num_values), null, null, null,
                                             ctypes.byref(ft))
    if rc != ERROR_SUCCESS:
        raise ctypes.WinError(2)

    return (num_sub_keys.value, num_values.value, ft.dwLowDateTime
                    | (ft.dwHighDateTime << 32))


def QueryValueEx(key, value_name):
    """This calls the Windows QueryValueEx function in a Unicode safe way."""
    size = 256
    data_type = ctypes.wintypes.DWORD()
    while True:
        tmp_size = ctypes.wintypes.DWORD(size)
        buf = ctypes.create_string_buffer(size)
        rc = RegQueryValueEx(key.handle, value_name, LPDWORD(),
                             ctypes.byref(data_type), ctypes.cast(buf, LPBYTE),
                             ctypes.byref(tmp_size))
        if rc != ERROR_MORE_DATA:
            break

        # We limit the size here to ~10 MB so the response doesn't get too big.
        if size > 10 * 1024 * 1024:
            raise exceptions.WindowsError("Value too big to be read.")

        size *= 2

    if rc != ERROR_SUCCESS:
        raise ctypes.WinError(2)

    return (Reg2Py(buf, tmp_size.value, data_type.value), data_type.value)


def EnumKey(key, index):
    """This calls the Windows RegEnumKeyEx function in a Unicode safe way."""
    buf = ctypes.create_unicode_buffer(257)
    length = ctypes.wintypes.DWORD(257)
    rc = RegEnumKeyEx(key.handle, index, ctypes.cast(buf, ctypes.c_wchar_p),
                      ctypes.byref(length), LPDWORD(), ctypes.c_wchar_p(),
                      LPDWORD(), ctypes.POINTER(FileTime)())
    if rc != 0:
        raise ctypes.WinError(2)

    return ctypes.wstring_at(buf, length.value).rstrip(u"\x00")


def EnumValue(key, index):
    """This calls the Windows RegEnumValue function in a Unicode safe way."""
    null = ctypes.POINTER(ctypes.wintypes.DWORD)()
    value_size = ctypes.wintypes.DWORD()
    data_size = ctypes.wintypes.DWORD()
    rc = RegQueryInfoKey(key.handle, ctypes.c_wchar_p(), null, null, null, null,
                         null, null, ctypes.byref(value_size),
                         ctypes.byref(data_size), null,
                         ctypes.POINTER(FileTime)())
    if rc != ERROR_SUCCESS:
        raise ctypes.WinError(2)

    value_size.value += 1
    data_size.value += 1

    value = ctypes.create_unicode_buffer(value_size.value)

    while True:
        data = ctypes.create_string_buffer(data_size.value)

        tmp_value_size = ctypes.wintypes.DWORD(value_size.value)
        tmp_data_size = ctypes.wintypes.DWORD(data_size.value)
        data_type = ctypes.wintypes.DWORD()
        rc = RegEnumValue(key.handle, index, ctypes.cast(
            value, ctypes.c_wchar_p),
                          ctypes.byref(tmp_value_size), null,
                          ctypes.byref(data_type), ctypes.cast(data, LPBYTE),
                          ctypes.byref(tmp_data_size))

        if rc != ERROR_MORE_DATA:
            break

        data_size.value *= 2

    if rc != ERROR_SUCCESS:
        raise ctypes.WinError(2)

    return (value.value, Reg2Py(data, tmp_data_size.value, data_type.value),
                    data_type.value)


def Reg2Py(data, size, data_type):
    if data_type == _winreg.REG_DWORD:
        if size == 0:
            return 0
        return ctypes.cast(data, ctypes.POINTER(ctypes.c_int)).contents.value
    elif data_type == _winreg.REG_SZ or data_type == _winreg.REG_EXPAND_SZ:
        return ctypes.wstring_at(data, size // 2).rstrip(u"\x00")
    elif data_type == _winreg.REG_MULTI_SZ:
        return ctypes.wstring_at(data, size // 2).rstrip(u"\x00").split(u"\x00")
    else:
        if size == 0:
            return None
        return ctypes.string_at(data, size)


class RegistryKeyInformation(common.FileInformation):
    """Represent a key or value."""

    _hive_handle = None

    # Maps the registry types to names
    registry_map = {
        _winreg.REG_NONE: "REG_NONE",
        _winreg.REG_SZ: "REG_SZ",
        _winreg.REG_EXPAND_SZ: "REG_EXPAND_SZ",
        _winreg.REG_BINARY: "REG_BINARY",
        _winreg.REG_DWORD: "REG_DWORD",
        _winreg.REG_DWORD_LITTLE_ENDIAN: "REG_DWORD_LITTLE_ENDIAN",
        _winreg.REG_DWORD_BIG_ENDIAN: "REG_DWORD_BIG_ENDIAN",
        _winreg.REG_LINK: "REG_LINK",
        _winreg.REG_MULTI_SZ: "REG_MULTI_SZ",
    }

    def __init__(self, filename=None, **kwargs):
        filename = common.FileSpec(filename, filesystem="Reg", path_sep="\\")
        super(RegistryKeyInformation, self).__init__(
            filename=filename, **kwargs)
        self.hive = self.key_name = self.value_name = self.value = ""
        self.value_type = "REG_NONE"
        self.st_mode = stat.S_IFDIR

        path_components = self.filename.components()
        if not path_components:
            return

        # The first component MUST be a hive
        self.hive = path_components[0]
        self._hive_handle = KeyHandle(getattr(_winreg, self.hive, None))
        if self._hive_handle is None:
            raise IOError("Unknown hive name %s" % self.hive)

        # Maybe its a key.
        try:
            self._read_key(path_components)
        except exceptions.WindowsError:
            # Nop - maybe its a value then.
            self._read_value(path_components)

    def _read_value(self, path_components):
        self.key_name = "\\".join(path_components[1:-1])
        self.value_name = path_components[-1]
        with OpenKey(self._hive_handle, self.key_name) as key:
            # We are a value - we can be read but we can not be listed.
            self.value, value_type = QueryValueEx(key, self.value_name)
            self.st_mode = stat.S_IFREG
            self.value_type = self.registry_map[value_type]
            self.st_size = len(utils.SmartStr(self.value))

    def _read_key(self, path_components):
        # The path is just the hive name.
        if len(path_components) == 1:
            return

        # Its probably a key
        self.key_name = "\\".join(path_components[1:])
        self.value_name = ""
        # Try to get the default value for this key
        with OpenKey(self._hive_handle, self.key_name) as key:
            # Check for default value.
            try:
                self.value, value_type = QueryValueEx(key, self.value_name)
                self.value_type = self.registry_map[value_type]
                self.st_size = len(utils.SmartStr(self.value))
            except exceptions.WindowsError:
                pass

    @classmethod
    def from_stat(cls, filespec, session=None):
        return RegistryKeyInformation(filename=filespec, session=session)

    def open(self):
        if self.value_type != "REG_NONE":
            return StringIO.StringIO(self.value)

        return obj.NoneObject("No data")

    def list(self):
        if self.st_mode == stat.S_IFREG:
            return

        # We represent the virtual root of all hives.
        if self._hive_handle is None:
            for name in dir(_winreg):
                if name.startswith("HKEY_"):
                    yield RegistryKeyInformation(
                        filename=name, session=self.session)

            return

        try:
            with OpenKey(self._hive_handle, self.key_name) as key:
                (number_of_keys,
                 number_of_values,
                 last_modified) = QueryInfoKey(key)

                st_mtime = basic.UnixTimeStamp(
                    name="st_mtime", value=(
                        last_modified / 10000000 - WIN_UNIX_DIFF_MSECS),
                    session=self.session)

                # First keys - These will look like directories.
                for i in xrange(number_of_keys):
                    name = EnumKey(key, i)
                    key_name = "\\".join((self.hive, self.key_name, name))
                    try:
                        subkey = RegistryKeyInformation(
                            filename=key_name, session=self.session)
                        subkey.st_mtime = st_mtime

                        yield subkey
                    except exceptions.WindowsError:
                        pass

                # Now Values - These will look like files.
                for i in xrange(number_of_values):
                    name, _, _ = EnumValue(key, i)
                    key_name = "\\".join((self.hive, self.key_name, name))
                    try:
                        subkey = RegistryKeyInformation(
                            filename=key_name, session=self.session)
                        subkey.st_mtime = st_mtime

                        yield subkey
                    except exceptions.WindowsError:
                        pass

        except exceptions.WindowsError as e:
            raise IOError("Unable to list key %s: %s" % (
                self.key_name, e))


# Register Reg as a filesystem:
common.FILE_SPEC_DISPATCHER["Reg"] = RegistryKeyInformation
