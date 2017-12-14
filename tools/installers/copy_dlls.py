"""This program copies the DLLs used by Rekall into the pyinstaller directory.

PyInstaller is pretty bad at discovering the needed DLLs and often misses a lot
of needed DLLs like the VC run times.

This program works by running inside Rekall itself, and introspecting the
currently used DLLs. We copy all the DLLs that are not in the system32 directory
to the target path.
"""
from __future__ import print_function
import ctypes
import re
import os
import shutil
import sys
import win32process

import yara

from rekall import plugins
from rekall_agent import agent

PROCESS_QUERY_INFORMATION = 0x400
PROCESS_VM_READ = 0x10

UCRT_DIR = r"C:\Program Files (x86)\Windows Kits\10\Redist\ucrt\dlls"


def EnumMissingModules():
  """Enumerate all modules which match the patterns MODULE_PATTERNS.
  PyInstaller often fails to locate all dlls which are required at
  runtime. We import all the client modules here, we simply introdpect
  all the modules we have loaded in our current running process, and
  all the ones matching the patterns are copied into the client
  package.
  Yields:
    a source file for a linked dll.
  """
  module_handle = ctypes.c_ulong()
  count = ctypes.c_ulong()
  process_handle = ctypes.windll.kernel32.OpenProcess(
      PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, os.getpid())
  ctypes.windll.psapi.EnumProcessModules(
      process_handle, ctypes.byref(module_handle), ctypes.sizeof(module_handle),
      ctypes. byref(count))

  # The size of a handle is pointer size (i.e. 64 bit on amd64 and 32 bit on
  # i386).
  if sys.maxsize > 2 ** 32:
    handle_type = ctypes.c_ulonglong
    dlls_arch = "x64"
  else:
    handle_type = ctypes.c_ulong
    dlls_arch = "x86"

  module_list = (handle_type * (count.value // ctypes.sizeof(handle_type)))()

  ctypes.windll.psapi.EnumProcessModulesEx(
      process_handle, ctypes.byref(module_list), ctypes.sizeof(module_list),
      ctypes.byref(count), 2)

  for x in module_list:
    module_filename = win32process.GetModuleFileNameEx(process_handle, x).lower()
    # PyInstaller is pretty bad in finding all the imported pyd files, and dlls.
    if ("winsxs" in module_filename or "site-packages" in module_filename or
        module_filename.endswith(".pyd") or "msvc" in module_filename or
        "\\dlls" in module_filename):
        yield module_filename
    else:
        print("Skipping %s" % module_filename)

  # See issue https://github.com/google/rekall/issues/335
  # We need to copy all these DLLs into the target as well.
  ucrt_dir = os.path.join(UCRT_DIR, dlls_arch)
  for filename in os.listdir(ucrt_dir):
    if filename.lower().endswith(".dll"):
      yield os.path.join(ucrt_dir, filename)


if __name__ == "__main__":
    target_dir = "dist/rekal"
    if not os.path.isdir(target_dir):
      raise RuntimeError("Target is not a directory.")

    for x in EnumMissingModules():
        print("Copying %s" % x)
        shutil.copy(x, target_dir)
