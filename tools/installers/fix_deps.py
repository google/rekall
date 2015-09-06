"""Patch Rekall's dependencies.

This file patches some of Rekall's dependencies which are not
pyinstaller friendly. Typically the problems are that these
dependencies use __file__ to try to locate their dlls but this
variable does not exist when running from inside a pyinstaller bundle.
"""
import os
import re

MARK = "# Patched by Rekall"

def patch_distorm():
    # Patch distorm:
    module="distorm3",
    search_regex=re.compile(
        "# Guess the DLL filename.+?_distorm_path[^\n]+?\n",
        re.S|re.M)
    replacement="""
# Guess the DLL filename and load the library.
import sys, os
if getattr(sys, "frozen", None):
  _distorm_path = os.path.dirname(sys.executable)
else:
  _distorm_path = split(__file__)[0]
"""

    module = __import__("distorm3")
    filename = module.__file__.replace(".pyc", ".py")
    module_data = open(filename).read()
    if MARK in module_data:
        print "%s already patched, skipping" % filename
        return

    module_data = re.sub(search_regex, replacement, module_data)
    module_data += MARK
    with open(filename, "wb") as fd:
        fd.write(module_data)
        print "Patching %s" % filename

def patch_gevent():
    # Gevent has some files which are conditionally imported by python
    # 3, but pyinstaller is too dumb and tries to import them, even if
    # running in python 2 so they have syntax errors. We just replace
    # the entire file, since it will never be imported by python 2
    # anyway.
    import gevent
    filename = os.path.dirname(gevent.__file__)
    filename = os.path.join(filename, "_socket3.py")
    with open(filename,  "wb") as fd:
        fd.write("")
        print "Patching %s" % filename


def patch_all():
    patch_distorm()
    patch_gevent()


if __name__ == "__main__":
    patch_all()
