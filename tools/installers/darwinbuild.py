"""A build script for osx installation."""
from __future__ import print_function
from rekall import constants

import capstone
import glob
import io
import os
import parso
import platform
import shutil
import subprocess
import tempfile

def copytree(src, dst, symlinks=False, ignore=None):
    if not os.path.exists(dst):
        os.makedirs(dst)
    for item in os.listdir(src):
        s = os.path.join(src, item)
        d = os.path.join(dst, item)
        if os.path.isdir(s):
            copytree(s, d, symlinks, ignore)
        else:
            if not os.path.exists(d) or os.stat(s).st_mtime - os.stat(d).st_mtime > 1:
                shutil.copy2(s, d)


def copy(src, dst):
    for filename in glob.glob(src):
        dest = os.path.join(dst, os.path.basename(filename))
        if os.path.isdir(filename):
            copytree(filename, dest)
        else:
            shutil.copy(filename, dest)


def rm(fileglob):
    for filename in glob.iglob(fileglob):
        if os.path.isdir(filename):
            shutil.rmtree(filename)
        else:
            os.remove(filename)


def touch(path):
    try:
        with io.open(path, "wt", encoding='utf8') as fd:
            fd.write("")
    except (IOError, OSError):
        pass



def main():
    if os.environ.get("VIRTUAL_ENV") is None:
        raise RuntimeError("You must run this script from within a "
                           "virtual env.")

    if not os.path.isdir("tools/installers"):
        raise RuntimeError("You must run this script from the top "
                           "level rekall source tree.")

    # Clean the build and dist directories.
    print("Cleaning build directories.")

    shutil.rmtree("build", True)
    shutil.rmtree("dist", True)

    print("Building with Pyinstaller")
    subprocess.call(["pyinstaller", "--onedir", "-y", "-i",
                     "resources/rekall.ico",
                     "tools/installers/rekal.py"])

    print("Copy missing libraries.")
    copy(capstone._cs._name, "dist/rekal")

    print("Copy resources into the package.")
    # Recent versions of Pyinstaller already copy resources they know about.
    copy("rekall-core/resources", "dist/rekal")

    # Copy parso syntax files.
    parso_dir = os.path.dirname(parso.__file__)
    copy(os.path.join(parso_dir, "python"), "dist/rekal/parso")

    # For OSX, OSQuery has a great installer so no need to bring our
    # own.

    print("Remove unnecessary crap added by pyinstaller.")
    rm("dist/rekal/_MEI")
    rm("dist/rekal/tcl/*")
    rm("dist/rekal/tk/*")
    rm("dist/rekal/idlelib")
    rm("dist/rekal/Include")
    touch("dist/rekal/tcl/ignore")
    touch("dist/rekal/tk/ignore")


if __name__ == "__main__":
    main()
