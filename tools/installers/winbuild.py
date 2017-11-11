"""A build script for windows installation."""
from __future__ import print_function
from rekall import constants

import glob
import io
import os
import parso
import platform
import shutil
import subprocess
import tempfile


def build_windows_installer():
    cwd = os.getcwd()
    target_path = os.path.join(cwd, r"dist\rekal")

    # Inno setup is particular about a version format.
    version = ".".join(constants.VERSION.split(".")[:3])

    template = """
#define REKALL_VERSION '%s'
#define REKALL_CODENAME '%s'
""" % (version, constants.CODENAME)

    template += r"""
[Files]
; PyInstaller files.
DestDir: {app}; Source: %s\*; Flags: recursesubdirs
""" % target_path

    template += r"""
[Setup]
ChangesAssociations=yes
Compression=zip
AppCopyright=GPLv2
AppPublisher=Rekall Team
AppPublisherURL=http://www.rekall-forensic.com/
AppName=Rekall
AppVerName=Rekall v{#REKALL_VERSION} {#REKALL_CODENAME}
DefaultDirName={pf}\Rekall
VersionInfoVersion={#REKALL_VERSION}
VersionInfoCompany=Rekall Inc.
VersionInfoDescription=Rekall Memory Forensic Framework
VersionInfoCopyright=Rekall Developers.
VersionInfoProductName=Rekall Memory Forensic Framework
MinVersion=5.01.2600sp1
PrivilegesRequired=poweruser
TimeStampsInUTC=true
OutputDir=%(cwd)s\tools\installers\Output
VersionInfoTextVersion=Rekall Memory Forensic Framework
InfoAfterFile=%(cwd)s\README.md
LicenseFile=%(cwd)s\LICENSE.txt
AllowNoIcons=true
AlwaysUsePersonalGroup=true
DefaultGroupName=Rekall Memory Forensics
SetupIconFile=%(cwd)s\resources\rekall.ico
UninstallDisplayIcon={app}\rekall.exe
""" % dict(cwd=cwd)

    if platform.architecture()[0] == "64bit":
        template += """
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
OutputBaseFilename=Rekall_{#REKALL_VERSION}_{#REKALL_CODENAME}_x64
"""
    else:
        template += """
OutputBaseFilename=Rekall_{#REKALL_VERSION}_{#REKALL_CODENAME}_x86
"""

    template += r'''
[_ISTool]
UseAbsolutePaths=true

[Icons]
Name: {group}\{cm:UninstallProgram, Rekall}; Filename: {uninstallexe}
Name: {group}\Rekall Memory Forensics (Console); Filename: {app}\Rekal.exe; WorkingDir: {app}
Name: {group}\Rekall Documentation; Filename: http://www.rekall-forensic.com/

[Registry]
Root: HKCR; Subkey: ".rkl"; ValueType: string; ValueName: ""; ValueData: "RekallForensicFile"; Flags: uninsdeletevalue
Root: HKCR; Subkey: "RekallForensicFile"; ValueType: string; ValueName: ""; ValueData: "Rekall Forensic File"; Flags: uninsdeletekey
Root: HKCR; Subkey: "RekallForensicFile\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\Rekal.exe"
Root: HKCR; Subkey: "RekallForensicFile\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\Rekal.exe"" -v webconsole --browser ""%1"""
'''
    with tempfile.NamedTemporaryFile(mode="wt", delete=False) as fd:
        fd.write(template)
        fd.close()

        try:
            # Call inno setup to build this.
            subprocess.call([r"c:\Program Files (x86)\Inno Setup 5\ISCC.exe",
                             fd.name])
        finally:
            rm(fd.name)


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

    print("Copy missing DLLs.")
    subprocess.call(["python", "tools/installers/copy_dlls.py"])

    print("Copy resources into the package.")
    # Recent versions of Pyinstaller already copy resources they know about.
    copy("rekall-core/resources", "dist/rekal")

    # Copy parso syntax files.
    parso_dir = os.path.dirname(parso.__file__)
    copy(os.path.join(parso_dir, "python"), "dist/rekal/parso")

    # Copy osqueryi.exe from the default location into the dist. NOTE:
    # Install osquery using chocolaty
    # https://chocolatey.org/packages/osquery
    path = r"c:\ProgramData\osquery\osqueryi.exe"
    if os.access(path, os.R_OK):
        print("Copying osquery into the package.")
        copy(path, "dist/rekal")

    print("Remove unnecessary crap added by pyinstaller.")
    rm("dist/rekal/_MEI")
    rm("dist/rekal/tcl/*")
    rm("dist/rekal/tk/*")
    rm("dist/rekal/tk*.dll")
    rm("dist/rekal/tcl*.dll")
    rm("dist/rekal/idlelib")
    rm("dist/rekal/Include")
    touch("dist/rekal/tcl/ignore")
    touch("dist/rekal/tk/ignore")


if __name__ == "__main__":
    main()
    build_windows_installer()
