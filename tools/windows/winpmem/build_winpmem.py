#!/usr/bin/python
"""Build script for winpmem.

This script builds the drivers and then the userspace application which embeds
them. To have it run, you will need to install the following components on a
windows system:

1) .Net framework:
   http://www.microsoft.com/en-us/download/details.aspx?id=17851

2) Microsoft Windows SDK for Windows 7 and .NET Framework 4
   http://www.microsoft.com/en-us/download/details.aspx?id=8279

   Make sure you select the c++ compilers here.

3) Windows Driver Kit Version 7.1.0:
   http://www.microsoft.com/en-us/download/details.aspx?id=11800

4) Python 2.7 from python.org.

If you install these in different locations be sure to adjust the constants
below.
"""
import re
import os
import subprocess
import shutil

VERSION="1.6.0"
PATH_TO_DDK = r"C:\WinDDK\7600.16385.1"
PATH_TO_VS = r"C:\Program Files\Microsoft SDKs\Windows\v7.1"

def BuildProgram(principal="test", store=None, signtool_params=""):
    args = dict(path=PATH_TO_VS,
                executable_src=os.path.join(os.getcwd(), "executable"),
                principal=principal, store="",
                signtool_params=signtool_params,
                version=VERSION,
                write_prefix="")

    if store:
        args["store"] = " /s %s " % store

    # We want to support the lowest common denominator for the winpmem usermode
    # application, so we choose to target Windows XP x86.
    env_command = ["cmd", "/E:ON", "/V:ON", "/K",
                   r"%(path)s\Bin\SetEnv.cmd" % args,
                   "/Release", "/x86", "/xp"]

    pipe = subprocess.Popen(env_command, stdin=subprocess.PIPE, shell=False)
    pipe.communicate(
        "cd \"%(executable_src)s\" && del /q release "
        "&& msbuild winpmem.vcxproj /p:Configuration=Release \n" % args)

    if pipe.returncode:
        raise IOError("Something went wrong")

    build_path = "%(executable_src)s/release/winpmem.exe" % args

    # Sign the binary.
    pipe = subprocess.Popen(env_command, stdin=subprocess.PIPE, shell=False)

    cmd = ("Signtool sign /v %(store)s /n %(principal)s %(signtool_params)s "
           "/t http://timestamp.verisign.com/scripts/timestamp.dll "
           "executable\\release\\winpmem.exe"
           "\n") % args

    pipe.communicate(cmd)


    if "Write Supported" in open(build_path, "rb").read():
        args["write_prefix"] = "write_"

    output_path = "winpmem_%(write_prefix)s%(version)s.exe" % args
    shutil.copyfile(build_path, output_path)


    print "\r\n\r\nCreated file %s" % output_path


def BuildDriver(arch, target, principal="test", store=None, signtool_params=""):
    args = dict(path=PATH_TO_DDK,
                arch=arch,
                target=target, store="",
                principal=principal, signtool_params=signtool_params,
                cwd=os.getcwd())

    if store:
        args["store"] = " /s %s " % store


    if arch=="x64":
        args["arch2"] = "amd64"
    else:
        args["arch2"] = "i386"

    cmd = (r"cmd /k %(path)s\bin\setenv.bat %(path)s chk %(arch)s %(target)s "
           "no_oacr" % args)

    pipe = subprocess.Popen(cmd, stdin=subprocess.PIPE, shell=False)
    pipe.communicate("cd \"%(cwd)s\" && build /w \n" % args)

    output_path = r"release/%(arch2)s/winpmem.sys" % args

    # Before we proceed we need to make sure the binaries have no write support.
    if ("test" not in principal and
        "Write Supported" in open(output_path, "rb").read()):
        raise RuntimeError("Tried to sign binaries with write support!!!!!")

    pipe = subprocess.Popen(cmd, stdin=subprocess.PIPE, shell=False)
    cmd = ("cd \"%(cwd)s\" && "
           "Signtool sign /v %(store)s /n %(principal)s %(signtool_params)s "
           "/t http://timestamp.verisign.com/scripts/timestamp.dll "
           "release\%(arch2)s\winpmem.sys"
           "\n") % args

    pipe.communicate(cmd)

    shutil.copyfile(output_path, "binaries/winpmem_%(arch)s.sys" % args)


def CleanUpOldFiles():
    try:
        shutil.rmtree("release")
    except OSError:
        pass

    try:
        for x in os.listdir("binaries"):
            os.remove(os.path.join("binaries", x))
    except OSError:
        pass


def BuildSignedProductionBinaries():
    args = dict(
        principal="Michael",
        signtool_params="/ac \"certs\\DigiCert_High_Assurance_EV_Root_CA.crt\" ")
    x64_driver = BuildDriver("x64", "WIN7", **args)
    x32_driver = BuildDriver("x86", "WXP", **args)
    BuildProgram(**args)

def BuildTestSignedBinries():
    args = dict(store="PrivateCertStore",
                principal="test")
    BuildDriver("x64", "WIN7", **args)
    BuildDriver("x86", "WXP", **args)
    BuildProgram(**args)

CleanUpOldFiles()
BuildTestSignedBinries()
BuildSignedProductionBinaries()
