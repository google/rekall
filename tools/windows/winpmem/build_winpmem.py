#!/usr/bin/python
import re
import os
import subprocess
import shutil

VERSION=1.4
PATH_TO_DDK = r"C:\WinDDK\7600.16385.1"
PATH_TO_VS = r"C:\Program Files\Microsoft SDKs\Windows\v7.0"

def BuildProgram(principle="test", store=None, signtool_params=""):
    args = dict(path=PATH_TO_VS,
                executable_src=os.path.join(os.getcwd(), "executable"),
                principle=principle, store="",
                signtool_params=signtool_params,
                version=VERSION,
                write_prefix="")

    if store:
        args["store"] = " /s %s " % store

    env_command = ["cmd", "/E:ON", "/V:ON", "/K",
                   r"%(path)s\Bin\SetEnv.cmd" % args]

    pipe = subprocess.Popen(env_command, stdin=subprocess.PIPE, shell=False)
    pipe.communicate("cd \"%(executable_src)s\" && del /q release "
                     "&& msbuild winpmem.vcproj /p:Configuration=Release \n" % args)

    build_path = "%(executable_src)s/release/winpmem.exe" % args

    # Sign the binary.
    pipe = subprocess.Popen(env_command, stdin=subprocess.PIPE, shell=False)

    cmd = ("Signtool sign /v %(store)s /n %(principle)s %(signtool_params)s "
           "/t http://timestamp.verisign.com/scripts/timestamp.dll "
           "executable\\release\\winpmem.exe"
           "\n") % args

    pipe.communicate(cmd)


    if "Write Supported" in open(build_path, "rb").read():
        args["write_prefix"] = "write_"

    output_path = "winpmem_%(write_prefix)s%(version)s.exe" % args
    shutil.copyfile(build_path, output_path)


    print "\r\n\r\nCreated file %s" % output_path


def BuildDriver(arch, target, principle="test", store=None, signtool_params=""):
    args = dict(path=PATH_TO_DDK,
                arch=arch,
                target=target, store="",
                principle=principle, signtool_params=signtool_params,
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
    if ("test" not in principle and
        "Write Supported" in open(output_path, "rb").read()):
        raise RuntimeError("Tried to sign binaries with write support!!!!!")

    pipe = subprocess.Popen(cmd, stdin=subprocess.PIPE, shell=False)
    cmd = ("cd \"%(cwd)s\" && "
           "Signtool sign /v %(store)s /n %(principle)s %(signtool_params)s "
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
        principle="Michael",
        signtool_params="/ac \"certs\\DigiCert High Assurance EV Root CA.crt\" ")
    x64_driver = BuildDriver("x64", "WIN7", **args)
    x32_driver = BuildDriver("x86", "WXP", **args)
    BuildProgram(**args)

def BuildTestSignedBinries():
    args = dict(store="PrivateCertStore",
                principle="test")
    BuildDriver("x64", "WIN7", **args)
    BuildDriver("x86", "WXP", **args)
    BuildProgram(**args)

CleanUpOldFiles()
BuildTestSignedBinries()
#BuildSignedProductionBinaries()
