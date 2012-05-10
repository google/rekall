#!python
# Tool for WINDDK
#
# Author: Wander Lairson Costa
# email: wander {dot} lairson {at} gmail {dot} com
#
# Description:
#
# Environment variables:
# DDK_VERSION - the ddk version in use.
# DDKFLAGS - line command arguments to the build utility.
# TARGET_OS - W2K, WXP, WNET, WLH, WIN7.
# TARGET_ARCH - ia64, x86, x64.
# BUILD_TYPE - fre, chk
#
# History:
#   02/06/2011
#       - Modified by David Collett to allow cross-compiling under wine.
#   10/09/2009
#       - Initial version.

import sys
import os
import os.path
import subprocess
import re
import SCons.Node.FS
import SCons.Builder
import glob
import SCons.Node.FS

# Get the contents of the file with line
# continuation preprocessed
def _get_file_contents(f):
    output = ''
    for s in f:
        s = s.strip()
        if s.endswith('\\'):
            s = s[:s.rindex('\\')] + ' '
        elif s.endswith('/'):
            s = s[:s.rindex('/')] + ' '
        else:
            s += '\n'
        output += s
    return output

# Get the variables of the file
def _get_file_vars(f, vars):
    contents = _get_file_contents(f)
    dvars = {}
    for k in vars:
        r = re.compile(k + r'\s*=\s*([^\n]+)', re.I)
        m = r.search(contents)
        if m:
            dvars[k] = m.group(1).strip()
    return dvars

class _Emitter(object):
    type_map = {'PROGRAM':'exe',
                'PROGLIB':'exe',
                'DYNLINK':'dll',
                'LIBRARY':'lib',
                'DRIVER_LIBRARY':'lib',
                'DRIVER':'sys',
                'EXPORT_DRIVER':'sys',
                'MINIPORT':'sys',
                'GDI_DRIVER':'dll',
                'HAL':'dll',
                'NOTARGET':None}
    def __init__(self, env):
        self.env = env
        self.type = env.get('BUILD_TYPE', 'fre')
        self.version = env.get('TARGET_OS', '')
        self.primary_arch = env.get('TARGET_ARCH', 'x86')
        self.secondary_arch = env.get('TARGET_ARCH', 'x86')
        if self.secondary_arch == 'x86':
            self.secondary_arch = 'i386'
    def __call__(self, basedir):
        self.files = []
        self._emitter_helper(basedir)
        return self.files

    def _emitter_helper(self, cwd):
        sources_file = os.path.join(cwd, 'SOURCES')
        dirs_file = os.path.join(cwd, 'DIRS')
        if os.path.exists(sources_file):
            f = open(sources_file, 'r')
            vars = _get_file_vars(
                        f,
                        ('TARGETPATH',
                         'TARGETNAME',
                         'TARGETTYPE')
                    )
            objdir = '%s%s_%s_%s' % (vars.get('TARGETPATH', 'obj'),
                                     self.type,
                                     self.version,
                                     self.primary_arch)
            path = os.path.join(objdir, self.secondary_arch)
            ext = self.type_map[vars['TARGETTYPE']]
            binary = '%s.%s' % (vars['TARGETNAME'],ext)
            self.files.append(os.path.join(cwd, path, binary))
        if os.path.exists(dirs_file):
            f = open(dirs_file, 'r')
            vars = _get_file_vars(f, ('DIRS', 'OPTIONAL_DIRS'))
            for d in vars.get('DIRS', '').split():
                path = os.path.join(cwd, d)
                self._emitter_helper(path)

def check_output(*args):
    return  subprocess.Popen(*args, stdout=subprocess.PIPE).communicate()[0]

def _get_systemdrive():
    """ return the system drive (linux path) """
    try:
        return check_output(["winepath", "-u", "c:"]).strip()
    except subprocess.CalledProcessError:
        raise OSError("winepath failed, is WINE installed?")

def _wine_path(path):
    """ Convert a local system path to a wine path """
    try:
        return check_output(["winepath", "-w", path]).strip()
    except subprocess.CalledProcessError:
        raise OSError("winepath failed, is WINE installed?")

# Obtain the WinDDK root path
def _get_root_path(version = None):
    root_drive = _get_systemdrive()
    prefix = os.path.join(root_drive, 'WINDDK')

    if not os.path.exists(prefix):
        return None, None

    if version is None:
        current = ''
        for inst in glob.glob(os.path.join(prefix, '*')):
            if inst > current:
                current = inst
        path = current
        version = os.path.split(path)[1]
    else:
        path = os.path.join(prefix, version)

    if os.path.exists(path):
        return _wine_path(path), version
    else:
        return None, None

def _build(target, source, env):
    root_path, version = _get_root_path(env.get('DDK_VERSION', None))
    env['DDK_VERSION'] = version
    cmd = os.path.join(root_path, 'bin', 'setenv.bat')
    arch = env.get('TARGET_ARCH', 'x86')
    env['TARGET_ARCH'] = arch
    if not env.has_key('BUILD_TYPE'):
        env['BUILD_TYPE'] = 'fre'

    # before version 7, we don't supply processor architecture
    # when it is x86
    if arch == 'x86' and env['DDK_VERSION'].split('.')[0][0] < '7':
        arch = ''

    args = ["/usr/bin/wine", "cmd.exe", "/k",
            cmd,
            root_path,
            env['BUILD_TYPE'],
            arch, "no_oacr",
            '' if env.get('TARGET_OS', None) is None else env['TARGET_OS']] 

    print args
    pipe = subprocess.Popen(args,
                            shell=False,
                            stdin=subprocess.PIPE)

    pipe.communicate("cd %s && build.exe %s\n" % (os.getcwd(), env.get('DDKFLAGS', '')))
    return 0

def _emitter(target, source, env):
    emit = _Emitter(env)
    target = emit(os.getcwd())
    return target, source

def generate(env):
    builder = SCons.Builder.Builder(action = _build,
                                    emitter = _emitter,
                                    source_factory = SCons.Node.FS.Dir,
                                    single_source=0)
    env['BUILDERS']['DDKBuild'] = builder

def exists(env):
    return _get_root_path(env.get('DDK_VERSION', None))[0] is not None
