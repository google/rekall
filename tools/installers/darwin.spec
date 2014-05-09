# -*- mode: python -*-
import os
import sys
import distorm3

a = Analysis(
    ['rekall/rekal.py'],
    hiddenimports=[],
    hookspath=None,
    runtime_hooks=None)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    exclude_binaries=True,
    name='rekal',
    debug=False,
    strip=True,
    upx=True,
    console=True)

LIBYARA = os.path.join(sys.prefix, "lib", "libyara.so")
LIBDISTORM3 = os.path.join(distorm3.__path__[0], "libdistorm3.so")

coll = COLLECT(
    exe,
    a.binaries + [
        ("distorm3/libdistorm3.so", LIBDISTORM3, "BINARY"),
        ("lib/libyara.so", LIBYARA, "BINARY"),
    ],
    a.zipfiles,
    a.datas,
    strip=None,
    upx=True,
    name='rekal')

