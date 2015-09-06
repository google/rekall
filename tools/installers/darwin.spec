# -*- mode: python -*-
import os
import sys
import distorm3

a = Analysis(
    ['tools/installers/rekal.py'],
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

# The yara installer is dumb and puts the lib in dumb places. I have given up
# trying to guess where it'll end up after we pip install it.
LIBYARA = None
for dirpath, _, files in os.walk(sys.prefix):
    if "yara.so" in files:
        LIBYARA = os.path.join(dirpath, "yara.so")
        break

if LIBYARA is None:
    raise RuntimeError("Could not find yara.so.")


LIBDISTORM3 = os.path.join(distorm3.__path__[0], "libdistorm3.so")

coll = COLLECT(
    exe,
    a.binaries + [
        ("libdistorm3.so", LIBDISTORM3, "BINARY"),
        ("lib/yara.so", LIBYARA, "BINARY"),
    ],
    a.zipfiles,
    a.datas,
    strip=None,
    upx=True,
    name='rekal')
