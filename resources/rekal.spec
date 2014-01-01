# -*- mode: python -*-
a = Analysis(['rekall\\rekal.py'],
             pathex=['.'],
             hiddenimports=[],
             hookspath=None,
             runtime_hooks=None)
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          exclude_binaries=True,
          name='rekal.exe',
          debug=False,
          strip=None,
          upx=False,
          console=True,
          icon='resources/rekall.ico')
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=None,
               upx=True,
               name='rekal')
