# -*- mode: python -*-

block_cipher = None


a = Analysis(['simpleInjector.py'],
             pathex=['C:\\Users\\user\\Downloads\\Axonet-20200122T014033Z-001\\Axonet\\PartPicker\\HexicPyth-Local\\src\\SimpleInjector'],
             binaries=[],
             datas=[],
             hiddenimports=['primitives'],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='simpleInjector',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          runtime_tmpdir=None,
          console=True )
