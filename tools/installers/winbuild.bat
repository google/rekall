rem Run this batch file from the root rekall directory to build a new Rekall installer.

set SIGNER=Michael

del /s /q build
del /s /q dist

c:\Python27\python.exe c:\Python27\PyInstaller-2.1\pyinstaller.py --onedir -y -i resources\rekall.ico tools\installers\rekal.py

signtool sign /n %SIGNER% /t http://timestamp.verisign.com/scripts/timestamp.dll dist\rekal\*.exe

"c:\Program Files (x86)\Inno Setup 5\ISCC.exe" tools\installers\rekall.iss
