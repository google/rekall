rem Run this batch file from the root rekall directory to build a new Rekall installer.

set SIGNER=Michael

del /s /q build
del /s /q dist

rem Fix components that dont play well with pyinstaller.
python tools\installers\fix_deps.py

pyinstaller --onedir -y -i resources\rekall.ico tools\installers\rekal.py

rem signtool sign /n %SIGNER% /t http://timestamp.verisign.com/scripts/timestamp.dll dist\rekal\*.exe

"c:\Program Files (x86)\Inno Setup 5\ISCC.exe" tools\installers\rekall.iss
