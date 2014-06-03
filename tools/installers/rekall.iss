[Files]
; Extra Binaries to add to the package.
Source: C:\Python27\Lib\site-packages\distorm3\distorm3.dll; DestDir: {app}
Source: C:\Python27\DLLs\libyara.dll; DestDir: {app}\dlls

; The ISS installer is a 32 bit app and for this 64 bit build needs to package
; the 64 dll.
Source: C:\Windows\sysnative\MSVCR100.dll; DestDir: {app}
Source: C:\Windows\sysnative\MSVCP100.dll; DestDir: {app}

; Winpmem tool
Source: ..\..\..\rekall.downloads\WinPmem\winpmem_1.5.5.exe; DestDir: {app}
Source: ..\..\..\rekall.downloads\WinPmem\winpmem_write_1.5.5.exe; DestDir: {app}

; PyInstaller files.
DestDir: {app}; Source: ..\..\dist\rekal\*; Excludes: "_MEI"; Flags: recursesubdirs

; Manuscript files for webconsole
DestDir: {app}\manuskript\; Source: ..\..\manuskript\*; Flags: recursesubdirs
DestDir: {app}\webconsole\; Source: ..\..\rekall\plugins\tools\webconsole\*; Flags: recursesubdirs

[Setup]
Compression=zip
AppCopyright=GPLv2
AppPublisher=Rekall Team
AppPublisherURL=http://www.rekall-forensic.com/
AppName=Rekall
AppVerName=Rekall v1.0RC9
DefaultDirName={pf}\Rekall
VersionInfoVersion=1.0
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
VersionInfoCompany=Rekall Inc.
VersionInfoDescription=Rekall Memory Forensic Framework
VersionInfoCopyright=Rekall Developers.
VersionInfoProductName=Rekall Memory Forensic Framework
MinVersion=5.01.2600sp1
PrivilegesRequired=poweruser
TimeStampsInUTC=true
OutputBaseFilename=Rekall_1.0RC9_x64
VersionInfoTextVersion=Rekall Memory Forensic Framework
InfoAfterFile=..\..\README.txt
LicenseFile=..\..\LICENSE.txt
AllowNoIcons=true
AlwaysUsePersonalGroup=true
DefaultGroupName=Rekall Memory Forensics
SetupIconFile=..\..\resources\rekall.ico
UninstallDisplayIcon={app}\rekall.exe

[_ISTool]
UseAbsolutePaths=true

[Icons]
Name: {group}\{cm:UninstallProgram, Rekall}; Filename: {uninstallexe}
Name: {group}\Rekall Memory Forensics (Console); Filename: {app}\Rekal.exe; WorkingDir: {app}
Name: {group}\Rekall Memory Forensics (Notebook); Filename: {app}\Rekal.exe; WorkingDir: {app}; Parameters: notebook
Name: {group}\Rekall Documentation; Filename: http://www.rekall-forensic.com/docs.html
