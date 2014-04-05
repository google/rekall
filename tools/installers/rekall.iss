[Files]
; Extra Binaries to add to the package.
Source: C:\Python27\Lib\site-packages\distorm3\distorm3.dll; DestDir: {app}
Source: C:\Python27\DLLs\libyara.dll; DestDir: {app}\dlls
Source: C:\Windows\system32\MSVCR100.dll; DestDir: {app}

; Winpmem tool
Source: ..\..\..\rekall.downloads\WinPmem\winpmem_1.5.5.exe; DestDir: {app}
Source: ..\..\..\rekall.downloads\WinPmem\winpmem_write_1.5.5.exe; DestDir: {app}

; PyInstaller files.
DestDir: {app}; Source: ..\..\dist\rekal\*; Excludes: "_MEI"; Flags: recursesubdirs

[Setup]
Compression=zip
AppCopyright=GPLv2
AppPublisher=Rekall Team
AppPublisherURL=http://rekall.googlecode.com/
AppName=Rekall
AppVerName=Rekall v1.0RC7
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
OutputBaseFilename=Rekall_1.0RC7_x64
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
Name: {group}\Rekall Documentation; Filename: http://docs.rekall.googlecode.com/git/index.html
