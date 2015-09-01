#define REKALL_VERSION '1.4.0'
#define REKALL_CODENAME 'Etzel'
#define WINPMEM_VERSION '2.0.1'

[Files]
; Extra Binaries to add to the package.
Source: C:\Python27\Lib\site-packages\distorm3\distorm3.dll; DestDir: {app}

; Winpmem tool
;Source: ..\windows\winpmem_{#WINPMEM_VERSION}.exe; DestDir: {app}
Source: ..\..\rekall-core\resources\*; DestDir: {app}; Flags: recursesubdirs

; PyInstaller files.
DestDir: {app}; Source: ..\..\dist\rekal\*; Excludes: "_MEI"; Flags: recursesubdirs

; Manuscript files for webconsole
DestDir: {app}\manuskript\; Source: ..\..\rekall-gui\manuskript\*; Flags: recursesubdirs
DestDir: {app}\webconsole\; Source: ..\..\rekall-gui\rekall_gui\plugins\webconsole\*; Flags: recursesubdirs

[Setup]
ChangesAssociations=yes
Compression=zip
AppCopyright=GPLv2
AppPublisher=Rekall Team
AppPublisherURL=http://www.rekall-forensic.com/
AppName=Rekall
AppVerName=Rekall v{#REKALL_VERSION} {#REKALL_CODENAME}
DefaultDirName={pf}\Rekall
VersionInfoVersion={#REKALL_VERSION}
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
VersionInfoCompany=Rekall Inc.
VersionInfoDescription=Rekall Memory Forensic Framework
VersionInfoCopyright=Rekall Developers.
VersionInfoProductName=Rekall Memory Forensic Framework
MinVersion=5.01.2600sp1
PrivilegesRequired=poweruser
TimeStampsInUTC=true
OutputBaseFilename=Rekall_{#REKALL_VERSION}_{#REKALL_CODENAME}_x64
VersionInfoTextVersion=Rekall Memory Forensic Framework
InfoAfterFile=..\..\README.md
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
Name: {group}\Rekall Documentation; Filename: http://www.rekall-forensic.com/

[Registry]
Root: HKCR; Subkey: ".rkl"; ValueType: string; ValueName: ""; ValueData: "RekallForensicFile"; Flags: uninsdeletevalue
Root: HKCR; Subkey: "RekallForensicFile"; ValueType: string; ValueName: ""; ValueData: "Rekall Forensic File"; Flags: uninsdeletekey
Root: HKCR; Subkey: "RekallForensicFile\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\Rekal.exe"
Root: HKCR; Subkey: "RekallForensicFile\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\Rekal.exe"" -v webconsole --browser ""%1"""
