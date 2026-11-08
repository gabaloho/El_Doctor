; El Doctor - Windows setup wizard (Inno Setup 6).  Built by packaging/build_release.py:
;   ISCC /DAppVersion=2.1.0 /DSourceDir=<folder with eldoctor.exe, El Doctor.exe, docs, eldoctor.ico> /DOutputDir=<out>
;
; What the person installing sees:
;   1. "Install for all users (recommended)" or "Install for me only" (no administrator rights needed)
;   2. Licence, install folder, shortcuts, and - for all users - "Protect this computer around the clock"
;   3. Protection chosen on a first installation: who manages El Doctor (user name, e-mail, password)
;   4. Finish: "Open El Doctor now"
; Upgrades: run the new setup; accounts, keys and records are kept.  Uninstall: Settings > Apps > El Doctor
; (asks whether to delete the records; default: keep them).
;
; Silent installation (IT departments):
;   set ELDOCTOR_ADMIN_PASSWORD=...   (never on the command line)
;   ElDoctor-Setup-<version>.exe /VERYSILENT /ALLUSERS /TASKS="service,desktopicon" /ADMINUSER=alice /ADMINEMAIL=alice@corp.example /ADMINNAME="Alice Smith"
;   ElDoctor-Setup-<version>.exe /VERYSILENT /CURRENTUSER            (personal installation)

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\..\dist"
#endif
#ifndef OutputDir
  #define OutputDir "..\..\release"
#endif
#define AppName "El Doctor"
#define TaskName "ElDoctor Agent"

[Setup]
AppId={{6F2B8C1E-4D3A-4E8B-9C7F-2A1D5E6B8F40}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=El Doctor contributors
AppComments=Endpoint security monitor, threat response and user-activity record
DefaultDirName={autopf}\El Doctor
DefaultGroupName=El Doctor
DisableProgramGroupPage=yes
LicenseFile={#SourceDir}\LICENSE
OutputDir={#OutputDir}
OutputBaseFilename=ElDoctor-Setup-{#AppVersion}
SetupIconFile={#SourceDir}\eldoctor.ico
UninstallDisplayIcon={app}\El Doctor.exe
UninstallDisplayName={#AppName}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; "Install for all users" (administrator) or "for me only" (no administrator rights)
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog commandline
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
CloseApplications=yes
RestartApplications=no
ChangesEnvironment=yes
VersionInfoVersion={#AppVersion}
VersionInfoProductName={#AppName}
VersionInfoDescription={#AppName} setup
#ifdef SignTool
SignTool={#SignTool}
SignedUninstaller=yes
#endif

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "service"; Description: "&Protect this computer around the clock (recommended: runs in the background for every user, even when nobody has El Doctor open)"; GroupDescription: "Protection:"; Check: IsAdminInstallMode
Name: "autostart"; Description: "Open El Doctor when I sign in (it protects while it is open)"; GroupDescription: "Protection:"; Flags: unchecked; Check: not IsAdminInstallMode
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"

[Files]
Source: "{#SourceDir}\El Doctor.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\eldoctor.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\eldoctor.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\LICENSE"; DestDir: "{app}\docs"; DestName: "LICENSE.txt"; Flags: ignoreversion
Source: "{#SourceDir}\README.md"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "{#SourceDir}\INSTALL.md"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "{#SourceDir}\CHANGELOG.md"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "{#SourceDir}\SECURITY.md"; DestDir: "{app}\docs"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\El Doctor"; Filename: "{app}\El Doctor.exe"; IconFilename: "{app}\eldoctor.ico"; Comment: "El Doctor security console"
Name: "{autoprograms}\El Doctor (command line)"; Filename: "{cmd}"; Parameters: "/k ""cd /d ""{app}"" && eldoctor.exe --help"""; IconFilename: "{app}\eldoctor.ico"; Comment: "El Doctor commands (advanced)"
Name: "{autodesktop}\El Doctor"; Filename: "{app}\El Doctor.exe"; IconFilename: "{app}\eldoctor.ico"; Tasks: desktopicon
Name: "{userstartup}\El Doctor"; Filename: "{app}\El Doctor.exe"; IconFilename: "{app}\eldoctor.ico"; Tasks: autostart

[Run]
Filename: "{app}\El Doctor.exe"; Description: "Open El Doctor now"; Flags: postinstall nowait skipifsilent runasoriginaluser

[Code]
var
  AdminPage: TInputQueryWizardPage;
  PurgeData: Boolean;

function SetEnvironmentVariable(lpName: string; lpValue: string): BOOL;
  external 'SetEnvironmentVariableW@kernel32.dll stdcall';

{ A previous all-users installation whose records were kept: its accounts are reused, nobody is asked again. }
function ServiceConfiguredBefore(): Boolean;
var
  Dir: string;
begin
  Result := RegQueryStringValue(HKLM, 'SOFTWARE\ElDoctor', 'DataDir', Dir) and DirExists(Dir);
end;

function DefaultUserName(): string;
var
  I: Integer;
  S, R: string;
begin
  S := Lowercase(GetUserNameString());
  R := '';
  for I := 1 to Length(S) do
    if ((S[I] >= 'a') and (S[I] <= 'z')) or ((S[I] >= '0') and (S[I] <= '9')) or (S[I] = '.') or (S[I] = '_') or (S[I] = '-') then
      R := R + S[I];
  if (Length(R) < 3) or (R[1] < 'a') or (R[1] > 'z') then
    R := 'admin';
  Result := R;
end;

procedure InitializeWizard();
begin
  AdminPage := CreateInputQueryPage(wpSelectTasks,
    'Who manages El Doctor?',
    'This person approves responses, manages users and receives reports about deleted files.',
    'El Doctor asks for this account when someone opens it. You can add more people later (Users & settings).');
  AdminPage.Add('&User name (3-32 letters, digits, . _ -; starts with a letter):', False);
  AdminPage.Add('&Full name:', False);
  AdminPage.Add('&E-mail (reports about deleted files go here):', False);
  AdminPage.Add('&Password (at least 10 characters, with 3 of: lower case, upper case, digit, symbol):', True);
  AdminPage.Add('&Repeat the password:', True);
  AdminPage.Values[0] := DefaultUserName();
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := (PageID = AdminPage.ID) and
            ((not WizardIsTaskSelected('service')) or ServiceConfiguredBefore());
end;

function CountClasses(const S: string): Integer;
var
  I: Integer;
  L, U, D, O: Boolean;
begin
  L := False; U := False; D := False; O := False;
  for I := 1 to Length(S) do
    if (S[I] >= 'a') and (S[I] <= 'z') then L := True
    else if (S[I] >= 'A') and (S[I] <= 'Z') then U := True
    else if (S[I] >= '0') and (S[I] <= '9') then D := True
    else O := True;
  Result := Ord(L) + Ord(U) + Ord(D) + Ord(O);
end;

function ValidUserName(const S: string): Boolean;
var
  I: Integer;
begin
  Result := (Length(S) >= 3) and (Length(S) <= 32) and
            (((S[1] >= 'a') and (S[1] <= 'z')) or ((S[1] >= 'A') and (S[1] <= 'Z')));
  if Result then
    for I := 1 to Length(S) do
      if not (((S[I] >= 'a') and (S[I] <= 'z')) or ((S[I] >= 'A') and (S[I] <= 'Z')) or
              ((S[I] >= '0') and (S[I] <= '9')) or (S[I] = '.') or (S[I] = '_') or (S[I] = '-')) then
        Result := False;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  AtPos: Integer;
begin
  Result := True;
  if CurPageID <> AdminPage.ID then
    Exit;
  if not ValidUserName(AdminPage.Values[0]) then begin
    MsgBox('The user name must be 3 to 32 characters: letters, digits, dot, underscore or dash, starting with a letter.', mbError, MB_OK);
    Result := False; Exit;
  end;
  AtPos := Pos('@', AdminPage.Values[2]);
  if (AtPos < 2) or (Pos('.', Copy(AdminPage.Values[2], AtPos, Length(AdminPage.Values[2]))) = 0) then begin
    MsgBox('Please enter a valid e-mail address: reports about deleted files are sent there.', mbError, MB_OK);
    Result := False; Exit;
  end;
  if (Length(AdminPage.Values[3]) < 10) or (CountClasses(AdminPage.Values[3]) < 3) then begin
    MsgBox('The password needs at least 10 characters and 3 of: lower case, upper case, digit, symbol.', mbError, MB_OK);
    Result := False; Exit;
  end;
  if Pos(Lowercase(AdminPage.Values[0]), Lowercase(AdminPage.Values[3])) > 0 then begin
    MsgBox('The password must not contain the user name.', mbError, MB_OK);
    Result := False; Exit;
  end;
  if AdminPage.Values[3] <> AdminPage.Values[4] then begin
    MsgBox('The two passwords are different.', mbError, MB_OK);
    Result := False; Exit;
  end;
end;

{ Before files are replaced (upgrade): ask the running agent to stop cleanly - a hard kill would be recorded as a
  monitoring gap - then make sure the scheduled task is stopped. }
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Result := '';
  if IsAdminInstallMode and FileExists(ExpandConstant('{app}\eldoctor.exe')) then begin
    Exec(ExpandConstant('{app}\eldoctor.exe'), 'uninstall-service --stop-only --quiet', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{sys}\schtasks.exe'), '/End /TN "{#TaskName}"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
  LogFile, Msg: string;
begin
  if (CurStep <> ssPostInstall) or (not WizardIsTaskSelected('service')) then
    Exit;
  LogFile := ExpandConstant('{app}\install-service.log');
  { the account travels in this process's environment (inherited by eldoctor.exe), never on a command line }
  if not WizardSilent() then begin
    SetEnvironmentVariable('ELDOCTOR_ADMIN_USER', AdminPage.Values[0]);
    SetEnvironmentVariable('ELDOCTOR_ADMIN_NAME', AdminPage.Values[1]);
    SetEnvironmentVariable('ELDOCTOR_ADMIN_EMAIL', AdminPage.Values[2]);
    SetEnvironmentVariable('ELDOCTOR_ADMIN_PASSWORD', AdminPage.Values[3]);
  end else begin
    { silent: /ADMINUSER= /ADMINNAME= /ADMINEMAIL= override the ELDOCTOR_ADMIN_* environment when given;
      ELDOCTOR_ADMIN_PASSWORD is set by the administrator before running the silent setup }
    if ExpandConstant('{param:ADMINUSER|}') <> '' then
      SetEnvironmentVariable('ELDOCTOR_ADMIN_USER', ExpandConstant('{param:ADMINUSER|}'));
    if ExpandConstant('{param:ADMINNAME|}') <> '' then
      SetEnvironmentVariable('ELDOCTOR_ADMIN_NAME', ExpandConstant('{param:ADMINNAME|}'));
    if ExpandConstant('{param:ADMINEMAIL|}') <> '' then
      SetEnvironmentVariable('ELDOCTOR_ADMIN_EMAIL', ExpandConstant('{param:ADMINEMAIL|}'));
  end;
  WizardForm.StatusLabel.Caption := 'Turning on protection for this computer...';
  if not Exec(ExpandConstant('{app}\eldoctor.exe'), 'install-service --quiet --log "' + LogFile + '"', ExpandConstant('{app}'),
              SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    ResultCode := -1;
  SetEnvironmentVariable('ELDOCTOR_ADMIN_PASSWORD', '');
  if not WizardSilent() then
    AdminPage.Values[3] := '';
  if ResultCode <> 0 then begin
    Msg := 'El Doctor is installed, but protection for the whole computer could not be turned on.' + #13#10#13#10 +
           'Details are in:' + #13#10 + LogFile + #13#10#13#10 +
           'You can still use El Doctor, and try again later from an administrator command prompt:' + #13#10 +
           '"' + ExpandConstant('{app}\eldoctor.exe') + '" install-service';
    SuppressibleMsgBox(Msg, mbError, MB_OK, IDOK);
    Log('install-service failed with code ' + IntToStr(ResultCode));
  end;
end;

function InitializeUninstall(): Boolean;
begin
  Result := True;
  PurgeData := False;
  if not UninstallSilent() then
    PurgeData := MsgBox('Also delete El Doctor''s records on this computer (alerts, user-activity record, evidence, accounts)?' + #13#10#13#10 +
                        'Choose No to keep them: reinstalling El Doctor later will find them again.',
                        mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
  Args: string;
begin
  if CurUninstallStep = usUninstall then begin
    { remove the background service while eldoctor.exe is still there (a personal installation has none: no-op) }
    Args := 'uninstall-service --quiet';
    if PurgeData then
      Args := Args + ' --purge';
    if IsAdminInstallMode then
      Exec(ExpandConstant('{app}\eldoctor.exe'), Args, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
  if (CurUninstallStep = usPostUninstall) and PurgeData then
    DelTree(ExpandConstant('{%USERPROFILE}\.eldoctor'), True, True, True);
end;
