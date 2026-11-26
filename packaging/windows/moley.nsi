; Moley installer for Windows: the daemon and CLI (moley.exe) as a service,
; the tray app (moley-ui.exe), the browser extension's files and native host.
;
;   makensis -DVERSION=0.2.0 -DBIN=<dir with the exes> -DEXT=<extension dist> moley.nsi
;
; Silent install: Moley-Setup.exe /S. With /launch (the updater passes it)
; the tray starts afterwards.

Unicode true
ManifestDPIAware true
RequestExecutionLevel admin
SetCompressor /SOLID lzma

!include MUI2.nsh
!include FileFunc.nsh
!include WinMessages.nsh
!include StrFunc.nsh
${StrStr}
${UnStrRep}

Name "Moley"
OutFile "Moley-Setup-${VERSION}.exe"
InstallDir "$PROGRAMFILES64\Moley"
InstallDirRegKey HKLM "Software\Moley" "InstallDir"
BrandingText "Moley ${VERSION}"
VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "Moley"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "FileDescription" "Moley installer"
VIAddVersionKey "LegalCopyright" "GPL-3.0"

!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\Moley"
!define MUI_ICON "${ICON}"
!define MUI_UNICON "${ICON}"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "Open Moley"
!define MUI_FINISHPAGE_RUN_FUNCTION LaunchTray

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

; Explorer starts the tray as the signed-in user, not elevated like us.
Function LaunchTray
  Exec '"$WINDIR\explorer.exe" "$INSTDIR\moley-ui.exe"'
FunctionEnd

Section "Moley" Main
  SetShellVarContext current
  ; Close the tray; the service is stopped and re-registered by
  ; `service install` below, so files in use get replaced.
  nsExec::Exec 'taskkill /F /IM moley-ui.exe'
  nsExec::Exec 'sc.exe stop Moley'
  ; Let it close its tunnels, but not forever: whatever is still running
  ; (a stuck stop, the browser's native host) holds moley.exe open.
  nsExec::Exec `powershell.exe -NoProfile -Command "try { (Get-Service Moley -ErrorAction Stop).WaitForStatus('Stopped', '00:00:15') } catch {}"`
  nsExec::Exec 'taskkill /F /IM moley.exe'
  Sleep 500

  SetOutPath "$INSTDIR"
  File "${BIN}\moley.exe"
  File "${BIN}\moley-ui.exe"
  File "${ROOT}\LICENSE"
  SetOutPath "$INSTDIR\extension"
  File /r "${EXT}\*.*"
  SetOutPath "$INSTDIR"

  ; The service (it takes over a per-user daemon and its config), and the
  ; browser's native host for this user.
  DetailPrint "Installing the Moley service…"
  nsExec::ExecToLog '"$INSTDIR\moley.exe" service install'
  Pop $0
  StrCmp $0 "0" +2
    MessageBox MB_ICONEXCLAMATION|MB_OK "The Moley service didn't install (exit $0). Moley still routes the browser; see the details for why." /SD IDOK
  nsExec::ExecToLog '"$INSTDIR\moley.exe" browser install'

  ; The tray opens at sign-in (this replaces a per-user daemon's entry).
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "Moley" '"$INSTDIR\moley-ui.exe" --hidden'
  CreateShortcut "$SMPROGRAMS\Moley.lnk" "$INSTDIR\moley-ui.exe"

  ; `moley` in every terminal.
  ReadRegStr $1 HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path"
  ${StrStr} $3 "$1;" "$INSTDIR;"
  StrCmp $3 "" 0 +3
    WriteRegExpandStr HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path" "$1;$INSTDIR"
    SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=2000

  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "Software\Moley" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayName" "Moley"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "Publisher" "Moley"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayIcon" "$INSTDIR\moley-ui.exe"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "${UNINSTALL_KEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "EstimatedSize" $0

  ${GetParameters} $0
  ${GetOptions} $0 "/launch" $1
  IfErrors +2
    Call LaunchTray
SectionEnd

Section "Uninstall"
  SetShellVarContext current
  nsExec::Exec 'taskkill /F /IM moley-ui.exe'
  ; Removing the service also lifts a persistent kill switch. Your config
  ; stays in %ProgramData%\Moley.
  nsExec::ExecToLog '"$INSTDIR\moley.exe" service uninstall --yes'
  nsExec::ExecToLog '"$INSTDIR\moley.exe" browser uninstall'
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "Moley"
  Delete "$SMPROGRAMS\Moley.lnk"

  ReadRegStr $1 HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path"
  ${UnStrRep} $1 $1 ";$INSTDIR" ""
  WriteRegExpandStr HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path" $1
  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=2000

  RMDir /r "$INSTDIR\extension"
  Delete "$INSTDIR\moley.exe"
  Delete "$INSTDIR\moley-ui.exe"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "${UNINSTALL_KEY}"
  DeleteRegKey HKLM "Software\Moley"
SectionEnd
