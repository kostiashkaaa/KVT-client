; Обновление уже установленного KVT (KVT-x.y.z-update.exe, шаг 5.7).
;
; Собирает scripts\build-release.ps1 тем же makensis, что и полный установщик:
;   /DVERSION=0.2.0 /DMIN_VERSION=0.1.0 /DSRC=<target\release> /DOUTFILE=<путь>
;   /DPLUGINS=<каталог nsis_tauri_utils.dll> /DICON=<icon.ico>
;   /DWITH_CORES, /DWITH_ZAPRET и /DWITH_TGPROXY — если ядра, комплект zapret или
;   прокси для Telegram изменились с MIN_VERSION (в установках до 0.9.3 прокси нет).
;
; Что делает: находит KVT по реестру установщика; если его нет или версия старше
; MIN_VERSION — предлагает полную установку и ничего не меняет. Иначе закрывает
; окно KVT, останавливает службу (VPN и kill switch на несколько секунд выключаются),
; убирает прежние файлы в резервную папку, ставит новые и регистрирует службу
; (`kvt-service install` пишет и манифест с хэшем нового kvt.exe). Служба не
; поднялась — прежние файлы возвращаются. Настройки, подписки и ProgramData не трогаются.

Unicode true
ManifestDPIAware true
RequestExecutionLevel admin
SetCompressor /SOLID lzma

!include MUI2.nsh
!include LogicLib.nsh
!include WordFunc.nsh
!include x64.nsh
!addplugindir "${PLUGINS}"

!define PRODUCTNAME "KVT"
!define UNINSTKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCTNAME}"
!define MANUPRODUCTKEY "Software\KVT\KVT"
!define RELEASES "https://github.com/kostiashkaaa/KVT-client/releases"
!define BACKUP ".kvt-update-backup"

Name "KVT ${VERSION}"
Caption "$(KvtCaption)"
OutFile "${OUTFILE}"
BrandingText "KVT ${VERSION}"
VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "KVT"
VIAddVersionKey "FileDescription" "KVT update"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "KVT — GPL-3.0-or-later"
ShowInstDetails show

; Установленная версия (для страницы приветствия и сообщений).
Var Installed

!define MUI_ICON "${ICON}"
!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE "$(KvtCaption)"
!define MUI_WELCOMEPAGE_TEXT "$(KvtWelcome)"
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "$(KvtRun)"
!define MUI_FINISHPAGE_RUN_FUNCTION RunKvt
!insertmacro MUI_PAGE_FINISH
; Язык — как у Windows: русский для русской Windows, иначе английский (первый в списке).
!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "Russian"

LangString KvtCaption ${LANG_ENGLISH} "Updating KVT to ${VERSION}"
LangString KvtCaption ${LANG_RUSSIAN} "Обновление KVT до ${VERSION}"
LangString KvtWelcome ${LANG_ENGLISH} "Installed version: $Installed.$\r$\n$\r$\nThe KVT window will close and the VPN will disconnect for a few seconds: the service restarts with the new version. The kill switch is also off during that time.$\r$\n$\r$\nYour settings and subscriptions will be kept."
LangString KvtWelcome ${LANG_RUSSIAN} "Установленная версия: $Installed.$\r$\n$\r$\nОкно KVT закроется, а VPN отключится на несколько секунд: служба перезапускается вместе с новой версией. Kill switch на это время тоже выключен.$\r$\n$\r$\nНастройки и подписки сохранятся."
LangString KvtRun ${LANG_ENGLISH} "Start KVT"
LangString KvtRun ${LANG_RUSSIAN} "Запустить KVT"
LangString KvtNotInstalled ${LANG_ENGLISH} "KVT isn't installed on this computer — there's nothing to update.$\r$\n$\r$\nOpen the download page? It has the full installer (KVT-${VERSION}-setup.exe)."
LangString KvtNotInstalled ${LANG_RUSSIAN} "KVT на этом компьютере не установлен — обновлять нечего.$\r$\n$\r$\nОткрыть страницу загрузки? Там есть полная установка (KVT-${VERSION}-setup.exe)."
LangString KvtTooOld ${LANG_ENGLISH} "Version $Installed is installed, and this update is for versions ${MIN_VERSION} and later.$\r$\n$\r$\nOpen the download page? Get the full installer KVT-${VERSION}-setup.exe — it updates KVT and keeps your settings."
LangString KvtTooOld ${LANG_RUSSIAN} "Установлена версия $Installed, а это обновление подходит для версий от ${MIN_VERSION}.$\r$\n$\r$\nОткрыть страницу загрузки? Скачайте полную установку KVT-${VERSION}-setup.exe — она обновит KVT с сохранением настроек."
LangString KvtNewer ${LANG_ENGLISH} "A newer version is installed ($Installed). Updating to ${VERSION} isn't needed."
LangString KvtNewer ${LANG_RUSSIAN} "Установлена более новая версия ($Installed). Обновление до ${VERSION} не нужно."
LangString KvtSame ${LANG_ENGLISH} "KVT ${VERSION} is already installed. Reinstall the files?"
LangString KvtSame ${LANG_RUSSIAN} "KVT ${VERSION} уже установлен. Установить файлы заново?"
LangString KvtClosing ${LANG_ENGLISH} "Closing the KVT window…"
LangString KvtClosing ${LANG_RUSSIAN} "Закрытие окна KVT…"
LangString KvtStopping ${LANG_ENGLISH} "Stopping the KVT service…"
LangString KvtStopping ${LANG_RUSSIAN} "Остановка службы KVT…"
LangString KvtFiles ${LANG_ENGLISH} "New files…"
LangString KvtFiles ${LANG_RUSSIAN} "Новые файлы…"
LangString KvtRegistering ${LANG_ENGLISH} "Registering the KVT service…"
LangString KvtRegistering ${LANG_RUSSIAN} "Регистрация службы KVT…"
LangString KvtWriteFiles ${LANG_ENGLISH} "writing files"
LangString KvtWriteFiles ${LANG_RUSSIAN} "запись файлов"
LangString KvtRollingBack ${LANG_ENGLISH} "Update failed ($2) — restoring the previous version…"
LangString KvtRollingBack ${LANG_RUSSIAN} "Обновление не удалось ($2) — возвращаю прежнюю версию…"
LangString KvtFailed ${LANG_ENGLISH} "Couldn't update KVT ($2). The previous version $Installed is restored and working.$\r$\n$\r$\nDownload the full installer KVT-${VERSION}-setup.exe from the download page."
LangString KvtFailed ${LANG_RUSSIAN} "Обновить KVT не удалось ($2). Прежняя версия $Installed возвращена и работает.$\r$\n$\r$\nСкачайте полную установку KVT-${VERSION}-setup.exe со страницы загрузки."
LangString KvtDone ${LANG_ENGLISH} "KVT updated to ${VERSION}."
LangString KvtDone ${LANG_RUSSIAN} "KVT обновлён до ${VERSION}."


Function .onInit
  ; Полный установщик (x64) пишет в 64-битную ветку реестра, а makensis собирает
  ; 32-битную программу — без этого она читала бы WOW6432Node и не нашла KVT.
  ${If} ${RunningX64}
    SetRegView 64
  ${EndIf}
  ReadRegStr $INSTDIR HKLM "${MANUPRODUCTKEY}" ""
  ReadRegStr $Installed HKLM "${UNINSTKEY}" "DisplayVersion"
  ${If} $INSTDIR == ""
  ${OrIfNot} ${FileExists} "$INSTDIR\kvt-service.exe"
    MessageBox MB_ICONINFORMATION|MB_YESNO "$(KvtNotInstalled)" /SD IDNO IDNO +2
      ExecShell "open" "${RELEASES}"
    Quit
  ${EndIf}
  ${VersionCompare} "$Installed" "${MIN_VERSION}" $1
  ${If} $1 = 2
    MessageBox MB_ICONINFORMATION|MB_YESNO "$(KvtTooOld)" /SD IDNO IDNO +2
      ExecShell "open" "${RELEASES}"
    Quit
  ${EndIf}
  ${VersionCompare} "$Installed" "${VERSION}" $1
  ${If} $1 = 1
    MessageBox MB_ICONEXCLAMATION|MB_OK "$(KvtNewer)" /SD IDOK
    Quit
  ${ElseIf} $1 = 0
    MessageBox MB_ICONQUESTION|MB_YESNO "$(KvtSame)" /SD IDYES IDYES +2
    Quit
  ${EndIf}

FunctionEnd

Function RunKvt
  nsis_tauri_utils::RunAsUser "$INSTDIR\kvt.exe" ""
FunctionEnd

; Переносит файл или папку в резервную копию (переименование — без копирования).
!macro Backup NAME
  ${If} ${FileExists} "$INSTDIR\${NAME}"
    Rename "$INSTDIR\${NAME}" "$INSTDIR\${BACKUP}\${NAME}"
  ${EndIf}
!macroend

; Возвращает прежний файл или папку на место, убрав новые.
!macro Restore NAME
  ${If} ${FileExists} "$INSTDIR\${BACKUP}\${NAME}"
    RMDir /r "$INSTDIR\${NAME}"
    Delete "$INSTDIR\${NAME}"
    Rename "$INSTDIR\${BACKUP}\${NAME}" "$INSTDIR\${NAME}"
  ${EndIf}
!macroend

Section "Update"
  SetOutPath "$INSTDIR"

  DetailPrint "$(KvtClosing)"
  nsExec::Exec 'taskkill /F /IM kvt.exe'
  Pop $1

  DetailPrint "$(KvtStopping)"
  nsExec::ExecToLog '"$INSTDIR\kvt-service.exe" stop'
  Pop $1
  ; Процесс службы отпускает файлы чуть позже, чем сообщает об остановке.
  Sleep 1000

  RMDir /r "$INSTDIR\${BACKUP}"
  CreateDirectory "$INSTDIR\${BACKUP}"
  !insertmacro Backup "kvt.exe"
  !insertmacro Backup "kvt-service.exe"
  !insertmacro Backup "licenses"
  !ifdef WITH_CORES
    !insertmacro Backup "cores"
  !endif
  !ifdef WITH_ZAPRET
    !insertmacro Backup "zapret"
  !endif
  !ifdef WITH_TGPROXY
    !insertmacro Backup "tgproxy"
  !endif

  DetailPrint "$(KvtFiles)"
  ClearErrors
  File "${SRC}\kvt.exe"
  File "${SRC}\kvt-service.exe"
  File /r "${SRC}\licenses"
  !ifdef WITH_CORES
    File /r "${SRC}\cores"
  !endif
  !ifdef WITH_ZAPRET
    File /r "${SRC}\zapret"
  !endif
  !ifdef WITH_TGPROXY
    File /r "${SRC}\tgproxy"
  !endif
  StrCpy $2 0
  ${IfNot} ${Errors}
    DetailPrint "$(KvtRegistering)"
    nsExec::ExecToLog '"$INSTDIR\kvt-service.exe" install'
    Pop $2
  ${Else}
    StrCpy $2 "$(KvtWriteFiles)"
  ${EndIf}

  ${If} $2 != 0
    DetailPrint "$(KvtRollingBack)"
    nsExec::ExecToLog '"$INSTDIR\kvt-service.exe" stop'
    Pop $1
    Sleep 1000
    !insertmacro Restore "kvt.exe"
    !insertmacro Restore "kvt-service.exe"
    !insertmacro Restore "licenses"
    !ifdef WITH_CORES
      !insertmacro Restore "cores"
    !endif
    !ifdef WITH_ZAPRET
      !insertmacro Restore "zapret"
    !endif
    !ifdef WITH_TGPROXY
      !insertmacro Restore "tgproxy"
    !endif
    nsExec::ExecToLog '"$INSTDIR\kvt-service.exe" install'
    Pop $1
    RMDir /r "$INSTDIR\${BACKUP}"
    MessageBox MB_ICONEXCLAMATION|MB_OK "$(KvtFailed)" /SD IDOK
    Abort
  ${EndIf}

  RMDir /r "$INSTDIR\${BACKUP}"
  WriteRegStr HKLM "${UNINSTKEY}" "DisplayVersion" "${VERSION}"
  DetailPrint "$(KvtDone)"
SectionEnd
