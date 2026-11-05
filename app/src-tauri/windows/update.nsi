; Обновление уже установленного KVT (KVT-x.y.z-update.exe, шаг 5.7).
;
; Собирает scripts\build-release.ps1 тем же makensis, что и полный установщик:
;   /DVERSION=0.2.0 /DMIN_VERSION=0.1.0 /DSRC=<target\release> /DOUTFILE=<путь>
;   /DPLUGINS=<каталог nsis_tauri_utils.dll> /DICON=<icon.ico>
;   /DWITH_CORES и /DWITH_ZAPRET — если ядра или комплект zapret изменились с MIN_VERSION.
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

Name "Обновление KVT ${VERSION}"
Caption "Обновление KVT до ${VERSION}"
OutFile "${OUTFILE}"
BrandingText "KVT ${VERSION}"
VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "KVT"
VIAddVersionKey "FileDescription" "Обновление KVT"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "KVT — GPL-3.0-or-later"
ShowInstDetails show

; Установленная версия (для страницы приветствия и сообщений).
Var Installed

!define MUI_ICON "${ICON}"
!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE "Обновление KVT до ${VERSION}"
!define MUI_WELCOMEPAGE_TEXT "Установленная версия: $Installed.$\r$\n$\r$\nОкно KVT закроется, а VPN отключится на несколько секунд: служба перезапускается вместе с новой версией. Kill switch на это время тоже выключен.$\r$\n$\r$\nНастройки и подписки сохранятся."
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "Запустить KVT"
!define MUI_FINISHPAGE_RUN_FUNCTION RunKvt
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_LANGUAGE "Russian"


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
    MessageBox MB_ICONINFORMATION|MB_YESNO "KVT на этом компьютере не установлен — обновлять нечего.$\r$\n$\r$\nОткрыть страницу загрузки? Там есть полная установка (KVT-${VERSION}-setup.exe)." /SD IDNO IDNO +2
      ExecShell "open" "${RELEASES}"
    Quit
  ${EndIf}
  ${VersionCompare} "$Installed" "${MIN_VERSION}" $1
  ${If} $1 = 2
    MessageBox MB_ICONINFORMATION|MB_YESNO "Установлена версия $Installed, а это обновление подходит для версий от ${MIN_VERSION}.$\r$\n$\r$\nОткрыть страницу загрузки? Скачайте полную установку KVT-${VERSION}-setup.exe — она обновит KVT с сохранением настроек." /SD IDNO IDNO +2
      ExecShell "open" "${RELEASES}"
    Quit
  ${EndIf}
  ${VersionCompare} "$Installed" "${VERSION}" $1
  ${If} $1 = 1
    MessageBox MB_ICONEXCLAMATION|MB_OK "Установлена более новая версия ($Installed). Обновление до ${VERSION} не нужно." /SD IDOK
    Quit
  ${ElseIf} $1 = 0
    MessageBox MB_ICONQUESTION|MB_YESNO "KVT ${VERSION} уже установлен. Установить файлы заново?" /SD IDYES IDYES +2
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

Section "Обновление"
  SetOutPath "$INSTDIR"

  DetailPrint "Закрытие окна KVT…"
  nsExec::Exec 'taskkill /F /IM kvt.exe'
  Pop $1

  DetailPrint "Остановка службы KVT…"
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

  DetailPrint "Новые файлы…"
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
  StrCpy $2 0
  ${IfNot} ${Errors}
    DetailPrint "Регистрация службы KVT…"
    nsExec::ExecToLog '"$INSTDIR\kvt-service.exe" install'
    Pop $2
  ${Else}
    StrCpy $2 "запись файлов"
  ${EndIf}

  ${If} $2 != 0
    DetailPrint "Обновление не удалось ($2) — возвращаю прежнюю версию…"
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
    nsExec::ExecToLog '"$INSTDIR\kvt-service.exe" install'
    Pop $1
    RMDir /r "$INSTDIR\${BACKUP}"
    MessageBox MB_ICONEXCLAMATION|MB_OK "Обновить KVT не удалось ($2). Прежняя версия $Installed возвращена и работает.$\r$\n$\r$\nСкачайте полную установку KVT-${VERSION}-setup.exe со страницы загрузки." /SD IDOK
    Abort
  ${EndIf}

  RMDir /r "$INSTDIR\${BACKUP}"
  WriteRegStr HKLM "${UNINSTKEY}" "DisplayVersion" "${VERSION}"
  DetailPrint "KVT обновлён до ${VERSION}."
SectionEnd
