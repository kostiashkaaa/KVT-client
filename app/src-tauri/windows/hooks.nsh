; Хуки установщика KVT (шаблон NSIS Tauri вставляет их в свои секции).
;
; Служба держит свои файлы и ядра, поэтому перед заменой файлов она останавливается,
; а после — регистрируется заново (`kvt-service install` обновляет регистрацию,
; если служба уже есть, и пишет манифест с хэшем нового kvt.exe).
;
; При обновлении (5.7) шаблон запускает прежний деинсталлятор с /UPDATE
; ($UpdateMode = 1): тогда служба только останавливается, а настройки,
; ProgramData и автозапуск остаются.

!define KVT_LANG_RU 1049

; Строка на языке установщика.
!macro KvtDetail RU EN
  ${If} $LANGUAGE == ${KVT_LANG_RU}
    DetailPrint "${RU}"
  ${Else}
    DetailPrint "${EN}"
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREINSTALL
  ${If} ${FileExists} "$INSTDIR\kvt-service.exe"
    !insertmacro KvtDetail "Остановка службы KVT…" "Stopping the KVT service…"
    nsExec::ExecToLog '"$INSTDIR\kvt-service.exe" stop'
    Pop $0
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTINSTALL
  !insertmacro KvtDetail "Регистрация службы KVT…" "Registering the KVT service…"
  nsExec::ExecToLog '"$INSTDIR\kvt-service.exe" install'
  Pop $0
  ${If} $0 != 0
    ${If} $LANGUAGE == ${KVT_LANG_RU}
      MessageBox MB_ICONEXCLAMATION|MB_OK "Служба KVT не зарегистрировалась (код $0). Без неё подключение не заработает. Запустите установку ещё раз; если не поможет — напишите в GitHub Issues проекта." /SD IDOK
    ${Else}
      MessageBox MB_ICONEXCLAMATION|MB_OK "The KVT service wasn't registered (code $0). Connecting won't work without it. Run the installer again; if that doesn't help, report it in the project's GitHub Issues." /SD IDOK
    ${EndIf}
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ${If} $UpdateMode = 1
    !insertmacro KvtDetail "Остановка службы KVT…" "Stopping the KVT service…"
    nsExec::ExecToLog '"$INSTDIR\kvt-service.exe" stop'
    Pop $0
  ${Else}
    ; Служба удаляется; фильтры WFP (kill switch) снимаются вместе с ней,
    ; драйвер WinDivert — если им не пользуется чужой zapret.
    !insertmacro KvtDetail "Удаление службы KVT…" "Removing the KVT service…"
    nsExec::ExecToLog '"$INSTDIR\kvt-service.exe" uninstall'
    Pop $0
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ${If} $UpdateMode <> 1
    ; Списки маршрутизации, обновления zapret, журналы и манифест службы.
    ReadEnvStr $0 PROGRAMDATA
    ${If} $0 != ""
      RMDir /r "$0\KVT"
    ${EndIf}
    ; Имя отправителя уведомлений (KVT регистрирует его при запуске).
    DeleteRegKey HKCU "Software\Classes\AppUserModelId\dev.kvt.client"
    ; Остатки каталогов ядер, zapret и прокси Telegram, если в них что-то появилось после установки.
    RMDir /r "$INSTDIR\cores"
    RMDir /r "$INSTDIR\zapret"
    RMDir /r "$INSTDIR\tgproxy"
    RMDir /r "$INSTDIR\licenses"
    RMDir "$INSTDIR"
  ${EndIf}
!macroend
