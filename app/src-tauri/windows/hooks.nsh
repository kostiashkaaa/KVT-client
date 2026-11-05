; Хуки установщика KVT (шаблон NSIS Tauri вставляет их в свои секции).
;
; Служба держит свои файлы и ядра, поэтому перед заменой файлов она останавливается,
; а после — регистрируется заново (`kvt-service install` обновляет регистрацию,
; если служба уже есть, и пишет манифест с хэшем нового kvt.exe).
;
; При обновлении (5.7) шаблон запускает прежний деинсталлятор с /UPDATE
; ($UpdateMode = 1): тогда служба только останавливается, а настройки,
; ProgramData и автозапуск остаются.

!macro NSIS_HOOK_PREINSTALL
  ${If} ${FileExists} "$INSTDIR\kvt-service.exe"
    DetailPrint "Остановка службы KVT…"
    nsExec::ExecToLog '"$INSTDIR\kvt-service.exe" stop'
    Pop $0
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTINSTALL
  DetailPrint "Регистрация службы KVT…"
  nsExec::ExecToLog '"$INSTDIR\kvt-service.exe" install'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONEXCLAMATION|MB_OK "Служба KVT не зарегистрировалась (код $0). Без неё подключение не заработает. Запустите установку ещё раз; если не поможет — напишите в GitHub Issues проекта." /SD IDOK
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ${If} $UpdateMode = 1
    DetailPrint "Остановка службы KVT…"
    nsExec::ExecToLog '"$INSTDIR\kvt-service.exe" stop'
    Pop $0
  ${Else}
    ; Служба удаляется; фильтры WFP (kill switch) снимаются вместе с ней,
    ; драйвер WinDivert — если им не пользуется чужой zapret.
    DetailPrint "Удаление службы KVT…"
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
    ; Остатки каталогов ядер и zapret, если в них что-то появилось после установки.
    RMDir /r "$INSTDIR\cores"
    RMDir /r "$INSTDIR\zapret"
    RMDir /r "$INSTDIR\licenses"
    RMDir "$INSTDIR"
  ${EndIf}
!macroend
