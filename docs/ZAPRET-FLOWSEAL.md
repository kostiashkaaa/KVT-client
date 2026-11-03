# Этап 4: встраивание zapret (Flowseal)

Источник: [Flowseal/zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube).
Заметки собраны 30.10.2026 по релизу **1.10.4** (20.10.2026). Перед реализацией перепроверить.

## Лицензии

- Репозиторий — MIT (`LICENSE.txt`, копирайт bol-van и Flowseal). Уведомления сохранить.
- `winws.exe` (bol-van/zapret) — MIT.
- WinDivert — LGPLv3 или GPLv2 на выбор; для GPL-3.0 проекта берём LGPLv3.
- `cygwin1.dll` — лицензию проверить до первого релиза.

## Что берём из релиза

Архив `zapret-discord-youtube-<версия>.zip` с зафиксированной SHA-256
(для 1.10.4: `291af673bd0238506f9548e0e94ca0abf244000f4c9a06960544fb01c5f97b34`).
Скачивается при сборке установщика, не в рантайме.

- `bin/`: `winws.exe`, `WinDivert.dll`, `WinDivert64.sys`, `cygwin1.dll`, фейки `*.bin`.
- `lists/`: `list-general.txt`, `list-google.txt`, `list-exclude.txt`, `ipset-all.txt`, `ipset-exclude.txt`.
- Стратегии: `general.bat` и 20 вариантов (`ALT`…`ALT13`, `EXP`, `FAKE TLS AUTO*`, `SIMPLE FAKE*`).
- `utils/targets.txt` — цели для проверки стратегий.

## Как встраиваем

`service.bat` и `test zapret.ps1` **не вызываем**: они интерактивные и имеют побочные
эффекты:

- включают TCP timestamps через `netsh` при каждом запуске;
- убивают все `winws.exe`;
- удаляют службы `WinDivert` и `GoodbyeDPI`.

Вместо этого:

1. **Стратегии — данные.** Парсер `.bat` извлекает аргументы после `winws.exe`
   (строки склеиваются по `^`, профили разделены `--new`) и превращает их в
   структуру. `%BIN%` и `%LISTS%` подставляет служба: только свои каталоги в
   `Program Files`/`ProgramData`. `%GameFilterTCP%`/`%GameFilterUDP%` — из настроек
   (выключено = `12`).
2. **Whitelist флагов.** Служба отвергает неизвестные флаги и пути вне своих каталогов
   (`--debug=@файл` и подобные), потому что winws работает от SYSTEM.
3. **Единый RoutingPlan.** Домены слоя Zapret дописываются в hostlist.
   **IP VPN-серверов** — в `--ipset-exclude` каждого профиля. Так winws не трогает
   рукопожатие VPN.
4. **Автоподбор стратегии.** Свой тестер вместо `test zapret.ps1`:
   - перебор стратегий на целях из `targets.txt`;
   - HTTP/1.1, TLS 1.2 и TLS 1.3, как у Flowseal;
   - плюс проверка заморозки после 16–20 КБ (`measure_download`);
   - выбор по числу успешных проверок, затем по задержке;
   - результат запоминается для сети;
   - запросы идут через NetGovernor.
5. **Конфликты.** Если найдены служба `zapret` (установленная через `service.bat`),
   `GoodbyeDPI`, `discordfix_zapret`, `winws1`/`winws2` или чужой запущенный `winws.exe`:
   - пользователь видит предупреждение и кнопку «Остановить»;
   - без согласия ничего не удаляем.
6. **Обновления.** Версию сверяем с `.service/version.txt` в репозитории Flowseal.
   Новый релиз приходит с обновлением KVT (хэш зафиксирован), а не скачивается «вживую».

## Известные конфликты

- Касперский детектирует WinDivert как `Not-a-virus:RiskTool.Multi.WinDivert` —
  нужна подсказка про исключение.
- Античиты реагируют на WinDivert.
- Мешают AdGuard, Killer, Intel Connectivity Network Service, Check Point, SmartByte.
- Пути с кириллицей или пробелами ломают `.bat`. У нас пути задаёт служба, но проверить.
