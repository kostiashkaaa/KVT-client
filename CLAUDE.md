# KVT

VPN-клиент для Windows 10/11: подписки (Xray, sing-box), маршрутизация по спискам, zapret,
kill switch. Rust (Tauri 2) + Svelte 5. Сборка, запуск службы, релиз — в
[CONTRIBUTING.md](CONTRIBUTING.md); здесь только то, что легко упустить.

## Части

- `crates/kvt-core` — общая логика без прав: модель, парсеры ссылок (`parser/`), конфиги
  ядер (`compile/`), маршрутизация, IPC (`ipc.rs`), `governor.rs`, `netlog.rs`.
- `crates/kvt-service` — служба Windows с правами администратора: ядра, TUN, kill switch
  (WFP), zapret. Принимает команды по named pipe (`pipe.rs` → `handler.rs`).
- `app/src-tauri` — крейт `kvt-app`, бинарник `kvt.exe`: подписки, трей, watchdog, связь
  со службой (`service_client.rs`). Команды для окна — `generate_handler!` в `main.rs`.
- `app/src` — интерфейс; весь вызов Rust идёт через `app/src/lib/api.ts`.
- `presets/` — данные (сетевая политика, правила ошибок ядер), не код.
- `docs/` — локальный план (`ARCHITECTURE.md` с этапами, чек-лист релиза), в git не идёт.

## Команды

- Тесты: `cargo test --workspace`
- Линт: `cargo clippy --workspace --all-targets -- -D warnings` и `cd app && npm run check`
- Формат: `cargo fmt --all`
- Интерфейс в браузере с тестовыми данными: превью `kvt-ui` из `.claude/launch.json`
  (порт 5173; `?servers=10000` — длинный список).
- Перед `cargo build/clippy/test` для `kvt-app` нужен собранный фронтенд
  (`cd app && npm run build`): `tauri::generate_context!` читает `app/dist`.

## Правила кода

- `unsafe_code = "deny"`, clippy `unwrap_used` + `-D warnings` — в рабочем коде без
  `unwrap()`; в тестах можно.
- Изменил `Request`/`Response` в `kvt_core::ipc` — подними `PROTOCOL_VERSION`: служба
  отвергает `Hello` с другой версией, окно и служба обновляются вместе.
- Новая команда в `api.ts` — с веткой `if (!inTauri)` для браузерного превью
  (заглушка или понятная ошибка «работает в приложении»).
- Секреты (ключи, ссылки подписок, UUID, адреса серверов) не уходят в WebView, журналы,
  тексты ошибок и диагностику. В `api.ts` — только данные для показа.
- Любой сетевой запрос — через `NetGovernor` (лимиты на SNI против блокировок ТСПУ) и с
  записью в `netlog`. Локальных прокси-портов и телеметрии нет.
- Разбор недоверенного ввода (подписки, ответы серверов) — с тестами на плохие данные.
- Тексты интерфейса, комментарии, сообщения коммитов — по-русски. Тексты UI: коротко,
  что случилось и что сделать.
- Отложенная работа помечается `TODO(этап N)` по плану из `docs/ARCHITECTURE.md`.
- Отступы: 4 пробела в Rust, 2 — в ts/svelte/json/css; LF (`.editorconfig`).

## Подводные камни

- Служба доверяет только `kvt.exe` из своего каталога: для разработки окно и служба
  должны лежать в одном `target\debug`. У установленной службы ещё сверяется SHA-256
  клиента с манифестом установки.
- Тесты с `--ignored` (kill switch, toast) и `cargo run -p kvt-service -- --console`
  требуют прав администратора — их запускает пользователь сам; дай ему команды.
- `crates/kvt-core/tests/real_cores.rs` и `real_zapret.rs` нужны скачанные ядра/zapret
  (`scripts/fetch-*.ps1`) и списки (`update-rules`, см. CONTRIBUTING), иначе молча
  пропускаются — зелёный прогон не значит, что они проверили что-то.
- `kvt-service --console` и установленная служба делят один pipe и `service.log`: пока
  работает консольная, установленная не стартует, а `kvt.exe` из Program Files
  отклоняется («отклонён чужой клиент», в окне — «early eof»).
- Журналы: окно — `%LOCALAPPDATA%\dev.kvt.client\logs\kvt.log`, служба —
  `C:\ProgramData\KVT\logs\service.log`.
- Версия живёт в трёх местах: `Cargo.toml` (workspace), `app/package.json`,
  `app/src-tauri/tauri.conf.json`; `release.yml` сверяет тег с `tauri.conf.json`. Плюс
  раздел в `CHANGELOG.md`.

## Порядок работы

- Идти по этапам плана из `docs/ARCHITECTURE.md`, к следующему — только по слову
  пользователя. Решённое «не делаем» — там же, в разделе «Чего не делаем».
- Коммитить только по явной просьбе. Без строки `Co-Authored-By: Claude`.

## Поддержка этого файла

Если команда, путь или правило выше перестали быть правдой (переименование, новые шаги
сборки, новый крейт) — поправь строку в этой же задаче и скажи об этом одной фразой.
Новый подводный камень, на который ушло больше одной попытки, — добавь одной строкой.
Файл держать в пределах ~120 строк.
