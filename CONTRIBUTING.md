# Разработка KVT

Спасибо, что хотите помочь. Здесь — как собрать KVT из исходников, запустить и
проверить изменения. Ошибки и предложения — в
[Issues](https://github.com/kostiashkaaa/KVT-client/issues).

## Устройство

```
app/                 окно: Tauri 2 + Svelte 5
app/src-tauri        Rust-часть приложения: подписки, трей, уведомления, связь со службой
crates/kvt-core      общая логика: модель, парсеры ссылок, маршрутизация, конфиги ядер, IPC
crates/kvt-service   служба Windows с правами администратора: ядра, TUN, kill switch (WFP), zapret
presets/             данные: сетевая политика, правила ошибок ядер
scripts/             загрузка ядер и zapret, сборка установщика
```

Окно и разбор подписок работают с правами пользователя. Всё, что требует прав
администратора, делает служба: она принимает от окна только типизированные команды
(`kvt_core::ipc`), сама строит конфиг ядра и доверяет только `kvt.exe` из своей папки.
Секреты (ключи, ссылки подписок) не попадают в WebView, журналы и диагностику.

## Что нужно

Windows 10 или 11, Rust (stable, MSVC), Node.js 20+, Visual Studio Build Tools с C++.

## Запуск из исходников

| Что | Команда |
|---|---|
| Окно KVT целиком | `cd app && npm install && npm run tauri dev` |
| Окно у правого края экрана с горячей перезагрузкой | `scripts\dev.ps1`; служба: `scripts\dev.ps1 -Service` (спросит UAC) |
| Только интерфейс в браузере, с тестовыми данными | `cd app && npm run dev` → http://localhost:5173 |
| Длинный список в превью | http://localhost:5173/?servers=10000 |
| Скриншоты для README (вид `?demo`: VPN подключён, аккуратные серверы) | при запущенном `npm run dev`: `cd app && npm run screenshots` → `assets/screenshots/`, нужен Microsoft Edge |
| Тесты Rust | `cargo test --workspace` |
| Линтеры | `cargo clippy --workspace --all-targets -- -D warnings`, `cd app && npm run check` |
| Убрать устаревшие сборки из `target` (`dev.ps1` делает это сам) | `scripts\clean-target.ps1` |
| Форматирование | `cargo fmt --all` |

### Служба и подключение

Ядрам нужен TUN, поэтому служба работает с правами администратора.

1. Один раз скачать ядра и Wintun (версии и SHA-256 зафиксированы в скрипте):
   `powershell -ExecutionPolicy Bypass -File scripts\fetch-cores.ps1`
2. Для zapret — комплект Flowseal:
   `powershell -ExecutionPolicy Bypass -File scripts\fetch-zapret.ps1`
3. В **терминале администратора**: `cargo run -p kvt-service -- --console`
   (или `target\debug\kvt-service.exe install` — зарегистрировать как службу Windows).
4. В обычном терминале: `cd app && npm run tauri dev` → добавить подписку → «Подключить».

Служба принимает команды только от `kvt.exe` из своего каталога, поэтому окно и
служба для разработки должны лежать в одном `target\debug`.

### Проверки, которым нужны права или сеть

- Kill switch (на несколько секунд закроет интернет этому тесту), из терминала
  администратора: `cargo test -p kvt-service kill_switch -- --ignored`.
- Конфиги настоящими ядрами:
  `cargo run -p kvt-service -- update-rules --dir target\debug\cores\rules`, затем
  `cargo test -p kvt-core --test real_cores`.
- Уведомление Windows: `cargo test -p kvt-app real_toast -- --ignored`.

### Журналы

- Окно: `%LOCALAPPDATA%\dev.kvt.client\logs\kvt.log`.
- Служба: `C:\ProgramData\KVT\logs\service.log`.

Ключи, ссылки подписок, UUID и адреса серверов в журнал не попадают. Правила, по которым
ошибки ядер превращаются в понятные сообщения, — `presets/core-errors.json`.

## Установщик и релиз

`powershell -ExecutionPolicy Bypass -File scripts\build-release.ps1` собирает службу,
скачивает ядра, Wintun и zapret по зафиксированным SHA-256, кладёт тексты лицензий и
собирает в `target\release\dist`:

- `KVT-x.y.z-setup.exe` — установка в `C:\Program Files\KVT` (NSIS);
- `KVT-x.y.z-update.exe` — обновление установленного KVT с откатом при сбое;
- `SHA256SUMS.txt`.

Ключи: `-Offline` — ещё установщик со встроенным WebView2, `-SkipFetch` — без повторной
загрузки ядер. Ресурсы установщика подключает `app/src-tauri/tauri.release.conf.json`,
хуки и шаблон NSIS лежат в `app/src-tauri/windows/`. От какой версии ставится
обновление и какие ядра были в ней — `scripts/update-baseline.json`.

Релиз выпускается тегом: поднять версию в `Cargo.toml`, `app/package.json` и
`app/src-tauri/tauri.conf.json`, дописать раздел в `CHANGELOG.md`, затем
`git tag vX.Y.Z && git push origin vX.Y.Z`. GitHub Actions (`release.yml`) прогонит
тесты, соберёт установщики, сделает аттестацию происхождения и опубликует релиз на
странице Releases с описанием из `CHANGELOG.md`.

## Правила для изменений

- `cargo fmt`, `cargo clippy -D warnings` и `npm run check` — без замечаний; CI проверяет
  то же самое.
- Новая логика — с тестами; разбор недоверенных данных (подписки, ответы серверов) — с
  тестами на плохой ввод.
- Тексты интерфейса — на двух языках парой на месте (`t("…", "…")`, `tr`/`trf!`), коротко
  и с действием: что случилось и что сделать. Журналы — по-русски.
- Никаких локальных прокси-портов, телеметрии и запросов в сеть без записи в журнал
  запросов.
