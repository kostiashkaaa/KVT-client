# Сторонние компоненты KVT

KVT распространяется по лицензии GNU GPL версии 3 (файл `LICENSE`). Вместе с ним
поставляются программы и данные других авторов — каждая под своей лицензией. Их тексты
лежат в папке `licenses` рядом с `kvt.exe`; исходники — по ссылкам ниже.

| Компонент | Что делает в KVT | Лицензия | Исходники |
|---|---|---|---|
| Xray-core | VPN-ядро (VLESS, Reality, XHTTP и др.) | MPL-2.0 | https://github.com/XTLS/Xray-core |
| sing-box | VPN-ядро (Hysteria2, TUIC и др.) | GPL-3.0-or-later | https://github.com/SagerNet/sing-box |
| Wintun | Драйвер виртуального адаптера (TUN) | Prebuilt Binaries License (WireGuard LLC) — только готовые подписанные файлы, без изменений | https://www.wintun.net |
| zapret (winws) | Обход DPI | MIT | https://github.com/bol-van/zapret |
| zapret-discord-youtube (Flowseal) | Стратегии и списки для winws | MIT | https://github.com/Flowseal/zapret-discord-youtube |
| WinDivert | Драйвер перехвата пакетов для winws | LGPL-3.0 (или GPL-2.0) | https://github.com/basil00/WinDivert |
| Cygwin (cygwin1.dll) | Библиотека, нужная winws | LGPL-3.0 | https://cygwin.com |
| tg-ws-proxy-rs (valnesfjord) | Прокси для Telegram Desktop в режимах «Zapret» и «Гибрид»; порт программы tg-ws-proxy (Flowseal, MIT) | MIT | https://github.com/valnesfjord/tg-ws-proxy-rs |
| flag-icons | Флаги стран в списке серверов | MIT | https://github.com/lipis/flag-icons |
| Tauri | Окно приложения и трей | MIT / Apache-2.0 | https://github.com/tauri-apps/tauri |
| Svelte | Интерфейс | MIT | https://github.com/sveltejs/svelte |
| Списки itdoginfo (podkop) | Маршрутизация: что открывать через VPN | по условиям репозитория | https://github.com/itdoginfo/allow-domains |
| Списки runetfreedom | Маршрутизация: полный реестр блокировок | по условиям репозитория | https://github.com/runetfreedom/russia-v2ray-rules-dat |

Ядра, Wintun, zapret и прокси для Telegram KVT берёт из официальных релизов по
зафиксированным SHA-256 (`scripts/fetch-cores.ps1`, `scripts/fetch-zapret.ps1`,
`scripts/fetch-tgproxy.ps1`) и не изменяет. Списки
маршрутизации служба загружает сама и в установщик они не входят.

Библиотеки Rust и JavaScript, из которых собраны `kvt.exe` и `kvt-service.exe`, —
под MIT, Apache-2.0, BSD, ISC, Zlib, Unicode-3.0 и MPL-2.0; полный список с версиями —
в `Cargo.lock` и `app/package-lock.json` исходников.
