// Подписи плиток сервисов. Чистые функции: тексты считаются при вызове (язык ставится
// до монтирования окна), без обращения к Rust.

import { t } from "../i18n";
import type { ServiceVia, ServicesSnapshot, TileState } from "../api";

/** Коротко, как на плитке: «VPN», «zapret», «напрямую». */
export function viaLabel(via: ServiceVia): string {
  switch (via) {
    case "vpn":
      return "VPN";
    case "zapret":
      return "zapret";
    case "proxy":
      return t("прокси", "proxy");
    case "blocked":
      return t("закрыт", "blocked");
    case "direct":
      return t("напрямую", "direct");
  }
}

/** Подсказка к плитке: что и как идёт. */
export function viaHint(name: string, via: ServiceVia): string {
  switch (via) {
    case "vpn":
      return t(`${name} идёт через VPN`, `${name} goes through the VPN`);
    case "zapret":
      return t(`${name} идёт через zapret: обход блокировки без VPN`, `${name} goes through zapret: a block bypass without the VPN`);
    case "proxy":
      return t(
        `${name} в Telegram Desktop идёт через прокси KVT; проверяется адрес, куда прокси подключается`,
        `${name} in Telegram Desktop goes through KVT's proxy; the check covers the address the proxy connects to`,
      );
    case "blocked":
      return t(`${name} закрыт правилами маршрутизации`, `${name} is blocked by the routing rules`);
    case "direct":
      return t(`${name} идёт напрямую, мимо VPN и zapret`, `${name} goes directly, past the VPN and zapret`);
  }
}

/** Словом, не только цветом точки. */
export function stateText(state: TileState): string {
  switch (state) {
    case "works":
      return t("открывается", "opens");
    case "slow":
      return t("медленно", "slow");
    case "down":
      return t("не открывается", "doesn't open");
    case "waiting":
      return t("ждём", "waiting");
    case "unknown":
      return t("не проверено", "not checked");
  }
}

/** «только что», «3 мин назад», «2 ч назад»; `at` — секунды Unix. */
export function ago(at: number, nowMs: number = Date.now()): string {
  const minutes = Math.max(0, Math.floor((nowMs / 1000 - at) / 60));
  if (minutes < 1) return t("только что", "just now");
  if (minutes < 60) return t(`${minutes} мин назад`, `${minutes} min ago`);
  const hours = Math.floor(minutes / 60);
  return t(`${hours} ч назад`, `${hours} h ago`);
}

/** Строка под заголовком: что уже известно и что делать дальше. */
export function caption(snap: ServicesSnapshot, nowMs: number = Date.now()): string {
  if (snap.checking) return t("Проверяю…", "Checking…");
  if (snap.at === null) {
    return snap.running === "off"
      ? t("Подключитесь — здесь появится, что открывается", "Connect — and you'll see what opens here")
      : t("Ещё не проверяли", "Not checked yet");
  }
  const when = t(`Проверено ${ago(snap.at, nowMs)}`, `Checked ${ago(snap.at, nowMs)}`);
  return snap.running === "off" ? `${when} · ${t("без VPN", "without VPN")}` : when;
}
