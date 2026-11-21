// Как выглядит подключение: цвет точки, заголовок и вид круглой кнопки. Одна чистая
// функция на карточку статуса главного окна и мини-панель из трея: два окна не должны
// расходиться в том, что написано про одно и то же состояние.

import { t } from "./i18n";
import type { Mode, ServiceStatus } from "./api";

/** Цвет точки у заголовка. */
export type Tone = "pending" | "warn" | "on" | "error" | "off";

export interface StatusInput {
  /** `null` — служба не отвечает. */
  status: ServiceStatus | null;
  /** Идут ли данные через туннель (`null` — ещё не проверяли). */
  tunnelOk: boolean | null;
  /** Окно само подключает или отключает. */
  busy: boolean;
  /** Службы KVT нет. */
  serviceDown?: boolean;
  /** Службу уже запускают: не пугаем красным «не запущена». */
  starting?: boolean;
  /** Служба другой версии (прерванное обновление). */
  mismatch?: boolean;
}

export interface StatusView {
  /** Работает VPN или только zapret. */
  connected: boolean;
  /** Ядро остановилось, а kill switch держит интернет закрытым. */
  blocked: boolean;
  /** Сервер принял подключение, но данные через туннель не идут. */
  noData: boolean;
  serviceStarting: boolean;
  tone: Tone;
  title: string;
  /** Вид круглой кнопки: выключено, идёт подключение, подключено (или без данных). */
  power: "pending" | "on warn" | "on" | "off";
}

export function statusView(input: StatusInput): StatusView {
  const { status, tunnelOk, busy, serviceDown = false, starting = false, mismatch = false } = input;
  const zapretOnly = status?.state === "zapret";
  const connected = status?.state === "connected" || zapretOnly;
  const blocked = status?.state === "failed" && status.blocked === true;
  const noData = status?.state === "connected" && tunnelOk === false;
  const serviceStarting = serviceDown && starting && !mismatch;
  const tone: Tone =
    busy || status?.state === "connecting" || serviceStarting
      ? "pending"
      : noData
        ? "warn"
        : connected
          ? "on"
          : status?.state === "failed" || serviceDown
            ? "error"
            : "off";
  const title = serviceStarting
    ? t("Запускаем службу KVT…", "Starting the KVT service…")
    : tone === "pending"
      ? t("Подключение…", "Connecting…")
      : zapretOnly
        ? t("Zapret работает", "Zapret is on")
        : noData
          ? t("Сайты не открываются", "Sites don't open")
          : connected
            ? t("Подключено", "Connected")
            : blocked
              ? t("Интернет закрыт", "Internet blocked")
              : serviceDown && mismatch
                ? t("Окно и служба KVT разных версий", "KVT window and service versions differ")
                : serviceDown
                  ? t("Служба KVT не запущена", "The KVT service isn't running")
                  : tone === "error"
                    ? t("Ошибка", "Error")
                    : t("Отключено", "Disconnected");
  const power = busy ? "pending" : noData || blocked ? "on warn" : connected ? "on" : "off";
  return { connected, blocked, noData, serviceStarting, tone, title, power };
}

/** Подсказка к режиму: что он даёт. `telegram` — прокси Telegram включён, и Telegram Desktop
 *  идёт через него в любом режиме. */
export function modeHint(mode: Mode, telegram: boolean): string {
  switch (mode) {
    case "vpn":
      return telegram
        ? t("Весь заблокированный трафик через VPN; Telegram — через прокси", "All blocked traffic via VPN; Telegram via the proxy")
        : t("Весь заблокированный трафик через VPN", "All blocked traffic via VPN");
    case "hybrid":
      return telegram
        ? t("YouTube и Discord через zapret, остальное через VPN; Telegram — через прокси", "YouTube and Discord via zapret, the rest via VPN; Telegram via the proxy")
        : t("YouTube и Discord через zapret, остальное через VPN", "YouTube and Discord via zapret, the rest via VPN");
    case "zapret":
      return telegram
        ? t("Без VPN: YouTube и Discord через zapret, Telegram Desktop через прокси", "No VPN: YouTube and Discord via zapret, Telegram Desktop via the proxy")
        : t("Без VPN: только обход DPI для YouTube и Discord", "No VPN: only the DPI bypass for YouTube and Discord");
  }
}
