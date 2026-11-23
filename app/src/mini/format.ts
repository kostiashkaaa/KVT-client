// Подписи мини-панели. Чистые функции: тексты считаются при вызове (язык ставится до
// монтирования окна), без обращения к Rust.

import { count, locale, t } from "../lib/i18n";
import { protocolTitle } from "../lib/subscriptions/format";
import type { PanelServer, PanelSubscription } from "../lib/api";

/** «VLESS · REALITY», «VLESS · XHTTP»: протокол и то, чем он защищён или как идёт. */
export function protoLabel(s: Pick<PanelServer, "protocol" | "transport" | "security">): string {
  const tail =
    s.security === "reality"
      ? "REALITY"
      : s.transport !== "tcp" && s.transport !== "udp"
        ? s.transport.toUpperCase()
        : s.security === "tls"
          ? "TLS"
          : "";
  const head = protocolTitle(s.protocol);
  return tail ? `${head} · ${tail}` : head;
}

/** Справа от сервера: задержка, «не работает» или пусто, пока не проверяли. */
export function pingText(s: Pick<PanelServer, "pingMs" | "health">): string {
  if (s.health === "down") return t("не работает", "not working");
  if (s.pingMs === null) return "";
  return `${s.pingMs} ${t("мс", "ms")}`;
}

const GB = 2 ** 30;
const gb = (bytes: number) =>
  (bytes / GB).toLocaleString(locale(), { maximumFractionDigits: bytes < 10 * GB ? 1 : 0 });

/** Остаток трафика: подпись под сервером и доля израсходованного для полосы. */
export interface Usage {
  label: string;
  /** 0–100; `null` — сколько израсходовано, не известно (полосы нет). */
  percent: number | null;
}

export function usageOf(sub: PanelSubscription | null): Usage | null {
  if (!sub || sub.totalBytes === null || sub.totalBytes <= 0) return null;
  const unit = t("ГБ", "GB");
  if (sub.usedBytes === null) return { label: `${sub.title} · ${gb(sub.totalBytes)} ${unit}`, percent: null };
  const percent = Math.min(100, Math.max(0, (sub.usedBytes / sub.totalBytes) * 100));
  return {
    label: `${sub.title} · ${gb(sub.usedBytes)} ${t("из", "of")} ${gb(sub.totalBytes)} ${unit}`,
    percent,
  };
}

/** Одно напоминание под заголовком. */
export type Notice =
  | { kind: "update"; version: string }
  | { kind: "expiring"; title: string; days: number; expired: boolean };

/** За сколько суток до конца подписки напоминать. */
export const EXPIRING_DAYS = 3;

/** Какое напоминание показать: новая версия важнее срока подписки. Подписка — выбранного
 *  сервера; `now` — секунды Unix. */
export function pickNotice(
  updateVersion: string | null,
  sub: PanelSubscription | null,
  now: number,
): Notice | null {
  if (updateVersion) return { kind: "update", version: updateVersion };
  if (!sub || sub.expire === null) return null;
  const left = sub.expire - now;
  if (left > EXPIRING_DAYS * 86400) return null;
  return {
    kind: "expiring",
    title: sub.title,
    expired: left <= 0,
    days: Math.max(1, Math.ceil(left / 86400)),
  };
}

export function noticeText(n: Notice): string {
  if (n.kind === "update") return t(`Вышла KVT ${n.version}`, `KVT ${n.version} is out`);
  if (n.expired) return t(`Подписка «${n.title}» закончилась`, `“${n.title}” has expired`);
  const days = count(n.days, ["день", "дня", "дней"], ["day", "days"]);
  return t(`Подписка «${n.title}» заканчивается через ${days}`, `“${n.title}” expires in ${days}`);
}

export function noticeAction(n: Notice): string {
  return n.kind === "update" ? t("Скачать", "Download") : t("Подробнее", "Details");
}

/** Часы сеанса. Служба отвечает раз в несколько секунд, а секунды идут сами от последнего
 *  ответа. Служба отдаёт целые секунды: ответ чуть позади своего счёта не должен откатывать
 *  время назад. Сильно меньше — это новый сеанс. */
export interface Received {
  secs: number;
  /** Когда пришёл ответ (`performance.now()`, мс). */
  at: number;
}

export function nextReceived(prev: Received, secs: number, now: number): Received {
  const estimate = prev.secs + (now - prev.at) / 1000;
  return secs > estimate || secs < estimate - 3 ? { secs, at: now } : prev;
}

/** Другой сервер при проблеме: первый по списку (он уже по задержке), не текущий и не
 *  заведомо нерабочий. */
export function alternative(servers: PanelServer[], current: string | null): PanelServer | null {
  return servers.find((s) => s.key !== current && s.health !== "down") ?? null;
}
