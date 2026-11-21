// Тексты карточки подписки: сроки, трафик, причины, названия протоколов. Чистые
// функции без состояния окна. `t()` зовётся внутри функций, а не на уровне модуля:
// язык окна ставится до монтирования, а модуль загружается раньше.

import { count, locale, t } from "../i18n";
import type { SubscriptionItem } from "../api";

/** Настроено что-то кроме значений по умолчанию — видно на кнопке. */
export const customized = (s: SubscriptionItem) =>
  s.options.keep.length + s.options.drop.length > 0 ||
  s.options.client !== null ||
  s.options.hwid !== "auto" ||
  s.options.ownHwid;

const PROTOCOLS: Record<string, string> = {
  vless: "VLESS",
  trojan: "Trojan",
  shadowsocks: "Shadowsocks",
  hysteria2: "Hysteria2",
  vmess: "VMess",
  tuic: "TUIC",
  anytls: "AnyTLS",
  socks: "SOCKS5",
};

export const protocolTitle = (p: string): string =>
  p === "http" ? t("HTTP-прокси", "HTTP proxy") : (PROTOCOLS[p] ?? p.toUpperCase());

const GB = 2 ** 30;
const gb = (b: number) => (b / GB).toLocaleString(locale(), { maximumFractionDigits: b < 10 * GB ? 1 : 0 });

function ago(unix: number): string {
  const min = Math.max(0, Math.round((Date.now() / 1000 - unix) / 60));
  if (min < 1) return t("только что", "just now");
  if (min < 60) return t(`${min} мин назад`, `${min} min ago`);
  const h = Math.round(min / 60);
  if (h < 24) return t(`${h} ч назад`, `${h} h ago`);
  return t(`${Math.round(h / 24)} дн назад`, `${Math.round(h / 24)} d ago`);
}

function inFuture(unix: number): string {
  const min = Math.round((unix - Date.now() / 1000) / 60);
  if (min < 1) return t("скоро", "soon");
  if (min < 60) return t(`через ${min} мин`, `in ${min} min`);
  const h = Math.round(min / 60);
  if (h < 48) return t(`через ${h} ч`, `in ${h} h`);
  return t(`через ${Math.round(h / 24)} дн`, `in ${Math.round(h / 24)} d`);
}

export function details(s: SubscriptionItem): string {
  // Перенесённая подписка, которую ещё не удалось загрузить.
  if (s.byUrl && s.servers === 0 && s.hidden === 0)
    return t("ещё не загружена — нажмите «Обновить», когда будет доступ к сайту провайдера", "not loaded yet — press “Update” once the provider's site is reachable");
  const hidden = s.hidden > 0 ? t(` (ещё ${s.hidden} скрыто фильтром)`, ` (${s.hidden} more hidden by the filter)`) : "";
  const servers = `${count(s.servers, ["сервер", "сервера", "серверов"], ["server", "servers"])}${hidden}`;
  if (!s.byUrl) return t(`${servers} · добавлены вручную, не обновляются`, `${servers} · added manually, not updated`);
  return [servers, t(`обновлена ${ago(s.updatedAt)}`, `updated ${ago(s.updatedAt)}`), s.nextUpdate ? t(`следующее ${inFuture(s.nextUpdate)}`, `next ${inFuture(s.nextUpdate)}`) : null]
    .filter(Boolean)
    .join(" · ");
}

export type Tone = "ok" | "warn" | "danger";

export function expiry(unix: number): { text: string; tone: Tone } {
  const days = Math.ceil((unix * 1000 - Date.now()) / 86_400_000);
  const date = new Date(unix * 1000).toLocaleDateString(locale(), { day: "numeric", month: "long" });
  if (days < 0) return { text: t(`Закончилась ${date} — продлите у провайдера`, `Expired ${date} — renew with your provider`), tone: "danger" };
  if (days === 0) return { text: t("Заканчивается сегодня", "Expires today"), tone: "danger" };
  const left = t(
    `осталось ${count(days, ["день", "дня", "дней"], ["", ""])}`,
    `${count(days, ["", "", ""], ["day", "days"])} left`,
  );
  return { text: t(`До ${date} · ${left}`, `Until ${date} · ${left}`), tone: days <= 3 ? "warn" : "ok" };
}

export function usage(s: SubscriptionItem): { text: string; share: number | null; tone: Tone } | null {
  if (s.usedBytes == null) return null;
  if (!s.totalBytes) return { text: t(`Израсходовано ${gb(s.usedBytes)} ГБ · без лимита`, `Used ${gb(s.usedBytes)} GB · no limit`), share: null, tone: "ok" };
  const share = s.usedBytes / s.totalBytes;
  const left = Math.max(0, s.totalBytes - s.usedBytes);
  return {
    text: share >= 1 ? t(`Трафик закончился: ${gb(s.totalBytes)} ГБ`, `Traffic used up: ${gb(s.totalBytes)} GB`) : t(`${gb(s.usedBytes)} из ${gb(s.totalBytes)} ГБ · осталось ${gb(left)} ГБ`, `${gb(s.usedBytes)} of ${gb(s.totalBytes)} GB · ${gb(left)} GB left`),
    share: Math.min(1, share),
    tone: share >= 1 ? "danger" : share > 0.9 ? "warn" : "ok",
  };
}

export type Usage = NonNullable<ReturnType<typeof usage>>;
export type Expiry = ReturnType<typeof expiry>;

export const skippedCount = (s: SubscriptionItem) => s.skipped.reduce((n, x) => n + x.count, 0);

export function skippedSummary(s: SubscriptionItem, skipped: number): string {
  return [
    skipped > 0
      ? t(
          `Пропущено ${count(skipped, ["строка", "строки", "строк"], ["", ""])}`,
          `Skipped ${count(skipped, ["", "", ""], ["line", "lines"])}`,
        )
      : null,
    s.duplicates > 0 ? t(`убрано повторов: ${s.duplicates}`, `duplicates removed: ${s.duplicates}`) : null,
  ]
    .filter(Boolean)
    .join(" · ");
}

/** Причина неудачного обновления одной фразой, с точкой в конце. */
export function trouble(s: SubscriptionItem, at: number): string {
  const reason = s.lastError?.trim().replace(/[.!]*$/, ".") ?? "";
  const old = s.servers > 0 ? t(" Пока работают серверы из прошлой версии.", " Servers from the previous version still work.") : "";
  return t(`Не обновилась ${ago(at)}: ${reason}${old}`, `Not updated ${ago(at)}: ${reason}${old}`);
}
