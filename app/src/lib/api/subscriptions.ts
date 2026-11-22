// Подписки и ручные ключи: список, настройки подписки, правка и удаление.

import { t } from "../i18n";
import { inTauri, invoke, listen } from "./bridge";
import { type ServerSummary, connect } from "./connection";
import { previewData } from "./preview";

export interface SubscriptionItem {
  id: string;
  title: string;
  byUrl: boolean;
  servers: number;
  usedBytes: number | null;
  totalBytes: number | null;
  /** Unix-время окончания. */
  expire: number | null;
  /** Unix-время последнего обновления. */
  updatedAt: number;
  /** Когда обновится сама (только у подписок по ссылке). */
  nextUpdate: number | null;
  /** Название задал пользователь. */
  renamed: boolean;
  /** Последнее обновление не удалось: почему и когда. */
  lastError: string | null;
  failedAt: number | null;
  /** Ссылки провайдера (только https) — открываются через Rust по id подписки. */
  supportUrl: string | null;
  webPageUrl: string | null;
  /** Текст провайдера — выводится только как текст. */
  announce: string | null;
  /** Служебные строки провайдера («Осталось 10 ГБ»). */
  info: string[];
  /** Серверы по протоколам, по убыванию. */
  protocols: { protocol: string; count: number }[];
  /** Почему часть строк подписки пропущена. */
  skipped: { reason: string; count: number }[];
  /** Выброшенные точные повторы. */
  duplicates: number;
  /** Что KVT у части серверов не применяет (например, pinSHA256): текст и число серверов. */
  warnings: { reason: string; count: number }[];
  /** Ключи группы «Добавлено вручную» (у подписок по ссылке пусто). */
  keys: ManualKey[];
  /** Сколько серверов скрыл фильтр из «Расширенных». */
  hidden: number;
  options: SubscriptionOptions;
}

/** Когда отправлять провайдеру ID устройства (x-hwid). */
export type HwidMode = "auto" | "always" | "never";

/** «Расширенные» подписки. Свой ID устройства окно не получает — только `ownHwid`. */
export interface SubscriptionOptions {
  /** Оставить только серверы с этими словами в названии (или с флагом страны). */
  keep: string[];
  /** Убрать серверы с этими словами. */
  drop: string[];
  /** null — «Авто» (по очереди), иначе профиль клиента или "custom". */
  client: string | null;
  userAgent: string | null;
  hwid: HwidMode;
  /** Задан ID устройства от провайдера. */
  ownHwid: boolean;
  /** ID устройства сейчас уходит провайдеру. */
  hwidSent: boolean;
}

/** Что сохранить в «Расширенных». */
export interface SubscriptionOptionsInput {
  keep: string;
  drop: string;
  client: string | null;
  userAgent: string;
  hwid: HwidMode;
  /** null — не менять, "" — убрать свой ID. */
  ownHwid: string | null;
}

const defaultOptions: SubscriptionOptions = {
  keep: [],
  drop: [],
  client: null,
  userAgent: null,
  hwid: "auto",
  ownHwid: false,
  hwidSent: false,
};

/** Ключ, добавленный вручную. Самой ссылки (с UUID или паролем) окно не получает —
 *  её можно только заменить новой. */
export interface ManualKey {
  key: string;
  /** Название целиком, как в ссылке (с флагами-эмодзи) — для правки. */
  name: string;
  /** Название без ведущего флага — для списка; он рисуется картинкой (`flag`). */
  title: string;
  /** Страна: из флага в названии, а если его нет — по адресу-IP сервера. */
  flag: string | null;
  protocol: string;
  transport: string;
}

/** Превью: у первой подписки — пропущенные строки, у второй — неудачное обновление.
 *  Функция, а не константа: t() читает язык при вызове (на уровне модуля он ещё не выбран). */
const previewExtras = (): Record<string, Partial<SubscriptionItem>> => ({
  a: {
    supportUrl: "https://t.me/support",
    webPageUrl: "https://example.com",
    announce:
      "Плановые работы на серверах в Германии 20 ноября с 03:00 до 04:00 МСК.",
    skipped: [{ reason: t("не поддерживается: WireGuard", "not supported: WireGuard"), count: 2 }],
    duplicates: 1,
    warnings: [
      {
        reason:
          t("сертификат сервера не проверяется — VPN-ядро не умеет сверять отпечаток pinSHA256", "the server certificate isn't verified — the VPN core can't check the pinSHA256 fingerprint"),
        count: 2,
      },
    ],
  },
  b: {
    options: { ...defaultOptions, hwidSent: true },
  },
  c: {
    lastError:
      t("Не удалось подключиться к серверу подписки — возможно, он заблокирован. Включите VPN и повторите", "Couldn't connect to the subscription server — it may be blocked. Turn on the VPN and try again"),
    failedAt: Math.floor(Date.now() / 1000) - 2 * 3600,
  },
});

/** Как фильтр в Rust (`NameFilter::allows`) — для превью. */
function previewAllows(o: SubscriptionOptions, s: ServerSummary): boolean {
  const name = s.name.toLowerCase();
  const hit = (w: string) => name.includes(w) || s.flag === w;
  return (o.keep.length === 0 || o.keep.some(hit)) && !o.drop.some(hit);
}

const previewOptions: Record<string, SubscriptionOptions> = {};

export async function listSubscriptions(): Promise<SubscriptionItem[]> {
  if (!inTauri) {
    const extras = previewExtras();
    return previewData().map((g) => {
      const options = previewOptions[g.id] ?? extras[g.id]?.options ?? defaultOptions;
      const visible = g.servers.filter((s) => previewAllows(options, s));
      return {
      id: g.id,
      title: previewTitles[g.id] ?? g.title,
      byUrl: g.byUrl,
      servers: visible.length,
      usedBytes: g.meta.usedBytes,
      totalBytes: g.meta.totalBytes,
      expire: g.meta.expire,
      updatedAt: g.updatedAt,
      nextUpdate: g.byUrl ? g.updatedAt + 12 * 3600 : null,
      renamed: g.id in previewTitles,
      lastError: null,
      failedAt: null,
      supportUrl: null,
      webPageUrl: null,
      announce: null,
      info: g.info,
      protocols: Object.entries(
        g.servers.reduce<Record<string, number>>(
          (acc, s) => ((acc[s.protocol] = (acc[s.protocol] ?? 0) + 1), acc),
          {},
        ),
      )
        .map(([protocol, count]) => ({ protocol, count }))
        .sort((a, b) => b.count - a.count),
      skipped: [],
      duplicates: 0,
      warnings: [],
      ...extras[g.id],
      hidden: g.servers.length - visible.length,
      options,
      keys: g.byUrl
        ? []
        : visible.map((s) => ({
            key: s.key,
            name: s.name,
            title: s.name,
            flag: s.flag,
            protocol: s.protocol,
            transport: s.transport,
          })),
      };
    });
  }
  return invoke<SubscriptionItem[]>("list_subscriptions");
}

/** Сохраняет «Расширенные» подписки. Если сменился клиент или ID устройства,
 *  подписка сразу загружается заново; ошибка загрузки — исключением, но
 *  настройки уже сохранены. */
export async function setSubscriptionOptions(
  id: string,
  options: SubscriptionOptionsInput,
): Promise<void> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 500));
    const words = (t: string) =>
      [...new Set(t.split(/[,;\n]/).map((w) => w.trim().toLowerCase()).filter(Boolean))];
    if (options.client === "custom" && !/^[ -~]{1,200}$/.test(options.userAgent.trim()))
      throw new Error(t("User-Agent пустой, длиннее 200 символов или не латиницей — проверьте строку.", "The User-Agent is empty, longer than 200 characters or not in Latin script — check it."));
    const old = previewOptions[id] ?? defaultOptions;
    previewOptions[id] = {
      keep: words(options.keep),
      drop: words(options.drop),
      client: options.client,
      userAgent: options.client === "custom" ? options.userAgent.trim() : null,
      hwid: options.hwid,
      ownHwid: options.ownHwid === null ? old.ownHwid : options.ownHwid.trim() !== "",
      hwidSent: options.hwid === "always" || (options.hwid === "auto" && old.hwidSent),
    };
    return;
  }
  await invoke("set_subscription_options", { id, options });
}

/** Меняет ключ из группы «Добавлено вручную»: название и, если указана, ссылку.
 *  Возвращает ключ сервера после правки (меняется вместе с адресом или портом). */
export async function editServer(
  key: string,
  name: string,
  link: string | null,
): Promise<string> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 400));
    const s = previewData()
      .flatMap((g) => g.servers)
      .find((x) => x.key === key);
    if (!s) throw new Error(t("Этого сервера уже нет в списке.", "This server is no longer in the list."));
    if (link && !link.includes("://"))
      throw new Error(
        t("В ссылке не нашлось сервера — проверьте, что она скопирована целиком.", "No server found in the link — check that it was copied in full."),
      );
    if (name.trim()) s.name = name.trim();
    return key;
  }
  return invoke<string>("edit_server", { key, name, link });
}

/** Удаляет один ключ из группы «Добавлено вручную» (последний — вместе с группой). */
export async function removeServer(key: string): Promise<void> {
  if (!inTauri) {
    for (const g of previewData())
      g.servers = g.servers.filter((s) => s.key !== key);
    const i = previewData().findIndex(
      (g) => !g.byUrl && g.servers.length === 0,
    );
    if (i >= 0) previewData().splice(i, 1);
    return;
  }
  await invoke("remove_server", { key });
}

export async function removeSubscription(id: string): Promise<void> {
  if (!inTauri) {
    const i = previewData().findIndex((g) => g.id === id);
    if (i >= 0) previewData().splice(i, 1);
    return;
  }
  await invoke("remove_subscription", { id });
}

export async function refreshSubscription(id: string): Promise<void> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 700));
    return;
  }
  await invoke("refresh_subscription", { id });
}

/** Обновляет все подписки по ссылке. Возвращает, сколько не обновилось. */
export async function refreshAllSubscriptions(): Promise<number> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 900));
    return previewData().some((g) => g.id === "c") ? 1 : 0;
  }
  return invoke<number>("refresh_all_subscriptions");
}

const previewTitles: Record<string, string> = {};

/** Своё название подписки; пустое — снова от провайдера. */
export async function renameSubscription(
  id: string,
  title: string,
): Promise<void> {
  if (!inTauri) {
    if (title.trim()) previewTitles[id] = title.trim();
    else delete previewTitles[id];
    return;
  }
  await invoke("rename_subscription", { id, title });
}

/** Открывает в браузере поддержку или сайт провайдера (адрес — из подписки, в Rust). */
export async function openSubscriptionLink(
  id: string,
  which: "support" | "site",
): Promise<void> {
  if (!inTauri) return;
  await invoke("open_subscription_link", { id, which });
}

/** Подписки изменились (добавлена, удалена, обновилась в фоне). Возвращает отписку. */
export function onSubscriptionsChanged(handler: () => void): () => void {
  if (!inTauri) return () => {};
  const off = listen("subscriptions-changed", handler);
  return () => void off.then((f) => f());
}
