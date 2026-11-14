// Мост к Rust-части приложения. В WebView попадают только данные для отображения:
// пароли, UUID и ссылки подписок остаются в Rust.

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { browserLang, isEn, t, type Lang, type LangChoice } from "./i18n";

export interface ServerSummary {
  /** Постоянный ключ сервера: выбор и проверки привязаны к нему, а не к номеру. */
  key: string;
  /** Название как в подписке без ведущего флага; флаги внутри («→🇪🇪») остаются. */
  name: string;
  /** Страна по первому флагу в названии (`ru`), как в других клиентах. */
  flag: string | null;
  address: string;
  port: number;
  protocol: string;
  transport: string;
  security: string;
  sni: string | null;
  core: "xray" | "sing-box";
  /** Тот же сервер, что у ключа выше в списке: провайдер повторил его под другим
   *  названием. Автопереключение такой повтор не перебирает. */
  sameAs: string | null;
}

export interface SubscriptionInfo {
  title: string | null;
  usedBytes: number | null;
  totalBytes: number | null;
  /** Unix-время окончания подписки. */
  expire: number | null;
  supportUrl: string | null;
  announce: string | null;
}

/** Подписка или вручную добавленные ключи — группа в общем списке серверов. */
export interface Group {
  id: string;
  title: string;
  byUrl: boolean;
  updatedAt: number;
  meta: SubscriptionInfo;
  servers: ServerSummary[];
  info: string[];
  /** Сколько строк подписки не разобралось. */
  errors: number;
}

export interface Added {
  /** Первая добавленная группа. */
  group: string | null;
  /** Первый сервер новой подписки — его сразу выбираем. */
  first: string | null;
  servers: number;
  /** Сколько подписок по ссылке добавлено (или обновлено, если уже были). */
  subscriptions: number;
  /** Что не добавилось (часть вставки) — тексты без ссылок. */
  failed: string[];
}

export type Mode = "vpn" | "hybrid" | "zapret";

const inTauri =
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
/** Окно работает в приложении, а не в превью браузера (`npm run dev`). */
export const inApp = inTauri;

/** Любая вставка: ссылки на подписки (одна, несколько или внутри текста), ссылки
 *  «добавить в приложение» (happ://add/…), ключи, base64, конфиги Xray и sing-box.
 *  Разбирает Rust; если добавилась только часть, причины — в `failed`. */
export async function addSubscription(input: string): Promise<Added> {
  if (!inTauri) {
    if (
      /(^|\s)https?:\/\/(?![^\s/@]+@[^\s/?#]+\/?([?#\s]|$))/i.test(input) &&
      !/(vless|vmess|trojan|ss|hy2|hysteria2|tuic|anytls|socks5?):\/\//i.test(
        input,
      )
    )
      throw new Error(
        t("Загрузка подписки по ссылке работает в приложении (npm run tauri dev).", "Loading a subscription by link works in the app (npm run tauri dev)."),
      );
    return previewAdd(input);
  }
  return invoke<Added>("add_input", { input });
}

export type QuickResult =
  | { kind: "reachable"; latency_ms: number }
  | { kind: "unreachable" }
  | { kind: "dns_failed" }
  | { kind: "not_applicable" };

/** Быстрая проверка: TCP-пинг без TLS. `group` — одна подписка, `null` — все. Итог — по ключам серверов. */
export async function quickCheck(
  group: string | null,
): Promise<Record<string, QuickResult>> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 600));
    const out: Record<string, QuickResult> = {};
    previewData()
      .filter((g) => group === null || g.id === group)
      .flatMap((g) => g.servers)
      .forEach((s, i) => {
        const demoMs = [38, 47, 52, 61, 66, 74, 118, 83, 55];
        out[s.key] = demo
          ? { kind: "reachable", latency_ms: demoMs[i % demoMs.length]! }
          : i === 1
            ? { kind: "unreachable" }
            : { kind: "reachable", latency_ms: 40 + i * 37 };
      });
    return out;
  }
  return invoke<Record<string, QuickResult>>("quick_check", { group });
}

export type ServiceStatus =
  | { state: "disconnected" }
  | { state: "connecting" }
  | { state: "connected"; core: "xray" | "sing-box" }
  | { state: "zapret"; strategy: string }
  /** `blocked` — ядро остановилось, а kill switch держит интернет закрытым. */
  | { state: "failed"; reason: string; blocked?: boolean };

export type ListAction = "proxy" | "direct" | "block";

export interface RoutingSettings {
  /** compact — списки podkop (itdoginfo), full — реестр runetfreedom. */
  listMode: "compact" | "full";
  /** Куда идёт всё, что не попало в списки. */
  everythingElse: "proxy" | "direct";
  /** Выбор для отдельных списков: id → действие. */
  overrides: Record<string, ListAction>;
  /** Свои сайты и адреса: важнее списков. */
  custom: CustomRoute[];
}

/** Свой сайт: домен со всеми поддоменами, IP или подсеть. */
export interface CustomRoute {
  target: string;
  action: ListAction;
}

export const defaultRouting = (): RoutingSettings => ({
  listMode: "compact",
  everythingElse: "proxy",
  overrides: {},
  custom: [],
});

export interface Choice {
  /** Ключ выбранного сервера. */
  server: string | null;
  mode: Mode | null;
  killSwitch: boolean;
  routing: RoutingSettings;
  dns: DnsChoice;
  /** Переключаться на другой сервер, если через текущий перестали идти данные. */
  autoSwitch: boolean;
  networks: NetworkProfile[];
  zapret: ZapretChoice;
  /** Уведомления Windows, пока окно закрыто. */
  notifications: boolean;
  /** Подключаться к выбранному серверу при запуске KVT. */
  connectOnStart: boolean;
  /** Узнавать у GitHub, не вышла ли новая версия KVT. */
  checkUpdates: boolean;
  /** Подсказки первого запуска пройдены или пропущены. */
  onboarded: boolean;
}

export interface ListInfo {
  id: string;
  title: string;
  kind: "region" | "category" | "service";
  /** Что входит в список; пусто — подсказки нет. */
  hint: string;
}

export async function listCatalog(): Promise<ListInfo[]> {
  if (!inTauri) {
    return [
      {
        id: "russia_inside",
        title: t("Заблокировано в России", "Blocked in Russia"),
        kind: "region",
        hint: t("Сайты и сервисы из реестра блокировок и замедленные", "Sites and services from the block registry, plus throttled ones"),
      },
      {
        id: "russia_outside",
        title: t("Российские сайты, закрытые для зарубежа", "Russian sites closed to foreign visitors"),
        kind: "region",
        hint: t("Госуслуги, банки, магазины — не открываются с зарубежных IP", "Gosuslugi, banks, shops — don't open from foreign IPs"),
      },
      {
        id: "geoblock",
        title: t("Сервисы, закрытые для России", "Services closed to Russia"),
        kind: "category",
        hint: t("ИИ, стриминг и магазины, которые сами не пускают из России", "AI, streaming and shops that refuse visitors from Russia"),
      },
      {
        id: "news",
        title: t("Новости", "News"),
        kind: "category",
        hint: t("Заблокированные СМИ", "Blocked media"),
      },
      {
        id: "youtube",
        title: "YouTube",
        kind: "service",
        hint: "youtube.com, googlevideo.com, ytimg.com",
      },
      {
        id: "discord",
        title: "Discord",
        kind: "service",
        hint: t("discord.com, discord.gg, голосовые серверы", "discord.com, discord.gg, voice servers"),
      },
      {
        id: "telegram",
        title: "Telegram",
        kind: "service",
        hint: t("t.me, telegram.org и адреса серверов", "t.me, telegram.org and server addresses"),
      },
      { id: "roblox", title: "Roblox", kind: "service", hint: "" },
    ];
  }
  return invoke<ListInfo[]>("list_catalog");
}

/** Свой сайт в том виде, в каком он попадёт в правило, или текст ошибки. */
export async function checkRouteTarget(target: string): Promise<string> {
  if (!inTauri) {
    const value = target.trim().toLowerCase();
    if (!value) throw t("Введите адрес сайта, IP или подсеть.", "Enter a site address, IP or subnet.");
    if (/\s/.test(value)) throw t("Одно правило — один адрес, без пробелов.", "One rule, one address, no spaces.");
    const host = value
      .replace(/^[a-z]+:\/\//, "")
      .split(/[/?#]/)[0]!
      .replace(/^.*@/, "")
      .replace(/:\d+$/, "")
      .replace(/^\*\./, "")
      .replace(/^www\./, "");
    if (!/^[\p{L}\d-]+(\.[\p{L}\d-]+)*$/u.test(host))
      throw t("Не похоже на адрес сайта. Пример: example.com", "Doesn't look like a site address. Example: example.com");
    return host;
  }
  return invoke<string>("check_route_target", { target });
}

/** Выбор сервера, режима и kill switch хранится в Rust — им пользуется и трей. */
export async function setChoice(choice: Choice): Promise<void> {
  if (inTauri) await invoke("set_choice", { choice });
}

/** Состояние для окна, открытого заново из трея. */
export async function snapshot(): Promise<{
  groups: Group[];
  choice: Choice | null;
}> {
  if (!inTauri) return { groups: withStressGroup(previewData()), choice: null };
  return invoke("snapshot");
}

export async function connect(): Promise<ServiceStatus> {
  if (demo) {
    await new Promise((r) => setTimeout(r, 1200));
    demoState = { state: "connected", core: "xray" };
    return demoState;
  }
  if (!inTauri)
    throw new Error(
      t("Подключение работает в приложении (npm run tauri dev) при запущенной службе.", "Connecting works in the app (npm run tauri dev) with the service running."),
    );
  return invoke<ServiceStatus>("connect");
}

export type CheckResult =
  | { verdict: "ok"; detail: string }
  | { verdict: "warning"; detail: string }
  | { verdict: "info"; detail: string };

export interface LeakReport {
  /** VPN был подключён: без него маршруты и DNS проверять не на что. */
  connected: boolean;
  openProxies: {
    port: number;
    process: string | null;
    knownScanPort: boolean;
  }[];
  ipv4Route: CheckResult;
  ipv6Route: CheckResult;
  dns: CheckResult;
}

export async function leakTest(): Promise<LeakReport> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 500));
    return {
      connected: false,
      openProxies: [
        { port: 10808, process: "example-vpn.exe", knownScanPort: false },
      ],
      ipv4Route: {
        verdict: "info",
        detail: t("VPN выключен: трафик идёт напрямую", "VPN is off: traffic goes direct"),
      },
      ipv6Route: {
        verdict: "ok",
        detail: t("IPv6 в интернет недоступен — утечки через IPv6 быть не может", "IPv6 internet is unavailable — no leak via IPv6 is possible"),
      },
      dns: {
        verdict: "info",
        detail: t("VPN выключен: DNS обслуживает провайдер", "VPN is off: DNS is served by your ISP"),
      },
    };
  }
  return invoke<LeakReport>("leak_test");
}

export async function disconnect(): Promise<ServiceStatus> {
  if (!inTauri) {
    demoState = { state: "disconnected" };
    return demoState;
  }
  return invoke<ServiceStatus>("disconnect");
}

/** `null` — служба не запущена. */
export async function serviceStatus(): Promise<ServiceStatus | null> {
  if (!inTauri) return demo ? demoState : null;
  return invoke<ServiceStatus | null>("service_status");
}

/** Сеанс — от «Подключить» до «Отключить»: время и трафик через адаптер KVT. */
export interface Session {
  secs: number;
  /** `null` — адаптера нет (режим Zapret). */
  rx: number | null;
  tx: number | null;
}

const previewStart = Date.now();

/** Последний сеанс, о котором сообщила служба (берётся после `serviceStatus`). */
export async function serviceSession(): Promise<Session | null> {
  if (!inTauri)
    return {
      secs: 4325 + Math.floor((Date.now() - previewStart) / 1000),
      rx: 1_331_000_000,
      tx: 88_200_000,
    };
  return invoke<Session | null>("service_session");
}

/** 0:42, 12:05, 1:12:05 — секунды сеанса для строки на главной. */
export function formatElapsed(secs: number): string {
  const s = Math.max(0, Math.floor(secs));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const ss = String(s % 60).padStart(2, "0");
  return h > 0 ? `${h}:${String(m).padStart(2, "0")}:${ss}` : `${m}:${ss}`;
}

/** 84 МБ, 1,24 ГБ — с запятой, без лишних знаков. */
export function formatBytes(bytes: number): string {
  const en = isEn();
  const units = en ? ["B", "KB", "MB", "GB", "TB"] : ["Б", "КБ", "МБ", "ГБ", "ТБ"];
  let value = bytes;
  let unit = 0;
  while (value >= 1000 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  const digits = unit === 0 || value >= 100 ? 0 : value >= 10 ? 1 : 2;
  const text = value.toFixed(digits);
  return `${en ? text : text.replace(".", ",")} ${units[unit]}`;
}

// Предпросмотр интерфейса в обычном браузере (npm run dev) без Rust-части.
// Флаг — первый эмодзи-флаг, ведущий уходит из названия (упрощённо, как kvt_core::flag).
function previewServer(name: string, i: number, group: string): ServerSummary {
  const first = /([\u{1F1E6}-\u{1F1FF}]{2})/u.exec(name);
  const flag = first
    ? Array.from(first[1]!, (c) =>
        String.fromCharCode(97 + c.codePointAt(0)! - 0x1f1e6),
      ).join("")
    : null;
  const leading = first?.index === 0;
  return {
    key: `${group}-${i}`,
    name: leading
      ? name.slice(first![1]!.length).replace(/^[\s|·,:\uFE0F]+/u, "")
      : name,
    flag,
    address: "preview.example",
    port: 443,
    protocol: "vless",
    transport: i % 4 === 2 ? "xhttp" : "tcp",
    security: "reality",
    sni: "www.microsoft.com",
    core: "xray",
    // В превью пятый сервер группы повторяет первый — видно пометку «тот же сервер».
    sameAs: i === 4 ? `${group}-0` : null,
  };
}

/** Превью: `?servers=10000` добавляет большую подписку — проверить главную на длинных списках. */
function withStressGroup(groups: Group[]): Group[] {
  const n = Number(new URLSearchParams(location.search).get("servers") ?? 0);
  if (!n) return groups;
  const flags = ["🇳🇱", "🇩🇪", "🇫🇮", "🇩🇰", "🇺🇸"];
  const servers = Array.from({ length: n }, (_, i) =>
    previewServer(`${flags[i % flags.length]} Сервер ${i + 1}`, i, "big"),
  );
  return [
    ...groups,
    { ...groups[0]!, id: "big", title: `Большая подписка (${n})`, servers },
  ];
}

function sampleGroups(): Group[] {
  return [
  {
    id: "a",
    title: "KVT",
    byUrl: true,
    updatedAt: Math.floor(Date.now() / 1000) - 3 * 3600,
    meta: {
      title: "KVT",
      usedBytes: 34 * 2 ** 30,
      totalBytes: 100 * 2 ** 30,
      expire: Math.floor(Date.now() / 1000) + 45 * 86400,
      supportUrl: null,
      announce: null,
    },
    servers: [
      "🇷🇺→🇪🇪 для wifi · via RU",
      "🇪🇪 для wifi · прямой",
      "🇳🇱 Нидерланды",
      "🇩🇪 Германия ⚡",
      "🇫🇮 Финляндия",
      "🇺🇸 США · YouTube",
      "Резерв без флага",
    ].map((n, i) => previewServer(n, i, "a")),
    info: [],
    errors: 0,
  },
  {
    id: "b",
    title: t("Добавлено вручную", "Added manually"),
    byUrl: false,
    updatedAt: Math.floor(Date.now() / 1000) - 60,
    meta: {
      title: null,
      usedBytes: null,
      totalBytes: null,
      expire: null,
      supportUrl: null,
      announce: null,
    },
    servers: [previewServer("🇩🇰 DK для wifi-familydk", 0, "b")],
    info: [],
    errors: 0,
  },
  {
    id: "c",
    title: "Резервный провайдер",
    byUrl: true,
    updatedAt: Math.floor(Date.now() / 1000) - 3 * 86400,
    meta: {
      title: "Резервный провайдер",
      usedBytes: 47 * 2 ** 30,
      totalBytes: 50 * 2 ** 30,
      expire: Math.floor(Date.now() / 1000) + 2 * 86400,
      supportUrl: null,
      announce: null,
    },
    servers: [
      previewServer("🇸🇪 Швеция", 0, "c"),
      previewServer("🇵🇱 Польша", 1, "c"),
    ],
    info: [],
    errors: 0,
  },
  ];
}

/** Превью: `?demo` — вид для скриншотов README: VPN подключён, аккуратные серверы,
 *  без плашки о новой версии. Снимает их `app/scripts/screenshots.mjs`. */
const demo =
  !inTauri &&
  typeof location !== "undefined" &&
  new URLSearchParams(location.search).has("demo");
let demoState: ServiceStatus = { state: "connected", core: "xray" };

function demoGroups(): Group[] {
  const now = Math.floor(Date.now() / 1000);
  const names: [string, string][] = [
    ["🇳🇱 Нидерланды", "🇳🇱 Netherlands"],
    ["🇩🇪 Германия", "🇩🇪 Germany"],
    ["🇫🇮 Финляндия", "🇫🇮 Finland"],
    ["🇸🇪 Швеция", "🇸🇪 Sweden"],
    ["🇵🇱 Польша", "🇵🇱 Poland"],
    ["🇬🇧 Лондон", "🇬🇧 London"],
    ["🇺🇸 США", "🇺🇸 United States"],
    ["🇹🇷 Турция", "🇹🇷 Turkey"],
  ];
  return [
    {
      id: "demo",
      title: t("Мой VPN", "My VPN"),
      byUrl: true,
      updatedAt: now - 2 * 3600,
      meta: {
        title: t("Мой VPN", "My VPN"),
        usedBytes: 34 * 2 ** 30,
        totalBytes: 200 * 2 ** 30,
        expire: now + 45 * 86400,
        supportUrl: null,
        announce: null,
      },
      servers: names.map(([ru, en], i) => ({
        ...previewServer(t(ru, en), i, "demo"),
        sameAs: null,
      })),
      info: [],
      errors: 0,
    },
    {
      id: "demo-manual",
      title: t("Добавлено вручную", "Added manually"),
      byUrl: false,
      updatedAt: now - 3 * 86400,
      meta: {
        title: null,
        usedBytes: null,
        totalBytes: null,
        expire: null,
        supportUrl: null,
        announce: null,
      },
      servers: [previewServer(t("🇫🇮 Свой сервер", "🇫🇮 My own server"), 0, "demo-manual")],
      info: [],
      errors: 0,
    },
  ];
}

let previewGroupsCache: Group[] | null = null;

/** Группы превью. Меняются на месте (добавление, удаление), как список в приложении. */
function previewData(): Group[] {
  previewGroupsCache ??= demo ? demoGroups() : sampleGroups();
  return previewGroupsCache;
}

function previewAdd(body: string): Added {
  const lines = body.split(/\r?\n/).filter((l) => l.includes("://"));
  // Как в приложении: ручные ключи — в одной группе.
  let group = previewData().find((g) => !g.byUrl);
  if (!group) {
    group = {
      id: "manual",
      title: t("Добавлено вручную", "Added manually"),
      byUrl: false,
      updatedAt: 0,
      meta: {
        title: null,
        usedBytes: null,
        totalBytes: null,
        expire: null,
        supportUrl: null,
        announce: null,
      },
      servers: [],
      info: [],
      errors: 0,
    };
    previewData().push(group);
  }
  const start = group.servers.length;
  const id = group.id;
  group.servers.push(
    ...lines.map((l, i) =>
      previewServer(
        decodeURIComponent(l.split("#")[1] ?? `Сервер ${i + 1}`),
        start + i,
        id,
      ),
    ),
  );
  group.updatedAt = Math.floor(Date.now() / 1000);
  return {
    group: id,
    first: lines.length > 0 ? `${id}-${start}` : null,
    servers: lines.length,
    subscriptions: 0,
    failed: [],
  };
}

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
  flag: string | null;
  protocol: string;
  address: string;
  port: number;
}

/** Превью: у первой подписки — пропущенные строки, у второй — неудачное обновление. */
const previewExtras: Record<string, Partial<SubscriptionItem>> = {
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
};

/** Как фильтр в Rust (`NameFilter::allows`) — для превью. */
function previewAllows(o: SubscriptionOptions, s: ServerSummary): boolean {
  const name = s.name.toLowerCase();
  const hit = (w: string) => name.includes(w) || s.flag === w;
  return (o.keep.length === 0 || o.keep.some(hit)) && !o.drop.some(hit);
}

const previewOptions: Record<string, SubscriptionOptions> = {};

export async function listSubscriptions(): Promise<SubscriptionItem[]> {
  if (!inTauri) {
    return previewData().map((g) => {
      const options = previewOptions[g.id] ?? previewExtras[g.id]?.options ?? defaultOptions;
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
      ...previewExtras[g.id],
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
            address: s.address,
            port: s.port,
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

export type ProbeVerdict =
  | "works"
  | "slow"
  | "dns_failed"
  | "unreachable"
  | "tls_frozen"
  | "data_frozen"
  | "rejected"
  | "config_error";

export type Outcome =
  | { kind: "checked"; verdict: ProbeVerdict; latency_ms: number | null }
  | { kind: "deferred"; retry_after_secs: number };

/**
 * Полная проверка через тестовое ядро: одна подписка (`group`) или все (`null`).
 * Результаты приходят по одному, по ключам серверов.
 */
export async function fullCheck(
  group: string | null,
  onResult: (key: string, outcome: Outcome) => void,
): Promise<void> {
  if (!inTauri) {
    const keys = previewData()
      .filter((g) => group === null || g.id === group)
      .flatMap((g) => g.servers.map((s) => s.key));
    const demo: Outcome[] = [
      { kind: "checked", verdict: "works", latency_ms: 184 },
      { kind: "checked", verdict: "data_frozen", latency_ms: 240 },
      { kind: "checked", verdict: "slow", latency_ms: 2100 },
      { kind: "deferred", retry_after_secs: 170 },
    ];
    for (const [i, key] of keys.entries()) {
      await new Promise((r) => setTimeout(r, 250));
      onResult(key, demo[i % demo.length]!);
    }
    return;
  }
  const off = await listen<{ key: string; outcome: Outcome }>(
    "probe-result",
    (e) => onResult(e.payload.key, e.payload.outcome),
  );
  try {
    await invoke("full_check", { group });
  } finally {
    off();
  }
}

// ── Этап 3: проверка DNS, «Почему не работает?», профили сетей, автопереключение ──

export type PathStatus =
  | { state: "works"; ms: number }
  | { state: "intercepted"; ms: number; by: string }
  | { state: "blocked" }
  | { state: "failed"; reason: string }
  | { state: "not_checked" };

export interface ResolverReport {
  id: string;
  title: string;
  udp: PathStatus;
  dot: PathStatus;
  doh: PathStatus;
}

export interface SpoofFinding {
  domain: string;
  source: string;
  kind: "stub" | "fake_ip" | "denied";
  got: string[];
}

export interface DnsReport {
  resolvers: ResolverReport[];
  systemServer: string | null;
  systemEgress: string | null;
  interception: boolean;
  spoofing: SpoofFinding[];
  fakeIp: boolean;
  encryptedAvailable: boolean;
  recommendedLocal: string;
  tone: "ok" | "warning";
  title: string;
  detail: string;
}

export interface Resolver {
  id: string;
  title: string;
  udp: string;
  /** Годится как DoH внутри туннеля. */
  tunnel: boolean;
}

export interface DnsChoice {
  /** Резолвер для сайтов, которые открываются напрямую. */
  local: string;
  /** DoH внутри туннеля для всего остального. */
  remote: string;
}

export const defaultDns = (): DnsChoice => ({
  local: "yandex",
  remote: "cloudflare",
});

const previewResolvers: Resolver[] = [
  { id: "yandex", title: t("Яндекс", "Yandex"), udp: "77.88.8.8", tunnel: false },
  { id: "cloudflare", title: "Cloudflare", udp: "1.1.1.1", tunnel: true },
  { id: "google", title: "Google", udp: "8.8.8.8", tunnel: true },
  { id: "quad9", title: "Quad9", udp: "9.9.9.9", tunnel: true },
  { id: "adguard", title: "AdGuard", udp: "94.140.14.14", tunnel: false },
];

export async function dnsCatalog(): Promise<Resolver[]> {
  if (!inTauri) return previewResolvers;
  return invoke<Resolver[]>("dns_catalog");
}

export async function dnsCheck(): Promise<DnsReport> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 900));
    const works = (ms: number): PathStatus => ({ state: "works", ms });
    return {
      resolvers: previewResolvers.map((r, i) => ({
        id: r.id,
        title: r.title,
        udp:
          i === 2
            ? { state: "intercepted", ms: 12, by: "212.48.193.5" }
            : works(20 + i * 9),
        dot: i === 3 ? { state: "blocked" } : works(150 + i * 20),
        doh: i === 0 ? { state: "not_checked" } : works(190 + i * 15),
      })),
      systemServer: "192.168.1.1",
      systemEgress: "212.48.193.5",
      interception: true,
      spoofing: [],
      fakeIp: false,
      encryptedAvailable: true,
      recommendedLocal: "yandex",
      tone: "warning",
      title: t("Провайдер перехватывает DNS-запросы", "Your ISP intercepts DNS queries"),
      detail:
        t("На запросы к публичным DNS по UDP отвечает сервер провайдера (212.48.193.5). При подключении через KVT это не мешает: DNS шифруется (DoH) и идёт внутри туннеля.", "Queries to public DNS over UDP are answered by your ISP's server (212.48.193.5). This doesn't matter when connected through KVT: DNS is encrypted (DoH) and goes inside the tunnel."),
    };
  }
  return invoke<DnsReport>("dns_check");
}

export type Fix =
  | { kind: "connect" }
  | { kind: "disconnect" }
  | { kind: "switch_server"; key: string; name: string }
  | { kind: "refresh_subscription" }
  | { kind: "add_subscription" }
  | { kind: "open_dns_check" }
  | { kind: "zapret_autoselect" };

export interface DiagnosisStep {
  title: string;
  state: "ok" | "warning" | "fail";
  detail: string;
}

export interface Diagnosis {
  tone: "ok" | "warning" | "error";
  title: string;
  detail: string;
  steps: DiagnosisStep[];
  fix: Fix | null;
}

export async function troubleshoot(): Promise<Diagnosis> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 1200));
    // В `?demo` — названия серверов из demo-списка.
    const current = demo ? t("Нидерланды", "Netherlands") : "NL Amsterdam";
    const next = demo ? t("Германия", "Germany") : "Германия ⚡";
    return {
      tone: "error",
      title: t("Провайдер блокирует этот сервер", "Your ISP is blocking this server"),
      detail:
        t(`Соединение обрывается после первых килобайт — режет DPI. Можно переключиться на «${next}».`, `The connection drops after the first kilobytes — DPI is cutting it. You can switch to “${next}”.`),
      steps: [
        { title: t("Сеть", "Network"), state: "ok", detail: t("Подключение к сети есть", "Network connection is up") },
        { title: t("Служба KVT", "KVT service"), state: "ok", detail: t("Служба работает", "The service is running") },
        { title: t("Подписка", "Subscription"), state: "ok", detail: t("Подписка действует", "The subscription is active") },
        { title: t("Интернет без VPN", "Internet without VPN"), state: "ok", detail: t("Интернет работает", "The internet works") },
        {
          title: t("Сервер", "Server"),
          state: "ok",
          detail: t(`«${current}» отвечает, 48 мс`, `“${current}” responds, 48 ms`),
        },
        {
          title: t("Проверка сервера", "Server check"),
          state: "fail",
          detail: t("Соединение обрывается после первых килобайт — режет DPI", "The connection drops after the first kilobytes — DPI is cutting it"),
        },
      ],
      fix: { kind: "switch_server", key: demo ? "demo-1" : "a-1", name: next },
    };
  }
  return invoke<Diagnosis>("troubleshoot");
}

export type OnJoin = "nothing" | "connect" | "disconnect";

export interface NetworkProfile {
  key: string;
  name: string;
  onJoin: OnJoin;
  /** Режим, который включается в этой сети; null — не менять. */
  mode: Mode | null;
}

export interface NetworkInfo {
  key: string;
  label: string;
  kind: "wifi" | "ethernet" | "mobile" | "other";
}

export interface NetworkView {
  network: NetworkInfo | null;
  profile: NetworkProfile | null;
}

export async function currentNetwork(): Promise<NetworkView> {
  if (!inTauri)
    return {
      network: { key: "preview", label: "Home 5G", kind: "wifi" },
      profile: null,
    };
  return invoke<NetworkView>("current_network");
}

export function onNetworkChanged(
  handler: (view: NetworkView) => void,
): () => void {
  if (!inTauri) return () => {};
  const off = listen<NetworkView>("network-changed", (e) => handler(e.payload));
  return () => void off.then((f) => f());
}

/** Выбор поменялся не из окна: автопереключение сервера или профиль сети. */
export function onChoiceChanged(handler: () => void): () => void {
  if (!inTauri) return () => {};
  const off = listen("choice-changed", handler);
  return () => void off.then((f) => f());
}

export type WatchdogEvent =
  | { kind: "switched"; from: string; to: string }
  | { kind: "no_network" }
  | { kind: "no_alternative"; server: string }
  | { kind: "gave_up" }
  /** Сеть просит войти (отель, кафе): другой сервер не поможет. */
  | { kind: "captive_portal" }
  /** Сервер, к которому были подключены, исчез из подписок — VPN отключён. */
  | { kind: "server_removed"; server: string }
  /** Провайдер убрал сервер, к которому были подключены, — KVT подключился к замене. */
  | { kind: "server_replaced"; from: string; to: string };

export function onWatchdog(
  handler: (event: WatchdogEvent) => void,
): () => void {
  if (!inTauri) return () => {};
  const off = listen<WatchdogEvent>("watchdog", (e) => handler(e.payload));
  return () => void off.then((f) => f());
}

// ── Этап 4: zapret (Flowseal) ──

export type GameFilter = "off" | "tcp" | "udp" | "all";

export interface ZapretStrategy {
  /** Имя файла стратегии Flowseal без .bat: «general (ALT4)». */
  id: string;
  /** «ALT4», «Основная». */
  title: string;
  recommended: boolean;
  /** Нужны TCP timestamps (fooling=ts). */
  needsTimestamps: boolean;
}

export interface ZapretChoice {
  /** Выбранная вручную стратегия; null — основная. */
  strategy: string | null;
  gameFilter: GameFilter;
  /** Разрешить включать TCP timestamps для стратегий, которым они нужны. */
  tcpTimestamps: boolean;
  /** Итог автоподбора для каждой сети. */
  byNetwork: Record<string, string>;
  /** Обход по IP-списку Flowseal, а не только по доменам. */
  ipset: boolean;
  /** Проверять работу раз в полчаса и после смены сети. */
  autoCheck: boolean;
  /** Если стратегия перестала работать — подобрать новую (режим «Zapret»). */
  autoPick: boolean;
  /** Прокси для Telegram Desktop: работает, пока KVT подключён, в любом режиме. */
  telegram: boolean;
  /** Путь прокси в «Гибриде»: сначала через VPN или всегда мимо него. */
  telegramRoute: TelegramRoute;
}

export type TelegramRoute = "vpn_first" | "direct";

export const defaultZapret = (): ZapretChoice => ({
  strategy: null,
  gameFilter: "off",
  tcpTimestamps: true,
  byNetwork: {},
  ipset: false,
  autoCheck: true,
  autoPick: true,
  telegram: true,
  telegramRoute: "direct",
});

/** Стратегия для сети: подобранная для неё, иначе выбранная, иначе основная. */
export function strategyFor(
  z: ZapretChoice,
  networkKey: string | null,
): string {
  return (
    (networkKey ? z.byNetwork[networkKey] : undefined) ??
    z.strategy ??
    "general"
  );
}

/** «general (ALT4)» → «ALT4», «general» → «Основная». */
export function strategyTitle(id: string): string {
  const m = /^general \((.+)\)$/.exec(id);
  return m ? m[1]! : id === "general" ? t("Основная", "Main") : id;
}

export interface ZapretConflict {
  /** Служба Windows (иначе процесс). */
  service: boolean;
  name: string;
}

export interface ZapretPick {
  best: string | null;
  bestTitle: string | null;
  score: number;
  max: number;
  /** Сколько проверок проходит без zapret. */
  baseline: number;
  tested: number;
  cancelled: boolean;
  /** Все проверенные стратегии с результатом. */
  tried: { id: string; title: string; passed: number }[];
}

export interface ZapretProgress {
  /** 0 — проверка без zapret, дальше — номер стратегии. */
  index: number;
  total: number;
  title: string;
  score: number | null;
  max: number;
}

const previewStrategies: ZapretStrategy[] = [
  "general",
  "general (ALT)",
  "general (ALT2)",
  "general (ALT4)",
  "general (FAKE TLS AUTO)",
  "general (SIMPLE FAKE)",
  "general (ALT5)",
].map((id, i) => ({
  id,
  title: strategyTitle(id),
  recommended: i !== 6,
  needsTimestamps: i === 2,
}));

export async function zapretStrategies(): Promise<ZapretStrategy[]> {
  if (!inTauri) return previewStrategies;
  return invoke<ZapretStrategy[]>("zapret_strategies");
}

export async function zapretConflicts(): Promise<ZapretConflict[]> {
  if (!inTauri) return demo ? [] : [{ service: true, name: "GoodbyeDPI" }];
  return invoke<ZapretConflict[]>("zapret_conflicts");
}

export async function zapretStopConflicts(): Promise<ZapretConflict[]> {
  if (!inTauri) return [];
  return invoke<ZapretConflict[]>("zapret_stop_conflicts");
}

let previewCancel = false;

export async function zapretAutoselect(
  onProgress: (p: ZapretProgress) => void,
): Promise<ZapretPick> {
  if (!inTauri) {
    previewCancel = false;
    const total = previewStrategies.length;
    onProgress({ index: 0, total, title: t("Без zapret", "Without zapret"), score: null, max: 13 });
    await new Promise((r) => setTimeout(r, 500));
    onProgress({ index: 0, total, title: t("Без zapret", "Without zapret"), score: 4, max: 13 });
    const tried: ZapretPick["tried"] = [];
    for (const [i, s] of previewStrategies.slice(0, 4).entries()) {
      if (previewCancel) {
        return {
          best: null,
          bestTitle: null,
          score: 4,
          max: 13,
          baseline: 4,
          tested: i,
          cancelled: true,
          tried,
        };
      }
      onProgress({ index: i + 1, total, title: s.title, score: null, max: 13 });
      await new Promise((r) => setTimeout(r, 700));
      const passed = i === 3 ? 13 : 6 + i;
      tried.push({ id: s.id, title: s.title, passed });
      onProgress({
        index: i + 1,
        total,
        title: s.title,
        score: passed,
        max: 13,
      });
    }
    return {
      best: "general (ALT4)",
      bestTitle: "ALT4",
      score: 13,
      max: 13,
      baseline: 4,
      tested: 4,
      cancelled: false,
      tried,
    };
  }
  const off = await listen<ZapretProgress>("zapret-progress", (e) =>
    onProgress(e.payload),
  );
  try {
    return await invoke<ZapretPick>("zapret_autoselect");
  } finally {
    off();
  }
}

export async function zapretAutoselectCancel(): Promise<void> {
  if (!inTauri) {
    previewCancel = true;
    return;
  }
  await invoke("zapret_autoselect_cancel");
}

export interface ZapretInfo {
  /** Версия комплекта, который сейчас используется. */
  version: string;
  /** Версия, с которой поставляется KVT. */
  bundledVersion: string;
  /** Комплект обновлён кнопкой «Обновить». */
  updated: boolean;
  /** Файлы целы, хэши программ сходятся. */
  ok: boolean;
  problem: string | null;
  strategies: number;
  /** Стратегии, не прошедшие белый список флагов. */
  rejected: string[];
  driver: "missing" | "stopped" | "running";
}

export interface FlowsealRelease {
  version: string;
  zipUrl: string;
  sha256: string;
}

export interface MaintenanceReport {
  version: string;
  changed: boolean;
  binariesUpdated: boolean;
  steps: string[];
}

export interface TargetCheck {
  name: string;
  /** Задержка по TLS 1.3 и TLS 1.2; null — не открылось. */
  tls13: number | null;
  tls12: number | null;
}

export interface ZapretCheck {
  targets: TargetCheck[];
  /** Загрузка больше 32 КБ прошла без обрыва. */
  download: boolean;
  passed: number;
  max: number;
  latencyMs: number;
}

export interface CheckRecord {
  /** Unix-время. */
  at: number;
  /** Стратегия во время проверки; null — zapret не работал. */
  strategy: string | null;
  check: ZapretCheck;
}

export type ZapretFix =
  "repair" | "stop_conflicts" | "autoselect" | "allow_timestamps" | "enable";

export interface ZapretDiagnosis {
  tone: "ok" | "warning" | "error";
  title: string;
  detail: string;
  steps: DiagnosisStep[];
  fix: ZapretFix | null;
  check: ZapretCheck | null;
}

export type ZapretAutoEvent =
  | { kind: "picked"; title: string; passed: number; max: number }
  | { kind: "unhealthy"; passed: number; max: number };

const previewCheck = (passed: number): ZapretCheck => ({
  targets: [
    ["Discord", 480, 530],
    [t("Discord: подключение", "Discord: gateway"), 570, null],
    [t("Discord: файлы", "Discord: files"), 470, 520],
    ["YouTube", 390, 410],
    [t("YouTube: картинки", "YouTube: images"), 320, 370],
    [t("YouTube: видео", "YouTube: video"), 300, 360],
  ].map(([name, a, b]) => ({
    name: name as string,
    tls13: a as number | null,
    tls12: b as number | null,
  })),
  download: true,
  passed,
  max: 13,
  latencyMs: 4700,
});

// ── Прокси для Telegram Desktop ──

export interface TgProxyStatus {
  /** Прокси сейчас работает. */
  running: boolean;
  /** Почему не запустился, если пытались. */
  error: string | null;
  port: number;
}

export async function tgProxyStatus(): Promise<TgProxyStatus> {
  if (!inTauri) return { running: true, error: null, port: 1443 };
  return invoke<TgProxyStatus>("tg_proxy_status");
}

/** Открывает в Telegram Desktop окно «Подключить прокси». */
export async function tgProxyOpen(): Promise<void> {
  if (!inTauri) return;
  await invoke("tg_proxy_open");
}

/** Ссылка `tg://proxy` для ручного подключения. */
export async function tgProxyLink(): Promise<string> {
  if (!inTauri)
    return "tg://proxy?server=127.0.0.1&port=1443&secret=dd00000000000000000000000000000000";
  return invoke<string>("tg_proxy_link");
}

export async function zapretInfo(): Promise<ZapretInfo> {
  if (!inTauri) {
    return {
      version: "1.10.4",
      bundledVersion: "1.10.4",
      updated: false,
      ok: true,
      problem: null,
      strategies: 22,
      rejected: [],
      driver: "stopped",
    };
  }
  return invoke<ZapretInfo>("zapret_info");
}

export async function zapretLatest(force = false): Promise<FlowsealRelease> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 400));
    return { version: "1.10.5", zipUrl: "", sha256: "" };
  }
  return invoke<FlowsealRelease>("zapret_latest", { force });
}

export async function zapretUpdate(): Promise<MaintenanceReport> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 1200));
    return {
      version: "1.10.5",
      changed: true,
      binariesUpdated: true,
      steps: [
        t("Скачан релиз 1.10.5 (SHA-256 сверен с GitHub)", "Downloaded release 1.10.5 (SHA-256 checked against GitHub)"),
        t("Стратегий: 22", "Strategies: 22"),
        t("winws и WinDivert — проверенные версии", "winws and WinDivert are verified versions"),
      ],
    };
  }
  return invoke<MaintenanceReport>("zapret_update");
}

export async function zapretRepair(): Promise<MaintenanceReport> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 1200));
    return {
      version: "1.10.4",
      changed: true,
      binariesUpdated: false,
      steps: [
        t("Рабочие списки сброшены — создадутся при запуске", "Working lists reset — they'll be recreated on start"),
        t("Файлы комплекта целы (Flowseal 1.10.4)", "Bundle files are intact (Flowseal 1.10.4)"),
        t("Драйвер WinDivert удалён — установится заново при запуске", "WinDivert driver removed — it'll be reinstalled on start"),
      ],
    };
  }
  return invoke<MaintenanceReport>("zapret_repair");
}

export async function zapretCheck(): Promise<CheckRecord> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 1200));
    return {
      at: Math.floor(Date.now() / 1000),
      strategy: "general (ALT4)",
      check: previewCheck(12),
    };
  }
  return invoke<CheckRecord>("zapret_check");
}

export async function zapretLast(): Promise<CheckRecord | null> {
  if (!inTauri) return null;
  return invoke<CheckRecord | null>("zapret_last");
}

export async function zapretDiagnose(): Promise<ZapretDiagnosis> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 1500));
    return {
      tone: "error",
      title: t("Стратегия не помогает в этой сети", "The strategy doesn't help on this network"),
      detail:
        t("С «ALT4» открывается 5 из 13 проверок. Провайдеры блокируют по-разному — подберите стратегию. Если не поможет ни одна, переустановите zapret.", "With “ALT4”, 5 of 13 checks open. ISPs block in different ways — pick a strategy. If none helps, reinstall zapret."),
      steps: [
        { title: t("Служба KVT", "KVT service"), state: "ok", detail: t("Работает", "Working") },
        {
          title: t("Файлы zapret", "zapret files"),
          state: "ok",
          detail: t("Flowseal 1.10.4, стратегий: 22", "Flowseal 1.10.4, strategies: 22"),
        },
        { title: t("Другие обходы", "Other bypasses"), state: "ok", detail: t("Не найдены", "None found") },
        { title: "zapret", state: "ok", detail: t("Работает, стратегия «ALT4»", "Working, strategy “ALT4”") },
        {
          title: t("Мешающая программа", "Interfering app"),
          state: "warning",
          detail:
            t("AdGuard — мешает Discord; добавьте Discord в исключения AdGuard", "AdGuard — interferes with Discord; add Discord to AdGuard's exclusions"),
        },
        {
          title: t("Discord и YouTube", "Discord and YouTube"),
          state: "fail",
          detail: t("Открывается 5 из 13 проверок", "5 of 13 checks open"),
        },
      ],
      fix: "autoselect",
      check: previewCheck(5),
    };
  }
  return invoke<ZapretDiagnosis>("zapret_diagnose");
}

export function onZapretCheck(
  handler: (record: CheckRecord) => void,
): () => void {
  if (!inTauri) return () => {};
  const off = listen<CheckRecord>("zapret-check", (e) => handler(e.payload));
  return () => void off.then((f) => f());
}

export function onZapretAuto(
  handler: (event: ZapretAutoEvent) => void,
): () => void {
  if (!inTauri) return () => {};
  const off = listen<ZapretAutoEvent>("zapret-auto", (e) => handler(e.payload));
  return () => void off.then((f) => f());
}

// ── Журнал сетевых запросов ──

export type NetPurpose =
  | "subscription"
  | "server_ping"
  | "server_check"
  | "tunnel"
  | "dns"
  | "zapret"
  | "rules"
  | "update"
  | "captive";

export interface NetEvent {
  /** Unix-время в миллисекундах. */
  at: number;
  origin: "app" | "service";
  purpose: NetPurpose;
  /** Только хост: путь и параметры ссылок в журнал не попадают. */
  host: string;
  route: "direct" | "tunnel" | "test_core";
  outcome: "ok" | "failed" | "deferred" | "frozen";
  ms: number | null;
  detail: string;
}

export interface HostSummary {
  host: string;
  opened: number;
  failed: number;
  /** Сколько раз NetGovernor остановил запрос. */
  held: number;
  /** Наибольшее число соединений за минуту. */
  peakPerMinute: number;
  last: number;
}

export interface NetJournal {
  /** От новых к старым. */
  events: NetEvent[];
  /** Сводка за последний час. */
  hosts: HostSummary[];
  /** Служба ответила; иначе в журнале только запросы приложения. */
  service: boolean;
}

function previewJournal(): NetJournal {
  const now = Date.now();
  const ev = (ago: number, e: Omit<NetEvent, "at">): NetEvent => ({
    at: now - ago * 1000,
    ...e,
  });
  const events: NetEvent[] = [
    ev(4, {
      origin: "app",
      purpose: "tunnel",
      host: "www.cloudflare.com",
      route: "tunnel",
      outcome: "ok",
      ms: 182,
      detail: "",
    }),
    ev(64, {
      origin: "app",
      purpose: "tunnel",
      host: "www.cloudflare.com",
      route: "tunnel",
      outcome: "ok",
      ms: 175,
      detail: "",
    }),
    ev(95, {
      origin: "app",
      purpose: "server_check",
      host: "www.microsoft.com",
      route: "test_core",
      outcome: "deferred",
      ms: null,
      detail: t("повтор через 58 с", "retry in 58 s"),
    }),
    ev(97, {
      origin: "app",
      purpose: "server_check",
      host: "www.microsoft.com",
      route: "test_core",
      outcome: "ok",
      ms: 412,
      detail: t("Работает", "Working"),
    }),
    ev(99, {
      origin: "app",
      purpose: "server_check",
      host: "cdn.example.net",
      route: "test_core",
      outcome: "failed",
      ms: 5000,
      detail:
        t("Провайдер притормозил соединение — подождите или выберите другой сервер", "Your ISP stalled the connection — wait or pick another server"),
    }),
    ev(120, {
      origin: "app",
      purpose: "server_ping",
      host: "nl1.example.net:443",
      route: "direct",
      outcome: "ok",
      ms: 48,
      detail: "",
    }),
    ev(120, {
      origin: "app",
      purpose: "server_ping",
      host: "de1.example.net:443",
      route: "direct",
      outcome: "failed",
      ms: null,
      detail: t("TCP не открылся", "TCP didn't open"),
    }),
    ev(300, {
      origin: "service",
      purpose: "rules",
      host: "raw.githubusercontent.com",
      route: "direct",
      outcome: "ok",
      ms: 640,
      detail: "",
    }),
    ev(302, {
      origin: "service",
      purpose: "rules",
      host: "github.com",
      route: "direct",
      outcome: "ok",
      ms: 910,
      detail: "",
    }),
    ev(900, {
      origin: "app",
      purpose: "subscription",
      host: "sub.example.com",
      route: "direct",
      outcome: "ok",
      ms: 730,
      detail: "",
    }),
    ev(1800, {
      origin: "app",
      purpose: "dns",
      host: "1.1.1.1:53",
      route: "direct",
      outcome: "ok",
      ms: 21,
      detail: "UDP",
    }),
    ev(1800, {
      origin: "app",
      purpose: "dns",
      host: "cloudflare-dns.com",
      route: "direct",
      outcome: "ok",
      ms: 160,
      detail: "DoH",
    }),
    ev(2400, {
      origin: "app",
      purpose: "update",
      host: "api.github.com",
      route: "direct",
      outcome: "ok",
      ms: 380,
      detail: t("версия Flowseal", "Flowseal version"),
    }),
  ];
  const by = new Map<string, HostSummary>();
  for (const e of events) {
    const s = by.get(e.host) ?? {
      host: e.host,
      opened: 0,
      failed: 0,
      held: 0,
      peakPerMinute: 0,
      last: 0,
    };
    if (e.outcome === "ok" || e.outcome === "failed") s.opened += 1;
    else s.held += 1;
    if (e.outcome === "failed") s.failed += 1;
    s.peakPerMinute = Math.max(s.peakPerMinute, Math.min(s.opened, 2));
    s.last = Math.max(s.last, e.at);
    by.set(e.host, s);
  }
  return {
    events,
    hosts: [...by.values()].sort((a, b) => b.opened - a.opened),
    service: true,
  };
}

export async function netLog(): Promise<NetJournal> {
  if (!inTauri) return previewJournal();
  return invoke<NetJournal>("net_log");
}

export async function netLogClear(): Promise<void> {
  if (inTauri) await invoke("net_log_clear");
}

// ── Аудит ПК ──

export type ServiceFix =
  | { action: "reset_win_http_proxy" }
  | { action: "disable_teredo" }
  | { action: "disable_zapret_service"; name: string }
  | { action: "disable_autostart"; id: string };

export type AuditFix =
  | { kind: "disable_system_proxy" }
  | { kind: "close_process"; pid: number; name: string }
  | { kind: "stop_zapret" }
  | ({ kind: "service" } & ServiceFix)
  | { kind: "disable_user_autostart"; id: string };

export interface AuditFinding {
  group: "leaks" | "conflicts" | "zapret";
  level: "ok" | "info" | "warning";
  title: string;
  detail: string;
  fix: AuditFix | null;
}

export interface AuditReport {
  findings: AuditFinding[];
  ms: number;
}

let previewProxyOn = true;

export async function pcAudit(): Promise<AuditReport> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 1500));
    const findings: AuditFinding[] = [
      previewProxyOn
        ? {
            group: "leaks",
            level: "warning",
            title: t("Включён системный прокси", "System proxy is on"),
            detail:
              t("Браузеры и другие программы отправляют трафик на 127.0.0.1:10808 — обычно это остаток другого VPN-клиента. Если та программа закрыта, сайты не открываются; если запущена — трафик идёт через неё, а не через KVT.", "Browsers and other apps send traffic to 127.0.0.1:10808 — usually a leftover from another VPN client. If that app is closed, sites won't open; if it's running, traffic goes through it instead of KVT."),
            fix: { kind: "disable_system_proxy" },
          }
        : {
            group: "leaks",
            level: "ok",
            title: t("Системный прокси", "System proxy"),
            detail:
              t("Не задан: программы выходят в сеть обычным путём, через туннель KVT.", "Not set: apps reach the internet the normal way, through the KVT tunnel."),
            fix: null,
          },
      {
        group: "leaks",
        level: "ok",
        title: t("Прокси WinHTTP", "WinHTTP proxy"),
        detail: t("Не задан.", "Not set."),
        fix: null,
      },
      {
        group: "leaks",
        level: "ok",
        title: "Teredo",
        detail: t("Выключен или не используется.", "Off or not in use."),
        fix: null,
      },
      {
        group: "leaks",
        level: "info",
        title: t("Браузер использует свой DNS", "A browser uses its own DNS"),
        detail:
          t("Microsoft Edge (chrome.cloudflare-dns.com): защищённый DNS включён в настройках браузера. Запросы зашифрованы, но идут мимо DNS KVT — если сайты из списков маршрутизации открываются не так, выключите «Безопасный DNS» в настройках браузера.", "Microsoft Edge (chrome.cloudflare-dns.com): secure DNS is on in the browser settings. Queries are encrypted but bypass KVT's DNS — if sites from the routing lists open the wrong way, turn off “Secure DNS” in the browser settings."),
        fix: null,
      },
      {
        group: "conflicts",
        level: "warning",
        title: t("Запущен v2rayN", "v2rayN is running"),
        detail:
          t("Два VPN одновременно спорят за маршруты и DNS: часть трафика уходит не туда, подключение обрывается. Закройте другой клиент, пока работает KVT.", "Two VPNs at once fight over routes and DNS: some traffic goes the wrong way and the connection drops. Close the other client while KVT is running."),
        fix: { kind: "close_process", pid: 4242, name: "v2rayN" },
      },
      {
        group: "conflicts",
        level: "ok",
        title: t("Туннели других VPN", "Other VPN tunnels"),
        detail: t("Активных нет.", "None active."),
        fix: null,
      },
      {
        group: "conflicts",
        level: "info",
        title: t("Антивирус проверяет HTTPS", "Antivirus scans HTTPS"),
        detail:
          t("Kaspersky Plus может перехватывать защищённые соединения. Если подписки не загружаются или проверка серверов ошибается, добавьте папку KVT в исключения или выключите «Проверку защищённых соединений».", "Kaspersky Plus may intercept secure connections. If subscriptions don't load or server checks go wrong, add the KVT folder to exclusions or turn off encrypted connection scanning."),
        fix: null,
      },
      {
        group: "zapret",
        level: "warning",
        title: t("Служба zapret запускается вместе с Windows", "Service zapret starts with Windows"),
        detail:
          t("zapret стартует при каждом включении компьютера и мешает zapret в KVT. Исправление остановит её и переведёт в ручной запуск — ничего не удаляется.", "zapret starts every time the computer turns on and interferes with zapret in KVT. The fix stops it and sets it to manual start — nothing is deleted."),
        fix: {
          kind: "service",
          action: "disable_zapret_service",
          name: "zapret",
        },
      },
    ];
    return { findings, ms: 1500 };
  }
  return invoke<AuditReport>("pc_audit");
}

export async function pcAuditFix(fix: AuditFix): Promise<void> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 600));
    if (fix.kind === "disable_system_proxy") {
      previewProxyOn = false;
      return;
    }
    throw new Error(t("Служба KVT не запущена — это исправление выполняет она", "The KVT service isn't running — it performs this fix"));
  }
  await invoke("pc_audit_fix", { fix });
}

// ── Перенос из других клиентов ──

export interface MigrationPreview {
  client: "v2rayn" | "throne" | "nekoray" | "hiddify" | "happ";
  title: string;
  /** Папка с данными клиента — она же идентификатор при переносе. */
  location: string;
  /** Только название и адрес сервера подписки: сама ссылка остаётся в Rust. */
  subscriptions: { name: string; host: string }[];
  servers: { name: string; protocol: string }[];
  skipped: { reason: string; count: number }[];
  note: string | null;
}

export interface MigrationReport {
  loaded: number;
  pending: number;
  existing: number;
  servers: number;
}

const previewMigration: MigrationPreview[] = [
  {
    client: "v2rayn",
    title: "v2rayN",
    location: String.raw`C:\Users\user\Downloads\v2rayN-windows-64`,
    subscriptions: [
      { name: "Мой провайдер", host: "sub.example.com" },
      { name: "Резерв", host: "panel.example.net" },
    ],
    servers: [
      { name: "Домашний сервер", protocol: "VLESS" },
      { name: "SS для игр", protocol: "Shadowsocks" },
    ],
    skipped: [{ reason: t("VMess не поддерживается", "VMess is not supported"), count: 3 }],
    note: null,
  },
  {
    client: "happ",
    title: "Happ",
    location: String.raw`C:\Users\user\AppData\Local\Happ`,
    subscriptions: [],
    servers: [],
    skipped: [],
    note: t("Happ хранит подписки в зашифрованном виде — KVT их не читает. Скопируйте в Happ ссылку на подписку и добавьте её в KVT кнопкой «+».", "Happ stores subscriptions encrypted — KVT can't read them. Copy the subscription link in Happ and add it to KVT with the “+” button."),
  },
];

export async function migrateScan(): Promise<MigrationPreview[]> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 1200));
    return previewMigration;
  }
  return invoke<MigrationPreview[]>("migrate_scan");
}

/** `null` — пользователь закрыл окно выбора папки. */
export async function migratePickFolder(): Promise<MigrationPreview[] | null> {
  if (!inTauri)
    throw new Error(t("Выбор папки работает в приложении (npm run tauri dev).", "Choosing a folder works in the app (npm run tauri dev)."));
  return invoke<MigrationPreview[] | null>("migrate_pick_folder");
}

export async function migrateImport(
  locations: string[],
  servers: boolean,
): Promise<MigrationReport> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 1000));
    return { loaded: 1, pending: 1, existing: 0, servers: servers ? 2 : 0 };
  }
  return invoke<MigrationReport>("migrate_import", {
    request: { locations, servers },
  });
}

// ── Этап 5.4: надёжность ──

/** Сообщения, появившиеся до открытия окна (например, о повреждённых настройках). */
export async function takeNotices(): Promise<string[]> {
  if (!inTauri) return [];
  return invoke<string[]>("take_notices");
}

/** Трей добавил сообщение для окна (ошибка действия, а уведомления выключены). */
export function onNotices(handler: () => void): () => void {
  if (!inTauri) return () => {};
  const off = listen("notices", handler);
  return () => void off.then((f) => f());
}

/** Страница, которую открывает трей: вкладка окна, «why» или «add». */
export type TrayPage = "home" | "zapret" | "journal" | "why" | "add";

/** Страница, которую трей попросил открыть до появления окна. */
export async function takePage(): Promise<TrayPage | null> {
  if (!inTauri) return null;
  return invoke<TrayPage | null>("take_page");
}

export function onNavigate(handler: (page: TrayPage) => void): () => void {
  if (!inTauri) return () => {};
  const off = listen<TrayPage>("navigate", (e) => handler(e.payload));
  return () => void off.then((f) => f());
}

export interface LangInfo {
  choice: LangChoice;
  /** Действующий язык (для «Как в Windows» — язык системы). */
  lang: Lang;
}

const PREVIEW_LANG = "kvt.lang";

function previewLang(): LangInfo {
  let choice: LangChoice = "auto";
  try {
    const c = localStorage.getItem(PREVIEW_LANG);
    if (c === "ru" || c === "en") choice = c;
  } catch {
    // Хранилище недоступно — язык браузера.
  }
  return { choice, lang: choice === "auto" ? browserLang() : choice };
}

/** Язык интерфейса: выбор и действующий язык. */
export async function getLanguage(): Promise<LangInfo> {
  if (!inTauri) return previewLang();
  return invoke<LangInfo>("get_language");
}

/** Сменить язык (трей и уведомления — сразу, окно перезагружается). */
export async function setLanguage(choice: LangChoice): Promise<LangInfo> {
  if (!inTauri) {
    try {
      if (choice === "auto") localStorage.removeItem(PREVIEW_LANG);
      else localStorage.setItem(PREVIEW_LANG, choice);
    } catch {
      // Превью: язык продержится до перезагрузки.
    }
    return previewLang();
  }
  return invoke<LangInfo>("set_language", { choice });
}

/** Служба отвечает, но другой версии (прерванное обновление) — нужна переустановка. */
export async function serviceMismatch(): Promise<boolean> {
  if (!inTauri) return false;
  return invoke<boolean>("service_mismatch");
}

/** Запускает службу KVT (право на запуск выдаёт установщик) и ждёт её ответа. */
export async function startService(): Promise<void> {
  if (inTauri) await invoke("start_service");
}

export interface About {
  version: string;
  /** xray, sing-box, wintun → версия. */
  cores: Record<string, string>;
  sourceUrl: string;
  /** Есть папка с текстами лицензий (в установленном KVT). */
  licenses: boolean;
}

export async function aboutInfo(): Promise<About> {
  if (!inTauri) {
    return {
      version: "0.9.4",
      cores: { xray: "26.10.31", "sing-box": "1.14.4", wintun: "0.14.1" },
      sourceUrl: "https://github.com/kostiashkaaa/KVT-client",
      licenses: true,
    };
  }
  return invoke<About>("about_info");
}

/** Открывает исходники, страницу загрузки или папку лицензий — только их. */
export async function openLink(
  target: "source" | "releases" | "latest" | "licenses",
): Promise<void> {
  if (inTauri) await invoke("open_link", { target });
}

export interface UpdateStatus {
  current: string;
  /** Последняя версия на GitHub; null — ещё не проверяли или не удалось. */
  latest: string | null;
  /** Она новее установленной. */
  available: boolean;
  /** Когда проверяли (Unix-время, мс). */
  checkedAt: number | null;
  error: string | null;
}

/** Что известно о новой версии — без запроса в сеть. */
export async function updateStatus(): Promise<UpdateStatus> {
  // В предпросмотре — как будто вышла новая версия: видно плашку и точку у «Настроек».
  if (!inTauri)
    return {
      current: "0.9.4",
      latest: demo ? "0.9.4" : "0.9.5",
      available: !demo,
      checkedAt: Date.now(),
      error: null,
    };
  return invoke<UpdateStatus>("update_status");
}

/** Спросить у GitHub сейчас (не чаще раза в минуту). */
export async function updateCheck(): Promise<UpdateStatus> {
  if (!inTauri)
    return {
      current: "0.9.4",
      latest: "0.9.5",
      available: true,
      checkedAt: Date.now(),
      error: null,
    };
  return invoke<UpdateStatus>("update_check");
}

/** Фоновая проверка нашла новую версию. */
export function onUpdateAvailable(handler: () => void): () => void {
  if (!inTauri) return () => {};
  const off = listen("update-available", handler);
  return () => void off.then((f) => f());
}

/** Автозапуск с Windows свёрнутым в трей (значение в реестре, не в настройках).
 *  blocked — запись наша, но её выключили в «Диспетчере задач» или «Параметрах»;
 *  other — в автозагрузке другой kvt.exe. */
export type AutostartState = "on" | "off" | "blocked" | "other";

export async function autostartState(): Promise<AutostartState> {
  if (!inTauri) return "on";
  return invoke<AutostartState>("autostart_state");
}

export async function setAutostart(enabled: boolean): Promise<void> {
  if (inTauri) await invoke("set_autostart", { enabled });
}

/** Идут ли данные через туннель: null — не проверяли или VPN выключен. */
export async function tunnelState(): Promise<boolean | null> {
  if (!inTauri) return demo && demoState.state === "connected" ? true : null;
  return invoke<boolean | null>("tunnel_state");
}

export function onTunnelState(
  handler: (ok: boolean | null) => void,
): () => void {
  if (!inTauri) return () => {};
  const off = listen<boolean | null>("tunnel-state", (e) => handler(e.payload));
  return () => void off.then((f) => f());
}

export interface DiagFile {
  name: string;
  text: string;
}

/** Что войдёт в архив диагностики (уже без ключей, ссылок подписок и адресов серверов). */
export async function diagPreview(): Promise<DiagFile[]> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 600));
    return [
      {
        name: "README.txt",
        text: [
          "Диагностика KVT 0.1.0",
          "Ключи, пароли, UUID, ссылки подписок и адреса серверов скрыты.",
        ].join("\n"),
      },
      {
        name: "status.json",
        text: JSON.stringify(
          { service: { state: "connected", core: "xray" }, tunnelOk: true },
          null,
          2,
        ),
      },
      {
        name: "kvt.log",
        text: [
          '2026-11-05T10:00:00Z  INFO KVT запущен version="0.1.0"',
          "2026-11-05T10:00:05Z  WARN подписка не обновилась error=нет ответа",
        ].join("\n"),
      },
      {
        name: "service.log",
        text: "2026-11-05T10:00:01Z  INFO подключено core=Xray kill_switch=true",
      },
      { name: "core.log", text: "" },
    ];
  }
  return invoke<DiagFile[]>("diag_preview");
}

/** Сохраняет показанное в предпросмотре. false — пользователь закрыл окно выбора файла. */
export async function diagSave(): Promise<boolean> {
  if (!inTauri)
    throw new Error(t("Сохранение работает в приложении (npm run tauri dev).", "Saving works in the app (npm run tauri dev)."));
  return invoke<boolean>("diag_save");
}
