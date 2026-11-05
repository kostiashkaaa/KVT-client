// Мост к Rust-части приложения. В WebView попадают только данные для отображения:
// пароли, UUID и ссылки подписок остаются в Rust.

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";


export interface ServerSummary {
  /** Постоянный ключ сервера: выбор и проверки привязаны к нему, а не к номеру. */
  key: string;
  /** Название без флага-эмодзи. */
  name: string;
  /** Код страны из флага в названии (`nl`). */
  flag: string | null;
  address: string;
  port: number;
  protocol: string;
  transport: string;
  security: string;
  sni: string | null;
  core: "xray" | "sing-box";
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
  group: string;
  /** Первый сервер новой подписки — его сразу выбираем. */
  first: string | null;
  servers: number;
}

export type Mode = "vpn" | "hybrid" | "zapret";

const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
/** Окно работает в приложении, а не в превью браузера (`npm run dev`). */
export const inApp = inTauri;

/** Одна https-ссылка — это адрес подписки; всё остальное — содержимое (ссылки на серверы). */
export function isSubscriptionUrl(input: string): boolean {
  return /^https?:\/\/\S+$/i.test(input.trim());
}

export async function addSubscription(input: string): Promise<Added> {
  if (isSubscriptionUrl(input)) {
    if (!inTauri) throw new Error("Загрузка подписки по ссылке работает в приложении (npm run tauri dev).");
    return invoke<Added>("add_subscription_url", { url: input.trim() });
  }
  if (!inTauri) return previewAdd(input);
  return invoke<Added>("parse_subscription", { body: input });
}

export type QuickResult =
  | { kind: "reachable"; latency_ms: number }
  | { kind: "unreachable" }
  | { kind: "dns_failed" }
  | { kind: "not_applicable" };

/** Быстрая проверка: TCP-пинг без TLS. `group` — одна подписка, `null` — все. Итог — по ключам серверов. */
export async function quickCheck(group: string | null): Promise<Record<string, QuickResult>> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 600));
    const out: Record<string, QuickResult> = {};
    previewGroups
      .filter((g) => group === null || g.id === group)
      .flatMap((g) => g.servers)
      .forEach((s, i) => {
        out[s.key] = i === 1 ? { kind: "unreachable" } : { kind: "reachable", latency_ms: 40 + i * 37 };
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
  | { state: "failed"; reason: string };

export type ListAction = "proxy" | "direct" | "block";

export interface RoutingSettings {
  /** compact — списки podkop (itdoginfo), full — реестр runetfreedom. */
  listMode: "compact" | "full";
  /** Куда идёт всё, что не попало в списки. */
  everythingElse: "proxy" | "direct";
  /** Выбор для отдельных списков: id → действие. */
  overrides: Record<string, ListAction>;
}

export const defaultRouting = (): RoutingSettings => ({
  listMode: "compact",
  everythingElse: "proxy",
  overrides: {},
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
  /** Подсказки первого запуска пройдены или пропущены. */
  onboarded: boolean;
}

export interface ListInfo {
  id: string;
  title: string;
  kind: "region" | "category" | "service";
}

export async function listCatalog(): Promise<ListInfo[]> {
  if (!inTauri) {
    return [
      { id: "russia_inside", title: "Заблокировано в России", kind: "region" },
      { id: "russia_outside", title: "Российские сайты, закрытые для зарубежа", kind: "region" },
      { id: "geoblock", title: "Сервисы, закрытые для России", kind: "category" },
      { id: "news", title: "Новости", kind: "category" },
      { id: "youtube", title: "YouTube", kind: "service" },
      { id: "discord", title: "Discord", kind: "service" },
      { id: "telegram", title: "Telegram", kind: "service" },
    ];
  }
  return invoke<ListInfo[]>("list_catalog");
}

/** Выбор сервера, режима и kill switch хранится в Rust — им пользуется и трей. */
export async function setChoice(choice: Choice): Promise<void> {
  if (inTauri) await invoke("set_choice", { choice });
}

/** Состояние для окна, открытого заново из трея. */
export async function snapshot(): Promise<{ groups: Group[]; choice: Choice | null }> {
  if (!inTauri) return { groups: withStressGroup(previewGroups), choice: null };
  return invoke("snapshot");
}

export async function connect(): Promise<ServiceStatus> {
  if (!inTauri) throw new Error("Подключение работает в приложении (npm run tauri dev) при запущенной службе.");
  return invoke<ServiceStatus>("connect");
}

export type CheckResult =
  | { verdict: "ok"; detail: string }
  | { verdict: "warning"; detail: string }
  | { verdict: "info"; detail: string };

export interface LeakReport {
  openProxies: { port: number; process: string | null; knownScanPort: boolean }[];
  ipv4Route: CheckResult;
  ipv6Route: CheckResult;
  dns: CheckResult;
}

export async function leakTest(connected: boolean): Promise<LeakReport> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 500));
    return {
      openProxies: [{ port: 10808, process: "example-vpn.exe", knownScanPort: false }],
      ipv4Route: { verdict: "info", detail: "VPN выключен: трафик идёт напрямую" },
      ipv6Route: { verdict: "ok", detail: "IPv6 в интернет недоступен — утечки через IPv6 быть не может" },
      dns: { verdict: "info", detail: "VPN выключен: DNS обслуживает провайдер" },
    };
  }
  return invoke<LeakReport>("leak_test", { connected });
}

export async function disconnect(): Promise<ServiceStatus> {
  if (!inTauri) return { state: "disconnected" };
  return invoke<ServiceStatus>("disconnect");
}

/** `null` — служба не запущена. */
export async function serviceStatus(): Promise<ServiceStatus | null> {
  if (!inTauri) return null;
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
  if (!inTauri) return { secs: 4325 + Math.floor((Date.now() - previewStart) / 1000), rx: 1_331_000_000, tx: 88_200_000 };
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
  const units = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
  let value = bytes;
  let unit = 0;
  while (value >= 1000 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  const digits = unit === 0 || value >= 100 ? 0 : value >= 10 ? 1 : 2;
  return `${value.toFixed(digits).replace(".", ",")} ${units[unit]}`;
}

// Предпросмотр интерфейса в обычном браузере (npm run dev) без Rust-части.
function previewServer(name: string, i: number, group: string): ServerSummary {
  const flags: Record<string, string> = { "🇳🇱": "nl", "🇩🇪": "de", "🇫🇮": "fi", "🇩🇰": "dk", "🇺🇸": "us" };
  const flag = Object.keys(flags).find((f) => name.startsWith(f));
  return {
    key: `${group}-${i}`,
    name: flag ? name.slice(flag.length).trim() : name,
    flag: flag ? flags[flag]! : null,
    address: "preview.example",
    port: 443,
    protocol: "vless",
    transport: i % 4 === 2 ? "xhttp" : "tcp",
    security: "reality",
    sni: "www.microsoft.com",
    core: "xray",
  };
}

/** Превью: `?servers=10000` добавляет большую подписку — проверить главную на длинных списках. */
function withStressGroup(groups: Group[]): Group[] {
  const n = Number(new URLSearchParams(location.search).get("servers") ?? 0);
  if (!n) return groups;
  const flags = ["🇳🇱", "🇩🇪", "🇫🇮", "🇩🇰", "🇺🇸"];
  const servers = Array.from({ length: n }, (_, i) => previewServer(`${flags[i % flags.length]} Сервер ${i + 1}`, i, "big"));
  return [...groups, { ...groups[0]!, id: "big", title: `Большая подписка (${n})`, servers }];
}

const previewGroups: Group[] = [
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
    title: "Добавлено вручную",
    byUrl: false,
    updatedAt: Math.floor(Date.now() / 1000) - 60,
    meta: { title: null, usedBytes: null, totalBytes: null, expire: null, supportUrl: null, announce: null },
    servers: [previewServer("🇩🇰 DK для wifi-familydk", 0, "b")],
    info: [],
    errors: 0,
  },
];

function previewAdd(body: string): Added {
  const lines = body.split(/\r?\n/).filter((l) => l.includes("://"));
  // Как в приложении: ручные ключи — в одной группе.
  let group = previewGroups.find((g) => !g.byUrl);
  if (!group) {
    group = {
      id: "manual",
      title: "Добавлено вручную",
      byUrl: false,
      updatedAt: 0,
      meta: { title: null, usedBytes: null, totalBytes: null, expire: null, supportUrl: null, announce: null },
      servers: [],
      info: [],
      errors: 0,
    };
    previewGroups.push(group);
  }
  const start = group.servers.length;
  const id = group.id;
  group.servers.push(
    ...lines.map((l, i) => previewServer(decodeURIComponent(l.split("#")[1] ?? `Сервер ${i + 1}`), start + i, id)),
  );
  group.updatedAt = Math.floor(Date.now() / 1000);
  return { group: id, first: lines.length > 0 ? `${id}-${start}` : null, servers: lines.length };
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
}

export async function listSubscriptions(): Promise<SubscriptionItem[]> {
  if (!inTauri) {
    return previewGroups.map((g) => ({
      id: g.id,
      title: g.title,
      byUrl: g.byUrl,
      servers: g.servers.length,
      usedBytes: g.meta.usedBytes,
      totalBytes: g.meta.totalBytes,
      expire: g.meta.expire,
      updatedAt: g.updatedAt,
    }));
  }
  return invoke<SubscriptionItem[]>("list_subscriptions");
}

export async function removeSubscription(id: string): Promise<void> {
  if (!inTauri) {
    const i = previewGroups.findIndex((g) => g.id === id);
    if (i >= 0) previewGroups.splice(i, 1);
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
    const keys = previewGroups.filter((g) => group === null || g.id === group).flatMap((g) => g.servers.map((s) => s.key));
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
  const off = await listen<{ key: string; outcome: Outcome }>("probe-result", (e) =>
    onResult(e.payload.key, e.payload.outcome),
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

export const defaultDns = (): DnsChoice => ({ local: "yandex", remote: "cloudflare" });

const previewResolvers: Resolver[] = [
  { id: "yandex", title: "Яндекс", udp: "77.88.8.8", tunnel: false },
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
        udp: i === 2 ? { state: "intercepted", ms: 12, by: "212.48.193.5" } : works(20 + i * 9),
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
      title: "Провайдер перехватывает DNS-запросы",
      detail:
        "На запросы к публичным DNS по UDP отвечает сервер провайдера (212.48.193.5). При подключении через KVT это не мешает: DNS шифруется (DoH) и идёт внутри туннеля.",
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
    return {
      tone: "error",
      title: "Провайдер блокирует этот сервер",
      detail: "Соединение обрывается после первых килобайт — режет DPI. Можно переключиться на «DE Frankfurt».",
      steps: [
        { title: "Сеть", state: "ok", detail: "Подключение к сети есть" },
        { title: "Служба KVT", state: "ok", detail: "Служба работает" },
        { title: "Подписка", state: "ok", detail: "Подписка действует" },
        { title: "Интернет без VPN", state: "ok", detail: "Интернет работает" },
        { title: "Сервер", state: "ok", detail: "«NL Amsterdam» отвечает, 48 мс" },
        { title: "Проверка сервера", state: "fail", detail: "Соединение обрывается после первых килобайт — режет DPI" },
      ],
      fix: { kind: "switch_server", key: "a-1", name: "Германия ⚡" },
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
  if (!inTauri) return { network: { key: "preview", label: "Home 5G", kind: "wifi" }, profile: null };
  return invoke<NetworkView>("current_network");
}

export function onNetworkChanged(handler: (view: NetworkView) => void): () => void {
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
  | { kind: "server_removed"; server: string };

export function onWatchdog(handler: (event: WatchdogEvent) => void): () => void {
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
  /** Свои домены для zapret и домены, которые он не трогает. */
  userDomains: string[];
  excludeDomains: string[];
  /** Обход по IP-списку Flowseal, а не только по доменам. */
  ipset: boolean;
  /** Проверять работу раз в полчаса и после смены сети. */
  autoCheck: boolean;
  /** Если стратегия перестала работать — подобрать новую (режим «Zapret»). */
  autoPick: boolean;
}

export const defaultZapret = (): ZapretChoice => ({
  strategy: null,
  gameFilter: "off",
  tcpTimestamps: true,
  byNetwork: {},
  userDomains: [],
  excludeDomains: [],
  ipset: false,
  autoCheck: true,
  autoPick: true,
});

/** Стратегия для сети: подобранная для неё, иначе выбранная, иначе основная. */
export function strategyFor(z: ZapretChoice, networkKey: string | null): string {
  return (networkKey ? z.byNetwork[networkKey] : undefined) ?? z.strategy ?? "general";
}

/** «general (ALT4)» → «ALT4», «general» → «Основная». */
export function strategyTitle(id: string): string {
  const m = /^general \((.+)\)$/.exec(id);
  return m ? m[1]! : id === "general" ? "Основная" : id;
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
].map((id, i) => ({ id, title: strategyTitle(id), recommended: i !== 6, needsTimestamps: i === 2 }));

export async function zapretStrategies(): Promise<ZapretStrategy[]> {
  if (!inTauri) return previewStrategies;
  return invoke<ZapretStrategy[]>("zapret_strategies");
}

export async function zapretConflicts(): Promise<ZapretConflict[]> {
  if (!inTauri) return [{ service: true, name: "GoodbyeDPI" }];
  return invoke<ZapretConflict[]>("zapret_conflicts");
}

export async function zapretStopConflicts(): Promise<ZapretConflict[]> {
  if (!inTauri) return [];
  return invoke<ZapretConflict[]>("zapret_stop_conflicts");
}

let previewCancel = false;

export async function zapretAutoselect(onProgress: (p: ZapretProgress) => void): Promise<ZapretPick> {
  if (!inTauri) {
    previewCancel = false;
    const total = previewStrategies.length;
    onProgress({ index: 0, total, title: "Без zapret", score: null, max: 13 });
    await new Promise((r) => setTimeout(r, 500));
    onProgress({ index: 0, total, title: "Без zapret", score: 4, max: 13 });
    const tried: ZapretPick["tried"] = [];
    for (const [i, s] of previewStrategies.slice(0, 4).entries()) {
      if (previewCancel) {
        return { best: null, bestTitle: null, score: 4, max: 13, baseline: 4, tested: i, cancelled: true, tried };
      }
      onProgress({ index: i + 1, total, title: s.title, score: null, max: 13 });
      await new Promise((r) => setTimeout(r, 700));
      const passed = i === 3 ? 13 : 6 + i;
      tried.push({ id: s.id, title: s.title, passed });
      onProgress({ index: i + 1, total, title: s.title, score: passed, max: 13 });
    }
    return { best: "general (ALT4)", bestTitle: "ALT4", score: 13, max: 13, baseline: 4, tested: 4, cancelled: false, tried };
  }
  const off = await listen<ZapretProgress>("zapret-progress", (e) => onProgress(e.payload));
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

export type ZapretFix = "repair" | "stop_conflicts" | "autoselect" | "allow_timestamps" | "enable";

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
    ["Discord: подключение", 570, null],
    ["Discord: файлы", 470, 520],
    ["YouTube", 390, 410],
    ["YouTube: картинки", 320, 370],
    ["YouTube: видео", 300, 360],
  ].map(([name, a, b]) => ({ name: name as string, tls13: a as number | null, tls12: b as number | null })),
  download: true,
  passed,
  max: 13,
  latencyMs: 4700,
});

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
      steps: ["Скачан релиз 1.10.5 (SHA-256 сверен с GitHub)", "Стратегий: 22", "winws и WinDivert — проверенные версии"],
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
        "Рабочие списки сброшены — создадутся при запуске",
        "Файлы комплекта целы (Flowseal 1.10.4)",
        "Драйвер WinDivert удалён — установится заново при запуске",
      ],
    };
  }
  return invoke<MaintenanceReport>("zapret_repair");
}

export async function zapretCheck(): Promise<CheckRecord> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 1200));
    return { at: Math.floor(Date.now() / 1000), strategy: "general (ALT4)", check: previewCheck(12) };
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
      title: "Стратегия не помогает в этой сети",
      detail:
        "С «ALT4» открывается 5 из 13 проверок. Провайдеры блокируют по-разному — подберите стратегию. Если не поможет ни одна, переустановите zapret.",
      steps: [
        { title: "Служба KVT", state: "ok", detail: "Работает" },
        { title: "Файлы zapret", state: "ok", detail: "Flowseal 1.10.4, стратегий: 22" },
        { title: "Другие обходы", state: "ok", detail: "Не найдены" },
        { title: "zapret", state: "ok", detail: "Работает, стратегия «ALT4»" },
        { title: "Мешающая программа", state: "warning", detail: "AdGuard — мешает Discord; добавьте Discord в исключения AdGuard" },
        { title: "Discord и YouTube", state: "fail", detail: "Открывается 5 из 13 проверок" },
      ],
      fix: "autoselect",
      check: previewCheck(5),
    };
  }
  return invoke<ZapretDiagnosis>("zapret_diagnose");
}

export function onZapretCheck(handler: (record: CheckRecord) => void): () => void {
  if (!inTauri) return () => {};
  const off = listen<CheckRecord>("zapret-check", (e) => handler(e.payload));
  return () => void off.then((f) => f());
}

export function onZapretAuto(handler: (event: ZapretAutoEvent) => void): () => void {
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
  const ev = (ago: number, e: Omit<NetEvent, "at">): NetEvent => ({ at: now - ago * 1000, ...e });
  const events: NetEvent[] = [
    ev(4, { origin: "app", purpose: "tunnel", host: "www.cloudflare.com", route: "tunnel", outcome: "ok", ms: 182, detail: "" }),
    ev(64, { origin: "app", purpose: "tunnel", host: "www.cloudflare.com", route: "tunnel", outcome: "ok", ms: 175, detail: "" }),
    ev(95, { origin: "app", purpose: "server_check", host: "www.microsoft.com", route: "test_core", outcome: "deferred", ms: null, detail: "повтор через 58 с" }),
    ev(97, { origin: "app", purpose: "server_check", host: "www.microsoft.com", route: "test_core", outcome: "ok", ms: 412, detail: "Работает" }),
    ev(99, { origin: "app", purpose: "server_check", host: "cdn.example.net", route: "test_core", outcome: "failed", ms: 5000, detail: "Провайдер притормозил соединение — подождите или выберите другой сервер" }),
    ev(120, { origin: "app", purpose: "server_ping", host: "nl1.example.net:443", route: "direct", outcome: "ok", ms: 48, detail: "" }),
    ev(120, { origin: "app", purpose: "server_ping", host: "de1.example.net:443", route: "direct", outcome: "failed", ms: null, detail: "TCP не открылся" }),
    ev(300, { origin: "service", purpose: "rules", host: "raw.githubusercontent.com", route: "direct", outcome: "ok", ms: 640, detail: "" }),
    ev(302, { origin: "service", purpose: "rules", host: "github.com", route: "direct", outcome: "ok", ms: 910, detail: "" }),
    ev(900, { origin: "app", purpose: "subscription", host: "sub.example.com", route: "direct", outcome: "ok", ms: 730, detail: "" }),
    ev(1800, { origin: "app", purpose: "dns", host: "1.1.1.1:53", route: "direct", outcome: "ok", ms: 21, detail: "UDP" }),
    ev(1800, { origin: "app", purpose: "dns", host: "cloudflare-dns.com", route: "direct", outcome: "ok", ms: 160, detail: "DoH" }),
    ev(2400, { origin: "app", purpose: "update", host: "api.github.com", route: "direct", outcome: "ok", ms: 380, detail: "версия Flowseal" }),
  ];
  const by = new Map<string, HostSummary>();
  for (const e of events) {
    const s = by.get(e.host) ?? { host: e.host, opened: 0, failed: 0, held: 0, peakPerMinute: 0, last: 0 };
    if (e.outcome === "ok" || e.outcome === "failed") s.opened += 1;
    else s.held += 1;
    if (e.outcome === "failed") s.failed += 1;
    s.peakPerMinute = Math.max(s.peakPerMinute, Math.min(s.opened, 2));
    s.last = Math.max(s.last, e.at);
    by.set(e.host, s);
  }
  return { events, hosts: [...by.values()].sort((a, b) => b.opened - a.opened), service: true };
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
            title: "Включён системный прокси",
            detail:
              "Браузеры и другие программы отправляют трафик на 127.0.0.1:10808 — обычно это остаток другого VPN-клиента. Если та программа закрыта, сайты не открываются; если запущена — трафик идёт через неё, а не через KVT.",
            fix: { kind: "disable_system_proxy" },
          }
        : {
            group: "leaks",
            level: "ok",
            title: "Системный прокси",
            detail: "Не задан: программы выходят в сеть обычным путём, через туннель KVT.",
            fix: null,
          },
      { group: "leaks", level: "ok", title: "Прокси WinHTTP", detail: "Не задан.", fix: null },
      { group: "leaks", level: "ok", title: "Teredo", detail: "Выключен или не используется.", fix: null },
      {
        group: "leaks",
        level: "info",
        title: "Браузер использует свой DNS",
        detail:
          "Microsoft Edge (chrome.cloudflare-dns.com): защищённый DNS включён в настройках браузера. Запросы зашифрованы, но идут мимо DNS KVT — если сайты из списков маршрутизации открываются не так, выключите «Безопасный DNS» в настройках браузера.",
        fix: null,
      },
      {
        group: "conflicts",
        level: "warning",
        title: "Запущен v2rayN",
        detail:
          "Два VPN одновременно спорят за маршруты и DNS: часть трафика уходит не туда, подключение обрывается. Закройте другой клиент, пока работает KVT.",
        fix: { kind: "close_process", pid: 4242, name: "v2rayN" },
      },
      { group: "conflicts", level: "ok", title: "Туннели других VPN", detail: "Активных нет.", fix: null },
      {
        group: "conflicts",
        level: "info",
        title: "Антивирус проверяет HTTPS",
        detail:
          "Kaspersky Plus может перехватывать защищённые соединения. Если подписки не загружаются или проверка серверов ошибается, добавьте папку KVT в исключения или выключите «Проверку защищённых соединений».",
        fix: null,
      },
      {
        group: "zapret",
        level: "warning",
        title: "Служба zapret запускается вместе с Windows",
        detail:
          "zapret стартует при каждом включении компьютера и мешает zapret в KVT. Исправление остановит её и переведёт в ручной запуск — ничего не удаляется.",
        fix: { kind: "service", action: "disable_zapret_service", name: "zapret" },
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
    throw new Error("Служба KVT не запущена — это исправление выполняет она");
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
    skipped: [{ reason: "VMess не поддерживается", count: 3 }],
    note: null,
  },
  {
    client: "happ",
    title: "Happ",
    location: String.raw`C:\Users\user\AppData\Local\Happ`,
    subscriptions: [],
    servers: [],
    skipped: [],
    note: "Happ хранит подписки в зашифрованном виде — KVT их не читает. Скопируйте в Happ ссылку на подписку и добавьте её в KVT кнопкой «+».",
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
  if (!inTauri) throw new Error("Выбор папки работает в приложении (npm run tauri dev).");
  return invoke<MigrationPreview[] | null>("migrate_pick_folder");
}

export async function migrateImport(locations: string[], servers: boolean): Promise<MigrationReport> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 1000));
    return { loaded: 1, pending: 1, existing: 0, servers: servers ? 2 : 0 };
  }
  return invoke<MigrationReport>("migrate_import", { request: { locations, servers } });
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
      version: "0.1.0",
      cores: { xray: "26.10.31", "sing-box": "1.14.4", wintun: "0.14.1" },
      sourceUrl: "https://github.com/kostiashkaaa/KVT-client",
      licenses: true,
    };
  }
  return invoke<About>("about_info");
}

/** Открывает исходники, страницу загрузки или папку лицензий — только их. */
export async function openLink(target: "source" | "releases" | "licenses"): Promise<void> {
  if (inTauri) await invoke("open_link", { target });
}

/** Автозапуск с Windows свёрнутым в трей (значение в реестре, не в настройках). */
export async function autostartEnabled(): Promise<boolean> {
  if (!inTauri) return true;
  return invoke<boolean>("autostart_enabled");
}

export async function setAutostart(enabled: boolean): Promise<void> {
  if (inTauri) await invoke("set_autostart", { enabled });
}

/** Идут ли данные через туннель: null — не проверяли или VPN выключен. */
export async function tunnelState(): Promise<boolean | null> {
  if (!inTauri) return null;
  return invoke<boolean | null>("tunnel_state");
}

export function onTunnelState(handler: (ok: boolean | null) => void): () => void {
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
        text: ["Диагностика KVT 0.1.0", "Ключи, пароли, UUID, ссылки подписок и адреса серверов скрыты."].join("\n"),
      },
      {
        name: "status.json",
        text: JSON.stringify({ service: { state: "connected", core: "xray" }, tunnelOk: true }, null, 2),
      },
      {
        name: "kvt.log",
        text: [
          '2026-11-05T10:00:00Z  INFO KVT запущен version="0.1.0"',
          "2026-11-05T10:00:05Z  WARN подписка не обновилась error=нет ответа",
        ].join("\n"),
      },
      { name: "service.log", text: "2026-11-05T10:00:01Z  INFO подключено core=Xray kill_switch=true" },
      { name: "core.log", text: "" },
    ];
  }
  return invoke<DiagFile[]>("diag_preview");
}

/** Сохраняет показанное в предпросмотре. false — пользователь закрыл окно выбора файла. */
export async function diagSave(): Promise<boolean> {
  if (!inTauri) throw new Error("Сохранение работает в приложении (npm run tauri dev).");
  return invoke<boolean>("diag_save");
}
