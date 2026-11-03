// Мост к Rust-части приложения. В WebView попадают только данные для отображения:
// пароли, UUID и ссылки подписок остаются в Rust.

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

export type Verdict = "ok" | "suspicious" | "avoid";

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
  fingerprintAdvice: Verdict | null;
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
  if (!inTauri) return { groups: previewGroups, choice: null };
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
    fingerprintAdvice: i % 5 === 1 ? "suspicious" : "ok",
  };
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
  | { kind: "open_dns_check" };

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
  | { kind: "gave_up" };

export function onWatchdog(handler: (event: WatchdogEvent) => void): () => void {
  if (!inTauri) return () => {};
  const off = listen<WatchdogEvent>("watchdog", (e) => handler(e.payload));
  return () => void off.then((f) => f());
}
