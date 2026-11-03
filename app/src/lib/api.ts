// Мост к Rust-части приложения. В WebView попадают только данные для отображения:
// пароли, UUID и ссылки подписок остаются в Rust.

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

export type Verdict = "ok" | "suspicious" | "avoid";

export interface ServerSummary {
  name: string;
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

export interface ParsedSubscription {
  id: string | null;
  servers: ServerSummary[];
  info: string[];
  errors: { line: number; message: string }[];
  duplicates: number;
  meta: SubscriptionInfo | null;
}

export type Mode = "vpn" | "hybrid" | "zapret";

const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

/** Одна https-ссылка — это адрес подписки; всё остальное — содержимое (ссылки на серверы). */
export function isSubscriptionUrl(input: string): boolean {
  return /^https?:\/\/\S+$/i.test(input.trim());
}

export async function addSubscription(input: string): Promise<ParsedSubscription> {
  if (isSubscriptionUrl(input)) {
    if (!inTauri) throw new Error("Загрузка подписки по ссылке работает в приложении (npm run tauri dev).");
    return invoke<ParsedSubscription>("add_subscription_url", { url: input.trim() });
  }
  if (!inTauri) return previewParse(input);
  return invoke<ParsedSubscription>("parse_subscription", { body: input });
}

export type QuickResult =
  | { kind: "reachable"; latency_ms: number }
  | { kind: "unreachable" }
  | { kind: "dns_failed" }
  | { kind: "not_applicable" };

/** Быстрая проверка: TCP-пинг без TLS, по всем серверам параллельно. */
export async function quickCheck(count: number): Promise<QuickResult[]> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 600));
    return Array.from({ length: count }, (_, i): QuickResult =>
      i === 1 ? { kind: "unreachable" } : { kind: "reachable", latency_ms: 40 + i * 37 },
    );
  }
  return invoke<QuickResult[]>("quick_check");
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
  serverIndex: number | null;
  mode: Mode | null;
  killSwitch: boolean;
  routing: RoutingSettings;
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
export async function snapshot(): Promise<{ subscription: ParsedSubscription | null; choice: Choice } | null> {
  if (!inTauri) return null;
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
function previewParse(body: string): ParsedSubscription {
  const lines = body.split(/\r?\n/).filter((l) => l.includes("://"));
  return {
    id: "preview",
    servers: lines.map((line, i) => ({
      name: decodeURIComponent(line.split("#")[1] ?? `Сервер ${i + 1}`),
      address: "preview.example",
      port: 443,
      protocol: line.split("://")[0] ?? "?",
      transport: "tcp",
      security: "reality",
      sni: "www.microsoft.com",
      core: "xray",
      fingerprintAdvice: i % 3 === 1 ? "suspicious" : "ok",
    })),
    info: [],
    errors: [],
    duplicates: 0,
    meta: {
      title: "Предпросмотр",
      usedBytes: 34 * 2 ** 30,
      totalBytes: 100 * 2 ** 30,
      expire: Math.floor(Date.now() / 1000) + 12 * 86400,
      supportUrl: null,
      announce: null,
    },
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
  active: boolean;
}

const previewSubscriptions: SubscriptionItem[] = [
  {
    id: "a",
    title: "KVT",
    byUrl: true,
    servers: 12,
    usedBytes: 34 * 2 ** 30,
    totalBytes: 100 * 2 ** 30,
    expire: Math.floor(Date.now() / 1000) + 49 * 86400,
    updatedAt: Math.floor(Date.now() / 1000) - 3 * 3600,
    active: true,
  },
  {
    id: "b",
    title: "Добавлена вручную",
    byUrl: false,
    servers: 2,
    usedBytes: null,
    totalBytes: null,
    expire: null,
    updatedAt: Math.floor(Date.now() / 1000) - 2 * 86400,
    active: false,
  },
];

export async function listSubscriptions(): Promise<SubscriptionItem[]> {
  if (!inTauri) return previewSubscriptions;
  return invoke<SubscriptionItem[]>("list_subscriptions");
}

export async function selectSubscription(id: string): Promise<ParsedSubscription | null> {
  if (!inTauri) return null;
  return invoke<ParsedSubscription | null>("select_subscription", { id });
}

export async function removeSubscription(id: string): Promise<void> {
  if (inTauri) await invoke("remove_subscription", { id });
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
 * Полная проверка через тестовое ядро. Результаты приходят по одному через
 * onProbeResult; итоговый массив — когда проверены все.
 */
export async function fullCheck(count: number, onResult: (index: number, outcome: Outcome) => void): Promise<void> {
  if (!inTauri) {
    const demo: Outcome[] = [
      { kind: "checked", verdict: "works", latency_ms: 184 },
      { kind: "checked", verdict: "data_frozen", latency_ms: 240 },
      { kind: "checked", verdict: "slow", latency_ms: 2100 },
      { kind: "deferred", retry_after_secs: 170 },
    ];
    for (let i = 0; i < count; i++) {
      await new Promise((r) => setTimeout(r, 250));
      onResult(i, demo[i % demo.length]!);
    }
    return;
  }
  const off = await listen<{ index: number; outcome: Outcome }>("probe-result", (e) =>
    onResult(e.payload.index, e.payload.outcome),
  );
  try {
    await invoke("full_check");
  } finally {
    off();
  }
}
