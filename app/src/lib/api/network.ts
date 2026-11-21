import { t } from "../i18n";
import { inTauri, invoke, listen } from "./bridge";
import { type Mode, connect, disconnect } from "./connection";
import { demo } from "./preview";

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

// Данные превью — функция, а не константа: t() читает язык при вызове (на уровне модуля он ещё не выбран).
const previewResolvers = (): Resolver[] => [
  { id: "yandex", title: t("Яндекс", "Yandex"), udp: "77.88.8.8", tunnel: false },
  { id: "cloudflare", title: "Cloudflare", udp: "1.1.1.1", tunnel: true },
  { id: "google", title: "Google", udp: "8.8.8.8", tunnel: true },
  { id: "quad9", title: "Quad9", udp: "9.9.9.9", tunnel: true },
  { id: "adguard", title: "AdGuard", udp: "94.140.14.14", tunnel: false },
];

export async function dnsCatalog(): Promise<Resolver[]> {
  if (!inTauri) return previewResolvers();
  return invoke<Resolver[]>("dns_catalog");
}

export async function dnsCheck(): Promise<DnsReport> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 900));
    const works = (ms: number): PathStatus => ({ state: "works", ms });
    return {
      resolvers: previewResolvers().map((r, i) => ({
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
