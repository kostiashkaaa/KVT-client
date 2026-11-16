import { t } from "../i18n";
import { inTauri, invoke } from "./bridge";

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
