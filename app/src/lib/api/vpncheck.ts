// «Проверить VPN»: с какого адреса и из какой страны видят снаружи, и какая
// скорость — через VPN и напрямую. Разбор ответов и замер делает Rust
// (`kvt_core::vpncheck`, запросы — `vpncheck` в kvt-app), сюда приходят готовые
// данные: адрес пользователя показывается — он и есть суть проверки.

import { inTauri, invoke } from "./bridge";
import { demo, demoState } from "./preview";
import type { SitePath, SiteRunning, SiteSkip } from "./sitecheck";

// Пути и их ограничения — те же, что у проверки одного сайта.
export type { SitePath, SiteRunning, SiteSkip };

/** Что показывают по одному пути. */
export interface VpnSideView {
  ip: string | null;
  country: string | null;
  /** Скорость, КБ/с; `null` — не измерилась или не показательная. */
  kbps: number | null;
  ms: number | null;
  /** Какой источник ответил адресом: показывается, когда основной недоступен. */
  traceVia: string | null;
  /** Каким источником измерена скорость. */
  speedVia: string | null;
}

export type VpnSide = ({ kind: "ok" } & VpnSideView) | { kind: "failed" } | { kind: "deferred" };

export interface VpnPathSide {
  path: SitePath;
  side: VpnSide;
}

export interface VpnSkipped {
  path: SitePath;
  reason: SiteSkip;
}

export interface VpnReport {
  running: SiteRunning;
  sides: VpnPathSide[];
  skipped: VpnSkipped[];
}

/** Проверить адрес выхода и скорость — через VPN и напрямую. */
export async function vpnCheck(): Promise<VpnReport> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 1200));
    const state = demoState.state;
    const running: SiteRunning = state === "connected" ? "vpn" : state === "zapret" ? "zapret" : "off";
    if (running === "vpn") {
      return {
        running,
        // В превью показательно: выход не в России, напрямую — она.
        sides: [
          { path: "tunnel", side: { kind: "ok", ip: "198.51.100.23", country: "NL", kbps: 6144, ms: 420, traceVia: "cloudflare", speedVia: "cloudflare" } },
          { path: "direct", side: { kind: "ok", ip: "203.0.113.7", country: "RU", kbps: demo ? 18432 : 9216, ms: 240, traceVia: demo ? "sypexgeo" : "cloudflare", speedVia: demo ? "ovh" : "cloudflare" } },
        ],
        skipped: [],
      };
    }
    return {
      running,
      sides: [{ path: "direct", side: { kind: "ok", ip: "203.0.113.7", country: "RU", kbps: 12288, ms: 210, traceVia: "cloudflare", speedVia: "cloudflare" } }],
      skipped: [],
    };
  }
  return invoke<VpnReport>("vpn_check");
}
