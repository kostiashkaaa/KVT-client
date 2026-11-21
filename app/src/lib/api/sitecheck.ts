// «Почему не работает?» для одного сайта: пробы по стадиям каждым доступным
// путём. Разбирает и проверяет адрес Rust (`kvt_core::sitecheck`), сюда приходят
// только вердикты и совет — без адресов, куда ходили.

import { t } from "../i18n";
import { inTauri, invoke } from "./bridge";
import { demo, demoState } from "./preview";

/** Что сейчас работает (как у плиток сервисов). */
export type SiteRunning = "off" | "vpn" | "hybrid" | "zapret";

/** Путь пробы: через туннель или напрямую (при работающем zapret — «через zapret»). */
export type SitePath = "tunnel" | "direct";

/** Почему путь не проверяли. */
export type SiteSkip = "kill_switch";

/** Как именно отвечает (или режет) путь. */
export type SiteVerdict =
  | "no_address"
  | "unreachable"
  | "tls_cut"
  | "tls_frozen"
  | "data_frozen"
  | "refused"
  | "slow"
  | "works";

/** Совет по итогам всех проб. */
export type SiteAdvice = "works" | "try_vpn" | "still_cut" | "change_server" | "check_dns";

export interface SitePathReport {
  path: SitePath;
  /** `null` — проверка отложена: соединения с этим сайтом недавно заморожены. */
  verdict: SiteVerdict | null;
  /** Сколько шла проба. */
  ms: number | null;
}

export interface SiteSkipped {
  path: SitePath;
  reason: SiteSkip;
}

export interface SiteReport {
  host: string;
  running: SiteRunning;
  paths: SitePathReport[];
  skipped: SiteSkipped[];
  advice: SiteAdvice;
}

/** Проверить один сайт: как именно его режут и какой путь открывает. */
export async function siteCheck(input: string): Promise<SiteReport> {
  if (!inTauri) {
    const host = input.trim().toLowerCase();
    if (!host) {
      throw new Error(t("Не похоже на адрес сайта. Пример: example.com", "Doesn't look like a site address. Example: example.com"));
    }
    await new Promise((r) => setTimeout(r, 900));
    const state = demoState.state;
    const running: SiteRunning = state === "connected" ? "vpn" : state === "zapret" ? "zapret" : "off";
    // В превью показательно: «напрямую» режут, туннель открывает.
    const paths: SitePathReport[] =
      running === "vpn"
        ? [
            { path: "tunnel", verdict: "works", ms: 940 },
            { path: "direct", verdict: demo ? "tls_cut" : "works", ms: demo ? 740 : 610 },
          ]
        : [{ path: "direct", verdict: demo ? "data_frozen" : "works", ms: 720 }];
    const advice: SiteAdvice = paths.some((p) => p.verdict === "works")
      ? "works"
      : "try_vpn";
    return { host: host || "example.com", running, paths, skipped: [], advice };
  }
  return invoke<SiteReport>("site_check", { input });
}
