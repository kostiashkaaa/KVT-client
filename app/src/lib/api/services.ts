import { inTauri, invoke, listen } from "./bridge";
import { previewServices } from "./preview";

// ── Сервисы на вкладке «Проверка» (YouTube, Discord, Telegram…) ──

/** Каким путём идёт трафик сервиса. */
export type ServiceVia = "vpn" | "zapret" | "direct" | "proxy" | "blocked";

/** `unknown` — не проверяли, `waiting` — слишком частые запросы к сайту. */
export type TileState = "unknown" | "waiting" | "works" | "slow" | "down";

/** Что работает сейчас на самом деле (не выбранный режим). */
export type ServicesRunning = "off" | "vpn" | "hybrid" | "zapret";

export interface ServiceTile {
  id: string;
  name: string;
  via: ServiceVia;
  state: TileState;
  /** Что случилось, на языке окна; пусто, пока не проверяли. */
  detail: string;
}

export interface ServicesSnapshot {
  /** Когда проверено (секунды Unix); null — не проверяли. */
  at: number | null;
  checking: boolean;
  running: ServicesRunning;
  tiles: ServiceTile[];
}

/** Итог последней проверки (или плитки «не проверено»). Сетевых запросов не шлёт. */
export async function servicesLast(): Promise<ServicesSnapshot> {
  if (!inTauri) return previewServices();
  return invoke<ServicesSnapshot>("services_last");
}

/** Проверить сервисы. `auto` — вкладка открылась: проверка, только если итог устарел и
 *  что-то подключено; без `auto` — кнопка «Проверить». */
export async function servicesCheck(auto: boolean): Promise<ServicesSnapshot> {
  if (!inTauri) return previewServices({ check: !auto });
  return invoke<ServicesSnapshot>("services_check", { auto });
}

/** Итог изменился или проверка началась (после подключения, по кнопке). */
export function onServices(
  handler: (snapshot: ServicesSnapshot) => void,
): () => void {
  if (!inTauri) return () => {};
  const off = listen<ServicesSnapshot>("services", (e) => handler(e.payload));
  return () => void off.then((f) => f());
}
