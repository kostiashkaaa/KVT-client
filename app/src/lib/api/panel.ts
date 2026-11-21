import { inTauri, invoke } from "./bridge";
import type { Mode } from "./connection";
import { previewPanel, previewPanelAct } from "./preview";

// ── Мини-панель у значка в трее (окно `mini`, страница mini.html) ──
// Статус, сеанс, туннель и плитки сервисов панель берёт теми же командами, что и главное
// окно (`serviceStatus`, `serviceSession`, `tunnelState`, `servicesLast`); здесь — то,
// что нужно только ей. Адресов, портов и ключей в этих данных нет.

/** Что известно о проверке сервера. */
export type ServerHealth = "works" | "slow" | "down" | "unknown";

export interface PanelServer {
  key: string;
  name: string;
  /** Страна по первому флагу в названии (`nl`). */
  flag: string | null;
  protocol: string;
  transport: string;
  security: string;
  /** Последняя известная задержка, мс (панель сама пинги не снимает). */
  pingMs: number | null;
  health: ServerHealth;
}

export interface PanelZapret {
  /** Название стратегии, как в окне. */
  strategy: string;
  /** Сеть, для которой стратегию подобрал автоподбор; `null` — выбрана вручную. */
  pickedFor: string | null;
}

/** Подписка выбранного сервера. */
export interface PanelSubscription {
  title: string;
  usedBytes: number | null;
  totalBytes: number | null;
  /** Unix-время окончания (секунды). */
  expire: number | null;
}

export interface PanelView {
  mode: Mode;
  killSwitch: boolean;
  autoSwitch: boolean;
  /** Прокси для Telegram Desktop. */
  telegram: boolean;
  server: PanelServer | null;
  /** Рабочие по задержке, затем не проверенные, затем неработающие. */
  servers: PanelServer[];
  /** Серверов в подписках всего: больше, чем в списке, — есть «Все серверы в окне». */
  total: number;
  zapret: PanelZapret;
  subscription: PanelSubscription | null;
}

/** Действия панели — пункты меню трея. */
export type PanelAction =
  | "toggle"
  | "ks"
  | "auto"
  | "tg"
  | `srv:${string}`
  | `mode:${Mode}`;

/** Страницы главного окна, на которые ведёт панель. */
export type PanelPage = "home" | "add" | "subscriptions" | "why" | "settings" | "zapret";

export async function panelSnapshot(): Promise<PanelView> {
  if (!inTauri) return previewPanel();
  return invoke<PanelView>("panel_snapshot");
}

/** Выполняет действие и возвращается, когда оно закончилось (подключение — до конца). */
export async function panelAct(id: PanelAction): Promise<void> {
  if (!inTauri) return previewPanelAct(id);
  await invoke("panel_act", { id });
}

/** Страница измерила содержимое: Rust ставит окно у значка и (в первый раз) показывает. */
export async function panelReady(height: number): Promise<void> {
  if (inTauri) await invoke("panel_ready", { height });
}

/** Закрыть панель (Esc). */
export async function panelClose(): Promise<void> {
  if (inTauri) await invoke("panel_close");
}

/** Закрыть панель и открыть главное окно (на странице `page`, если она указана). */
export async function panelOpen(page?: PanelPage): Promise<void> {
  if (inTauri) await invoke("panel_open", { page: page ?? null });
}
