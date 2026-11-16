import { t } from "../i18n";
import { inTauri, invoke, listen } from "./bridge";
import type { DiagnosisStep } from "./network";
import { demo } from "./preview";

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
