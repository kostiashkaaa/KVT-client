import { t } from "./i18n";
// Сообщения окна — через одно место (шаг 5.8).
//
// - Одинаковое сообщение (тот же ключ или тот же текст) не дублируется, а
//   продлевается и получает счётчик «×2».
// - На экране не больше четырёх: лишнее вытесняет самое старое, сначала из тех,
//   что исчезают сами.
// - Ошибки и предупреждения висят до «Понятно». Сообщения-сведения исчезают сами,
//   через время по длине текста, и не гаснут, пока над ними мышь или окно свёрнуто:
//   в zapret-kvn уведомления гасли раньше, чем их успевали прочитать.

export type NoticeTone = "warn" | "info";

export interface NoticeAction {
  label: string;
  primary?: boolean;
  run: () => void | Promise<void>;
}

export interface Notice {
  id: number;
  /** Сообщения с одним ключом заменяют друг друга (например, «ошибка подключения»). */
  key: string;
  text: string;
  tone: NoticeTone;
  /** Висит до «Понятно» (ошибки и предупреждения). */
  sticky: boolean;
  actions: NoticeAction[];
  /** Подпись кнопки закрытия. */
  closeLabel: string;
  /** Вызывается, когда сообщение закрыли этой кнопкой. */
  onclose?: () => void;
  /** Сколько раз пришло это же сообщение. */
  count: number;
}

export interface NoticeInput {
  text: string;
  tone?: NoticeTone;
  key?: string;
  /** По умолчанию: предупреждения висят, сведения исчезают сами. */
  sticky?: boolean;
  actions?: NoticeAction[];
  closeLabel?: string;
  onclose?: () => void;
}

export const MAX_NOTICES = 4;

/** Сколько живёт сообщение-сведение: 5–15 с, примерно по скорости чтения. */
export function lifetime(text: string): number {
  return Math.min(15_000, Math.max(5_000, 3_000 + text.length * 60));
}

interface Timer {
  remaining: number;
  started: number;
  handle: ReturnType<typeof setTimeout> | null;
}

let list = $state<Notice[]>([]);
let nextId = 1;
const timers = new Map<number, Timer>();
const hovered = new Set<number>();
let windowHidden = typeof document !== "undefined" && document.hidden;

function stop(id: number) {
  const t = timers.get(id);
  if (t?.handle) {
    clearTimeout(t.handle);
    t.remaining -= Date.now() - t.started;
    t.handle = null;
  }
}

function run(id: number) {
  const t = timers.get(id);
  if (!t || t.handle || hovered.has(id) || windowHidden) return;
  t.started = Date.now();
  t.handle = setTimeout(() => dismiss(id), Math.max(0, t.remaining));
}

function arm(n: Notice) {
  stop(n.id);
  timers.delete(n.id);
  if (n.sticky) return;
  timers.set(n.id, { remaining: lifetime(n.text), started: Date.now(), handle: null });
  run(n.id);
}

export function push(input: NoticeInput): number {
  const tone = input.tone ?? "warn";
  const sticky = input.sticky ?? tone === "warn";
  const key = input.key ?? `text:${input.text}`;
  const existing = list.find((n) => n.key === key) ?? list.find((n) => n.text === input.text);
  if (existing) {
    const same = existing.text === input.text;
    existing.count = same ? existing.count + 1 : 1;
    existing.text = input.text;
    existing.tone = tone;
    existing.sticky = sticky;
    existing.actions = input.actions ?? [];
    existing.closeLabel = input.closeLabel ?? t("Понятно", "Got it");
    existing.onclose = input.onclose;
    arm(existing);
    return existing.id;
  }
  const notice: Notice = {
    id: nextId++,
    key,
    text: input.text,
    tone,
    sticky,
    actions: input.actions ?? [],
    closeLabel: input.closeLabel ?? t("Понятно", "Got it"),
    onclose: input.onclose,
    count: 1,
  };
  list.push(notice);
  while (list.length > MAX_NOTICES) {
    const victim = list.find((n) => !n.sticky && n.id !== notice.id) ?? list[0]!;
    dismiss(victim.id);
  }
  arm(notice);
  return notice.id;
}

export function dismiss(id: number) {
  stop(id);
  timers.delete(id);
  hovered.delete(id);
  const i = list.findIndex((n) => n.id === id);
  if (i >= 0) list.splice(i, 1);
}

export function dismissKey(key: string) {
  for (const n of list.filter((n) => n.key === key)) dismiss(n.id);
}

/** Мышь над сообщением — таймер стоит. */
export function hover(id: number, on: boolean) {
  if (on) {
    hovered.add(id);
    stop(id);
  } else {
    hovered.delete(id);
    run(id);
  }
}

/** Окно свёрнуто или скрыто — таймеры всех сообщений стоят. */
export function setWindowHidden(hidden: boolean) {
  windowHidden = hidden;
  for (const id of timers.keys()) {
    if (hidden) stop(id);
    else run(id);
  }
}

if (typeof document !== "undefined") {
  document.addEventListener("visibilitychange", () => setWindowHidden(document.hidden));
}

export const notices = {
  get list(): Notice[] {
    return list;
  },
};
