// Тема окна: «Как в Windows», светлая или тёмная. Выбор живёт в localStorage
// WebView2 — это настройка вида, в службу и в settings.json она не нужна.
// Применяется до монтирования интерфейса (main.ts), чтобы окно не мигало.
//
// Плюс скрытая тема: 17 быстрых нажатий на «Настройки» включают её и выключают.

import { getCurrentWindow } from "@tauri-apps/api/window";
import { inApp } from "./api";

export type ThemeChoice = "auto" | "light" | "dark";

const CHOICE = "kvt.theme";
const SECRET = "kvt.theme.pickme";

function load(): { choice: ThemeChoice; pickme: boolean } {
  try {
    const c = localStorage.getItem(CHOICE);
    return {
      choice: c === "light" || c === "dark" ? c : "auto",
      pickme: localStorage.getItem(SECRET) === "1",
    };
  } catch {
    return { choice: "auto", pickme: false };
  }
}

export const theme = $state(load());

/** Ставит тему на `<html>` и красит под неё заголовок окна Windows. */
export function applyTheme(): void {
  const root = document.documentElement;
  if (theme.pickme) root.dataset.theme = "pickme";
  else if (theme.choice === "auto") delete root.dataset.theme;
  else root.dataset.theme = theme.choice;

  if (!inApp) return;
  // Заголовок окна рисует Windows: без этого при тёмной теме в светлой системе
  // он остался бы белым. null — снова следовать системе.
  const native = theme.pickme ? "dark" : theme.choice === "auto" ? null : theme.choice;
  void getCurrentWindow()
    .setTheme(native)
    .catch(() => {});
}

function save(): void {
  try {
    localStorage.setItem(CHOICE, theme.choice);
    if (theme.pickme) localStorage.setItem(SECRET, "1");
    else localStorage.removeItem(SECRET);
  } catch {
    // Хранилище недоступно — тема продержится до закрытия окна.
  }
}

/** Выбор в «Настройках». Явный выбор темы снимает и скрытую. */
export function setTheme(choice: ThemeChoice): void {
  theme.choice = choice;
  theme.pickme = false;
  save();
  applyTheme();
}

const TAPS = 17;
/** Пауза между нажатиями, после которой счёт начинается заново. */
const GAP_MS = 700;
let taps = 0;
let last = 0;

/** Нажатие на «Настройки»: каждое семнадцатое подряд переключает скрытую тему. */
export function tapSettings(): void {
  const now = performance.now();
  taps = now - last > GAP_MS ? 1 : taps + 1;
  last = now;
  if (taps < TAPS) return;
  taps = 0;
  theme.pickme = !theme.pickme;
  save();
  applyTheme();
}
