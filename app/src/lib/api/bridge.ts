// Общее для всех разделов api: вызов Rust и признак, что окно в приложении.

export { invoke } from "@tauri-apps/api/core";
export { listen } from "@tauri-apps/api/event";

export const inTauri =
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
/** Окно работает в приложении, а не в превью браузера (`npm run dev`). */
export const inApp = inTauri;
