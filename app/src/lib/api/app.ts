import { browserLang, t, type Lang, type LangChoice } from "../i18n";
import { inTauri, invoke, listen } from "./bridge";
import { demo, demoState } from "./preview";

// ── Этап 5.4: надёжность ──

/** Сообщения, появившиеся до открытия окна (например, о повреждённых настройках). */
export async function takeNotices(): Promise<string[]> {
  if (!inTauri) return [];
  return invoke<string[]>("take_notices");
}

/** Трей добавил сообщение для окна (ошибка действия, а уведомления выключены). */
export function onNotices(handler: () => void): () => void {
  if (!inTauri) return () => {};
  const off = listen("notices", handler);
  return () => void off.then((f) => f());
}

/** Страница, которую открывает трей: вкладка окна, «why» или «add». */
export type TrayPage = "home" | "zapret" | "journal" | "why" | "add";

/** Страница, которую трей попросил открыть до появления окна. */
export async function takePage(): Promise<TrayPage | null> {
  if (!inTauri) return null;
  return invoke<TrayPage | null>("take_page");
}

export function onNavigate(handler: (page: TrayPage) => void): () => void {
  if (!inTauri) return () => {};
  const off = listen<TrayPage>("navigate", (e) => handler(e.payload));
  return () => void off.then((f) => f());
}

export interface LangInfo {
  choice: LangChoice;
  /** Действующий язык (для «Как в Windows» — язык системы). */
  lang: Lang;
}

const PREVIEW_LANG = "kvt.lang";

function previewLang(): LangInfo {
  let choice: LangChoice = "auto";
  try {
    const c = localStorage.getItem(PREVIEW_LANG);
    if (c === "ru" || c === "en") choice = c;
  } catch {
    // Хранилище недоступно — язык браузера.
  }
  return { choice, lang: choice === "auto" ? browserLang() : choice };
}

/** Язык интерфейса: выбор и действующий язык. */
export async function getLanguage(): Promise<LangInfo> {
  if (!inTauri) return previewLang();
  return invoke<LangInfo>("get_language");
}

/** Сменить язык (трей и уведомления — сразу, окно перезагружается). */
export async function setLanguage(choice: LangChoice): Promise<LangInfo> {
  if (!inTauri) {
    try {
      if (choice === "auto") localStorage.removeItem(PREVIEW_LANG);
      else localStorage.setItem(PREVIEW_LANG, choice);
    } catch {
      // Превью: язык продержится до перезагрузки.
    }
    return previewLang();
  }
  return invoke<LangInfo>("set_language", { choice });
}

/** Служба отвечает, но другой версии (прерванное обновление) — нужна переустановка. */
export async function serviceMismatch(): Promise<boolean> {
  if (!inTauri) return false;
  return invoke<boolean>("service_mismatch");
}

/** Запускает службу KVT (право на запуск выдаёт установщик) и ждёт её ответа. */
export async function startService(): Promise<void> {
  if (inTauri) await invoke("start_service");
}

export interface About {
  version: string;
  /** xray, sing-box, wintun → версия. */
  cores: Record<string, string>;
  sourceUrl: string;
  /** Есть папка с текстами лицензий (в установленном KVT). */
  licenses: boolean;
}

export async function aboutInfo(): Promise<About> {
  if (!inTauri) {
    return {
      version: "0.9.4",
      cores: { xray: "26.10.31", "sing-box": "1.14.4", wintun: "0.14.1" },
      sourceUrl: "https://github.com/kostiashkaaa/KVT-client",
      licenses: true,
    };
  }
  return invoke<About>("about_info");
}

/** Что окно может открыть: список зашит в Rust (`about.rs`), адрес окно не задаёт. */
export type LinkTarget = "source" | "releases" | "latest" | "channel" | "licenses";

/** Открывает исходники, страницу загрузки, канал или папку лицензий — только их. */
export async function openLink(target: LinkTarget): Promise<void> {
  if (inTauri) await invoke("open_link", { target });
}

export interface UpdateStatus {
  current: string;
  /** Последняя версия на GitHub; null — ещё не проверяли или не удалось. */
  latest: string | null;
  /** Она новее установленной. */
  available: boolean;
  /** Когда проверяли (Unix-время, мс). */
  checkedAt: number | null;
  error: string | null;
}

/** Что известно о новой версии — без запроса в сеть. */
export async function updateStatus(): Promise<UpdateStatus> {
  // В предпросмотре — как будто вышла новая версия: видно плашку и точку у «Настроек».
  if (!inTauri)
    return {
      current: "0.9.4",
      latest: demo ? "0.9.4" : "0.9.5",
      available: !demo,
      checkedAt: Date.now(),
      error: null,
    };
  return invoke<UpdateStatus>("update_status");
}

/** Спросить у GitHub сейчас (не чаще раза в минуту). */
export async function updateCheck(): Promise<UpdateStatus> {
  if (!inTauri)
    return {
      current: "0.9.4",
      latest: "0.9.5",
      available: true,
      checkedAt: Date.now(),
      error: null,
    };
  return invoke<UpdateStatus>("update_check");
}

/** Фоновая проверка нашла новую версию. */
export function onUpdateAvailable(handler: () => void): () => void {
  if (!inTauri) return () => {};
  const off = listen("update-available", handler);
  return () => void off.then((f) => f());
}

/** Автозапуск с Windows свёрнутым в трей (значение в реестре, не в настройках).
 *  blocked — запись наша, но её выключили в «Диспетчере задач» или «Параметрах»;
 *  other — в автозагрузке другой kvt.exe. */
export type AutostartState = "on" | "off" | "blocked" | "other";

export async function autostartState(): Promise<AutostartState> {
  if (!inTauri) return "on";
  return invoke<AutostartState>("autostart_state");
}

export async function setAutostart(enabled: boolean): Promise<void> {
  if (inTauri) await invoke("set_autostart", { enabled });
}

/** Идут ли данные через туннель: null — не проверяли или VPN выключен. */
export async function tunnelState(): Promise<boolean | null> {
  if (!inTauri) return demo && demoState.state === "connected" ? true : null;
  return invoke<boolean | null>("tunnel_state");
}

export function onTunnelState(
  handler: (ok: boolean | null) => void,
): () => void {
  if (!inTauri) return () => {};
  const off = listen<boolean | null>("tunnel-state", (e) => handler(e.payload));
  return () => void off.then((f) => f());
}

export interface DiagFile {
  name: string;
  text: string;
}

/** Что войдёт в архив диагностики (уже без ключей, ссылок подписок и адресов серверов). */
export async function diagPreview(): Promise<DiagFile[]> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 600));
    return [
      {
        name: "README.txt",
        text: [
          "Диагностика KVT 0.1.0",
          "Ключи, пароли, UUID, ссылки подписок и адреса серверов скрыты.",
        ].join("\n"),
      },
      {
        name: "status.json",
        text: JSON.stringify(
          { service: { state: "connected", core: "xray" }, tunnelOk: true },
          null,
          2,
        ),
      },
      {
        name: "kvt.log",
        text: [
          '2026-11-05T10:00:00Z  INFO KVT запущен version="0.1.0"',
          "2026-11-05T10:00:05Z  WARN подписка не обновилась error=нет ответа",
        ].join("\n"),
      },
      {
        name: "service.log",
        text: "2026-11-05T10:00:01Z  INFO подключено core=Xray kill_switch=true",
      },
      { name: "core.log", text: "" },
    ];
  }
  return invoke<DiagFile[]>("diag_preview");
}

/** Сохраняет показанное в предпросмотре. false — пользователь закрыл окно выбора файла. */
export async function diagSave(): Promise<boolean> {
  if (!inTauri)
    throw new Error(t("Сохранение работает в приложении (npm run tauri dev).", "Saving works in the app (npm run tauri dev)."));
  return invoke<boolean>("diag_save");
}
