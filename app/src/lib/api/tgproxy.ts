import { inTauri, invoke } from "./bridge";

// ── Прокси для Telegram Desktop ──

export interface TgProxyStatus {
  /** Прокси сейчас работает. */
  running: boolean;
  /** Почему не запустился, если пытались. */
  error: string | null;
  port: number;
}

export async function tgProxyStatus(): Promise<TgProxyStatus> {
  if (!inTauri) return { running: true, error: null, port: 1443 };
  return invoke<TgProxyStatus>("tg_proxy_status");
}

/** Открывает в Telegram Desktop окно «Подключить прокси». */
export async function tgProxyOpen(): Promise<void> {
  if (!inTauri) return;
  await invoke("tg_proxy_open");
}

/** Ссылка `tg://proxy` для ручного подключения. */
export async function tgProxyLink(): Promise<string> {
  if (!inTauri)
    return "tg://proxy?server=127.0.0.1&port=1443&secret=dd00000000000000000000000000000000";
  return invoke<string>("tg_proxy_link");
}
