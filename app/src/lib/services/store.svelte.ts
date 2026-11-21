// Плитки сервисов («Проверка»): итог последней проверки из Rust. Живёт дольше
// страницы — вкладку можно сменить и вернуться, итог остаётся (и приходит событием,
// если проверка завершилась, пока окно было на другой вкладке).

import {
  onServices,
  servicesCheck,
  servicesLast,
  servicesPick,
  type ServicesSnapshot,
} from "../api";

export const services = $state({
  snapshot: null as ServicesSnapshot | null,
  /** Кнопка нажата: до ответа Rust показываем «Проверяю…», даже если событие ещё не пришло. */
  pending: false,
  error: null as string | null,
});

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

/** Перечитать итог. Сетевых запросов не шлёт: плитки меняются вместе с режимом. */
export async function reload() {
  try {
    services.snapshot = await servicesLast();
  } catch (e) {
    services.error = message(e);
  }
}

/** Вкладка открылась: проверить, только если что-то подключено и итог устарел. */
export async function checkOnOpen() {
  try {
    services.snapshot = await servicesCheck(true);
  } catch (e) {
    services.error = message(e);
  }
}

/** Кнопка «Проверить». */
export async function checkNow() {
  if (services.pending || services.snapshot?.checking) return;
  services.pending = true;
  services.error = null;
  try {
    services.snapshot = await servicesCheck(false);
  } catch (e) {
    services.error = message(e);
  } finally {
    services.pending = false;
  }
}

/** Свой набор плиток (`null` — по умолчанию). Rust сохраняет его и, если что-то
 *  подключено, сразу проверяет новый набор. */
export async function pickServices(ids: string[] | null) {
  if (services.pending) return;
  services.pending = true;
  services.error = null;
  try {
    services.snapshot = await servicesPick(ids);
  } catch (e) {
    services.error = message(e);
  } finally {
    services.pending = false;
  }
}

let listening = false;
export function listenServices() {
  if (listening) return;
  listening = true;
  onServices((s) => (services.snapshot = s));
}
