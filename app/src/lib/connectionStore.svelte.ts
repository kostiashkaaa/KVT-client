// Подключение: статус службы, сеанс и действия окна («Подключить», «Отключить», запуск
// службы), опрос раз в 3 с и переподключение при смене выбора. С чем служба работает
// сейчас — `connectedWith` (ключи настроек из `connectKeys`); что выбрано — `choiceStore`.
// Ошибки показывает окно (`initConnection`): сообщение с кнопкой «Почему не работает?»
// открывает вкладку «Проверка», навигация — не дело стора.

import { t } from "./i18n";
import {
  connect as doConnect,
  disconnect as doDisconnect,
  inApp,
  serviceMismatch,
  serviceSession,
  serviceStatus,
  setChoice,
  startService as doStartService,
  onTunnelState,
  tunnelState,
  type Mode,
  type ServiceStatus,
  type Session,
} from "./api";
import { dismissKey } from "./notices.svelte";
import { routingKeyOf, settingsKeyOf, telegramOf, zapretKeyOf } from "./connectKeys";
import { choice, currentChoice } from "./choiceStore.svelte";

/** С каким сервером, режимом и настройками zapret сейчас подключены. */
export interface ConnectedWith {
  server: string | null;
  mode: Mode;
  zapret: string;
  routing: string;
  settings: string;
}

export const conn = $state({
  /** Статус службы; `null` — не отвечает. */
  status: null as ServiceStatus | null,
  /** Служба ответила хотя бы раз с открытия окна (до этого «не запущена» не показываем). */
  polled: false,
  /** Служба ответила, но другой версии: вместо «Запустить службу» — переустановка. */
  mismatch: false,
  /** Окно запускает службу: «Запускаем службу…» вместо «не запущена». */
  starting: false,
  /** Время и трафик сеанса — из того же ответа службы, что и статус. */
  session: null as Session | null,
  /** Идут ли данные через туннель: null — ещё не проверяли. */
  tunnelOk: null as boolean | null,
  /** Окно выполняет действие (подключение или добавление подписки): опрос и
   *  переподключение ему не мешают. */
  busy: false,
  /** Идёт «Подключить», и его можно отменить; `cancelling` — отмена уже отправлена. */
  connecting: false,
  cancelling: false,
  connectedWith: null as ConnectedWith | null,
});

/** Работает VPN или только zapret. */
export const isActive = (s: ServiceStatus | null): boolean =>
  s?.state === "connected" || s?.state === "zapret";

/** Служба KVT не отвечает (в приложении): вместо «Подключить» — «Запустить службу». */
export const serviceDown = (): boolean => inApp && conn.polled && conn.status === null;

/** Настройки, с которыми служба работает сейчас (ключи — `connectKeys`). */
export const zapretKey = () => zapretKeyOf($state.snapshot(choice.zapret));
export const routingKey = () => routingKeyOf($state.snapshot(choice.routing));
export const settingsKey = () => settingsKeyOf(choice.killSwitch, $state.snapshot(choice.dns));

type Handlers = {
  /** Ошибка действия: одна на окно (новая заменяет прежнюю). */
  failed(e: unknown, why: boolean): void;
  /** Текст ошибки со ссылкой «Почему не работает?». */
  showError(text: string, why: boolean): void;
};

let handlers: Handlers = { failed: () => {}, showError: () => {} };

/** Ошибки и «Почему не работает?» показывает окно — передаёт свои обработчики. */
export function initConnection(h: Handlers) {
  handlers = h;
}

/** «Подключить»: запоминает, с чем подключились, и обновляет статус. */
export async function connect() {
  conn.busy = true;
  conn.connecting = true;
  conn.cancelling = false;
  dismissKey("error");
  const target = { server: choice.selected, mode: choice.mode, zapret: zapretKey(), routing: routingKey(), settings: settingsKey() };
  try {
    await setChoice(currentChoice());
    conn.status = await doConnect();
    conn.session = await serviceSession().catch(() => null);
  } catch (e) {
    // Отменили сами — служба ответила «Подключение отменено», это не ошибка.
    if (!conn.cancelling) handlers.failed(e, true);
    conn.status = await serviceStatus().catch(() => null);
  } finally {
    // Даже при ошибке запоминаем попытку: иначе переподключение пошло бы по кругу.
    conn.connectedWith = isActive(conn.status) ? target : null;
    conn.connecting = false;
    conn.cancelling = false;
    conn.busy = false;
  }
}

/** «Отключить» во время подключения: служба бросает запуск и всё останавливает. */
export async function cancelConnect() {
  if (!conn.connecting || conn.cancelling) return;
  conn.cancelling = true;
  try {
    conn.status = await doDisconnect();
    conn.session = null;
  } catch (e) {
    handlers.failed(e, true);
  }
}

export async function disconnect() {
  conn.busy = true;
  try {
    conn.status = await doDisconnect();
    conn.session = null;
    conn.connectedWith = null;
  } catch (e) {
    handlers.failed(e, true);
  } finally {
    conn.busy = false;
  }
}

/** Запускает службу KVT (право на запуск выдаёт установщик) и ждёт её ответа. */
export async function startService() {
  if (conn.starting) return;
  conn.starting = true;
  dismissKey("error");
  try {
    await doStartService();
    conn.status = await serviceStatus().catch(() => null);
  } catch (e) {
    handlers.failed(e, false);
  } finally {
    conn.starting = false;
  }
}

/** Другой сервер, режим или стратегия zapret при подключении — переподключаемся сразу,
 *  как в Happ. Вызывается из окна — эффекту нужен его контекст. */
export function watchReconnect() {
  $effect(() => {
    if (!choice.restored || conn.busy || !isActive(conn.status) || !conn.connectedWith) return;
    const zapretChanged =
      choice.mode !== "vpn"
        ? zapretKey() !== conn.connectedWith.zapret
        : telegramOf(zapretKey()) !== telegramOf(conn.connectedWith.zapret);
    const serverChanged = choice.mode !== "zapret" && choice.selected !== conn.connectedWith.server;
    if (!serverChanged && !zapretChanged && choice.mode === conn.connectedWith.mode) return;
    if (choice.selected === null && choice.mode !== "zapret") return;
    void connect();
  });
}

/** Идут ли данные через туннель: опрос при открытии окна и событие службы.
 *  Вызывается из окна — эффекту нужен его контекст. */
export function watchTunnel() {
  $effect(() => {
    void tunnelState().then((ok) => (conn.tunnelOk = ok));
    return onTunnelState((ok) => (conn.tunnelOk = ok));
  });
}

/** Сами запускали службу с открытия окна (один раз; дальше — кнопкой). */
let autoStarted = false;

/** Локальный pipe — дешёвый запрос; так видно, если ядро упало само.
 *  Вызывается из окна — эффекту нужен его контекст. */
export function watchStatus() {
  $effect(() => {
    const refreshStatus = async () => {
      if (conn.busy) return;
      const next = await serviceStatus().catch(() => null);
      // Пока шёл опрос, пользователь нажал «Подключить»: старый ответ не должен
      // перезаписать статус и сбросить connectedWith.
      if (conn.busy) return;
      if (next?.state === "failed" && conn.status?.state === "connected") {
        handlers.showError(t(`Соединение прервано: ${next.reason}`, `Connection lost: ${next.reason}`), true);
      }
      const nextActive = isActive(next);
      if (!nextActive) conn.connectedWith = null;
      // Подключились из трея или профиля сети — считаем, что с текущим выбором.
      else if (!conn.connectedWith && choice.restored)
        conn.connectedWith = { server: choice.selected, mode: choice.mode, zapret: zapretKey(), routing: routingKey(), settings: settingsKey() };
      const nextMismatch = next === null && (await serviceMismatch().catch(() => false));
      // Служба в отложенном автозапуске: после входа в Windows она поднимается
      // минуты через две, а окно из автозагрузки открывается раньше. Не ждём —
      // запускаем сами (пользователю это разрешено), иначе остаётся кнопка.
      if (inApp && next === null && !nextMismatch && !autoStarted) {
        autoStarted = true;
        void startService();
      }
      conn.status = next;
      conn.polled = true;
      conn.mismatch = nextMismatch;
      conn.session = nextActive ? await serviceSession().catch(() => null) : null;
    };
    void refreshStatus();
    const timer = setInterval(refreshStatus, 3000);
    return () => clearInterval(timer);
  });
}
