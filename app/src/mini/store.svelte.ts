// Состояние мини-панели: то, что читается из Rust (выбор, серверы, статус, сеанс, плитки
// сервисов), и действия. Панель живёт, пока открыта: данные обновляются раз в 3 с и по
// событиям окна, как в главном окне.

import {
  onChoiceChanged,
  onServices,
  onSubscriptionsChanged,
  onTunnelState,
  panelAct,
  panelSnapshot,
  serviceMismatch,
  serviceSession,
  serviceStatus,
  servicesLast,
  startService,
  tunnelState,
  type PanelAction,
  type PanelView,
  type ServiceStatus,
  type ServicesSnapshot,
  type Session,
} from "../lib/api";
import { statusView } from "../lib/statusView";
import { update, watchUpdates } from "../lib/update.svelte";
import { nextReceived, pickNotice, type Received } from "./format";

export const panel = $state({
  view: null as PanelView | null,
  status: null as ServiceStatus | null,
  session: null as Session | null,
  tunnelOk: null as boolean | null,
  services: null as ServicesSnapshot | null,
  /** Служба ответила хотя бы раз: до этого «не запущена» не показываем. */
  polled: false,
  /** Служба другой версии (прерванное обновление): запуск не поможет. */
  mismatch: false,
  /** Действие, которое выполняется (подключение, смена режима или сервера). */
  acting: null as PanelAction | null,
  /** Службу запускают кнопкой. */
  starting: false,
  /** Ошибка запуска службы. */
  error: null as string | null,
  /** Секунды сеанса от последнего ответа службы. */
  received: { secs: 0, at: 0 } as Received,
});

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

let inFlight = false;
let again = false;

/** Перечитать всё. Запросы не накладываются: пока идёт один, следующий ждёт. */
export async function refresh(): Promise<void> {
  if (inFlight) {
    again = true;
    return;
  }
  inFlight = true;
  try {
    const [view, status] = await Promise.all([
      panelSnapshot().catch(() => null),
      serviceStatus().catch(() => null),
    ]);
    if (view) panel.view = view;
    panel.status = status;
    const running = status?.state === "connected" || status?.state === "zapret";
    const [session, tunnel, mismatch, services] = await Promise.all([
      running ? serviceSession().catch(() => null) : null,
      tunnelState().catch(() => null),
      status === null ? serviceMismatch().catch(() => false) : false,
      servicesLast().catch(() => null),
    ]);
    if (session) panel.received = nextReceived(panel.received, session.secs, performance.now());
    panel.session = session;
    panel.tunnelOk = tunnel;
    panel.mismatch = mismatch;
    if (services) panel.services = services;
    panel.polled = true;
  } finally {
    inFlight = false;
    if (again) {
      again = false;
      void refresh();
    }
  }
}

/** Сколько действий идёт: второе «Подключить» во время подключения — это отмена. */
let acting = 0;

/** Действие панели — пункт меню трея. Ошибку показывает Rust уведомлением Windows. */
export async function act(id: PanelAction): Promise<void> {
  if (acting > 0 && id !== "toggle") return;
  acting += 1;
  panel.acting ??= id;
  try {
    await panelAct(id);
  } catch {
    // Уведомление об ошибке уже показано.
  } finally {
    acting -= 1;
    if (acting === 0) panel.acting = null;
  }
  await refresh();
}

/** «Запустить службу»: право на запуск выдаёт установщик. */
export async function startServiceNow(): Promise<void> {
  if (panel.starting) return;
  panel.starting = true;
  panel.error = null;
  try {
    await startService();
  } catch (e) {
    panel.error = message(e);
  } finally {
    panel.starting = false;
  }
  await refresh();
}

/** Что работает на самом деле: VPN или только zapret. */
export const running = () => panel.status?.state === "connected" || panel.status?.state === "zapret";

/** Идёт подключение или переподключение, которое начала панель. Подключение — «Подключить»
 *  без работающего VPN; переподключение — смена режима, сервера или kill switch при работающем. */
export const busy = () => panel.acting !== null && (panel.acting === "toggle" ? !running() : running());

/** Вид статуса: общая функция с карточкой главного окна. */
export const status = () =>
  statusView({
    status: panel.status,
    tunnelOk: panel.tunnelOk,
    busy: busy(),
    serviceDown: panel.polled && panel.status === null,
    starting: panel.starting,
    mismatch: panel.mismatch,
  });

/** Напоминание: новая версия (если «Позже» на плашке окна не нажимали) или срок подписки. */
export const notice = () => pickNotice(update.banner ? update.version : null, panel.view?.subscription ?? null, Date.now() / 1000);

/** Подписки на события и опрос; возвращает отписку. */
export function start(): () => void {
  void refresh();
  const timer = setInterval(() => void refresh(), 3000);
  // Окно живёт минуту после закрытия: показываясь снова, данные могли устареть —
  // читаем сразу, не дожидаясь ближайшего опроса.
  const onVisible = () => {
    if (!document.hidden) void refresh();
  };
  document.addEventListener("visibilitychange", onVisible);
  const offs = [
    watchUpdates(),
    onChoiceChanged(() => void refresh()),
    onSubscriptionsChanged(() => void refresh()),
    onTunnelState(() => void refresh()),
    onServices((s) => (panel.services = s)),
  ];
  return () => {
    clearInterval(timer);
    document.removeEventListener("visibilitychange", onVisible);
    for (const off of offs) off();
  };
}
