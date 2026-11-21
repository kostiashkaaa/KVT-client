// Подписки и ручные ключи: общий список групп, его восстановление из Rust (`snapshot`) и
// согласованность с выбором и подключением — выбранный сервер исчез, окно выбирает другой.
// Проверки серверов — `ServerChecks`; ошибки показывает окно (`initSubscriptions`).

import {
  type Group,
  onChoiceChanged,
  onSubscriptionsChanged,
  serviceStatus,
  snapshot,
} from "./api";
import { choice, applyChoice } from "./choiceStore.svelte";
import { conn, routingKey, settingsKey, zapretKey } from "./connectionStore.svelte";
import { ServerChecks } from "./serverChecks.svelte";

/** Все подписки и ручные ключи — группами в одном списке. */
export const subs = $state({
  groups: [] as Group[],
});

const firstKey = () => subs.groups.find((g) => g.servers.length > 0)?.servers[0]?.key ?? null;

/** Выбранный сервер из списка. */
export const selectedServer = () =>
  subs.groups.flatMap((g) => g.servers).find((s) => s.key === choice.selected) ?? null;

/** Есть ли хоть один сервер (подсказки первого запуска уже позади). */
export const hasServers = () => subs.groups.some((g) => g.servers.length > 0);

type Handlers = {
  /** Ошибка действия: одна на окно (новая заменяет прежнюю). */
  failed(e: unknown): void;
};

let handlers: Handlers = { failed: () => {} };

/** Ошибки показывает окно — передаёт свой обработчик. */
export function initSubscriptions(h: Handlers) {
  handlers = h;
}

/** Пинг и проверка серверов, обновление подписки, удаление ключей (serverChecks.svelte.ts). */
export const checks = new ServerChecks({
  groups: () => subs.groups,
  failed: (e) => handlers.failed(e),
  reloadGroups,
});

/** Окно могло быть закрыто (WebView выгружен) — восстанавливаем состояние из Rust. */
export async function loadSnapshot() {
  try {
    const snap = await snapshot();
    subs.groups = snap.groups;
    if (snap.choice) applyChoice(snap.choice, firstKey());
    else {
      choice.selected = firstKey();
      choice.onboarded = false;
    }
    // Подписки уже есть (KVT пользовались до подсказок) — первый запуск позади.
    if (hasServers()) choice.onboarded = true;
    void checks.autoPing();
  } finally {
    choice.restored = true;
  }
}

/** Перечитать список из Rust: подписка добавилась, обновилась в фоне или удалена. */
export async function reloadGroups() {
  const snap = await snapshot();
  subs.groups = snap.groups;
  // Выбранный сервер исчез (подписку удалили или провайдер убрал сервер). Если были
  // подключены к нему, Rust уже отключил VPN и сообщил об этом, — к первому
  // серверу другой подписки не переподключаемся.
  const exists = (key: string | null) => subs.groups.some((g) => g.servers.some((s) => s.key === key));
  if (exists(choice.selected)) return;
  // Ключ изменили (новая ссылка с другим адресом) — Rust уже перевёл выбор на
  // новый ключ: берём его, а не первый сервер списка.
  if (exists(snap.choice?.server ?? null)) {
    const next = snap.choice?.server ?? null;
    // Переподключение с новой ссылкой Rust делает сам — окно второй раз не нужно.
    if (conn.connectedWith && conn.connectedWith.server === choice.selected)
      conn.connectedWith = { ...conn.connectedWith, server: next };
    choice.selected = next;
    return;
  }
  conn.connectedWith = null;
  conn.status = await serviceStatus().catch(() => null);
  choice.selected = firstKey();
}

/** Сервер или режим сменились не из окна: автопереключение или профиль сети.
 *  Вызывается из окна — эффекту нужен его контекст. */
export function watchExternalChoice() {
  $effect(() =>
    onChoiceChanged(() => {
      void snapshot().then((snap) => {
        subs.groups = snap.groups;
        if (!snap.choice) return;
        applyChoice(snap.choice, firstKey());
        // Автопереключение уже подключилось к новому серверу, профиль сети сам
        // переподключил с новым режимом, автоподбор zapret сам перезапустил службу
        // с новой стратегией — второй раз из окна не нужно.
        if (conn.connectedWith)
          conn.connectedWith = {
            server: snap.choice.server,
            mode: choice.mode,
            zapret: zapretKey(),
            routing: routingKey(),
            settings: settingsKey(),
          };
      });
    }),
  );
}

/** Подписка добавлена, обновилась в фоне или удалена. Вызывается из окна — эффекту
 *  нужен его контекст. */
export function watchSubscriptions() {
  $effect(() => onSubscriptionsChanged(() => void reloadGroups()));
}
