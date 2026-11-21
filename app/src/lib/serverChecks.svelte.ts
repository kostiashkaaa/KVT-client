// Пинг и проверка серверов на главной: что показано в колонке задержки и значках проверки,
// какая подписка сейчас проверяется или обновляется. Список подписок (`groups`) и показ
// ошибки остаются у окна — они приходят через `deps`.

import {
  fullCheck,
  quickCheck,
  refreshSubscription,
  removeServer,
  type Group,
  type Outcome,
  type QuickResult,
} from "./api";
import { dismissKey } from "./notices.svelte";

/** Пинг при открытии окна — только для небольших списков. */
const AUTO_PING_MAX = 200;

export class ServerChecks {
  /** Быстрый пинг: итог по ключам серверов. */
  results = $state<Record<string, QuickResult>>({});
  /** Подписка, у которой идёт пинг. */
  checking = $state<string | null>(null);
  /** Итоги полной проверки по ключам серверов. */
  outcomes = $state<Record<string, Outcome>>({});
  /** Подписка, у которой идёт полная проверка. */
  fullChecking = $state<string | null>(null);
  /** Подписка, которая обновляется. */
  refreshing = $state<string | null>(null);

  private deps: {
    groups: () => Group[];
    failed: (e: unknown) => void;
    reloadGroups: () => Promise<void>;
  };

  constructor(deps: {
    /** Все подписки и ручные ключи. */
    groups: () => Group[];
    /** Показать ошибку действия. */
    failed: (e: unknown) => void;
    /** Перечитать список из Rust. */
    reloadGroups: () => Promise<void>;
  }) {
    this.deps = deps;
  }

  /** Пинг при открытии окна: колонка задержки сразу заполнена, а не «—».
   *  Только TCP без TLS (DPI не замечает) и только для небольших списков. */
  autoPing = async () => {
    const groups = this.deps.groups();
    if (groups.reduce((n, g) => n + g.servers.length, 0) > AUTO_PING_MAX) return;
    for (const g of groups) {
      if (g.servers.length === 0 || this.checking !== null || this.fullChecking !== null) continue;
      this.checking = g.id;
      try {
        this.results = { ...this.results, ...(await quickCheck(g.id)) };
      } catch {
        /* служба не ответила — пользователь нажмёт «Пинг» сам */
      } finally {
        this.checking = null;
      }
    }
  };

  check = async (group: string) => {
    this.checking = group;
    // Итог прошлой «Проверить» закрывал бы свежий пинг: цифры не менялись бы.
    const keys = new Set(this.deps.groups().find((g) => g.id === group)?.servers.map((s) => s.key));
    this.outcomes = Object.fromEntries(Object.entries(this.outcomes).filter(([k]) => !keys.has(k)));
    try {
      this.results = { ...this.results, ...(await quickCheck(group)) };
    } catch (e) {
      this.deps.failed(e);
    } finally {
      this.checking = null;
    }
  };

  runFullCheck = async (group: string) => {
    this.fullChecking = group;
    dismissKey("error");
    const keys = new Set(this.deps.groups().find((g) => g.id === group)?.servers.map((s) => s.key));
    this.outcomes = Object.fromEntries(Object.entries(this.outcomes).filter(([k]) => !keys.has(k)));
    try {
      await fullCheck(group, (key, o) => {
        this.outcomes[key] = o;
      });
    } catch (e) {
      this.deps.failed(e);
    } finally {
      this.fullChecking = null;
    }
  };

  refresh = async (group: string) => {
    this.refreshing = group;
    dismissKey("error");
    try {
      await refreshSubscription(group);
      await this.deps.reloadGroups();
    } catch (e) {
      this.deps.failed(e);
    } finally {
      this.refreshing = null;
    }
  };

  /** Ключ из группы «Добавлено вручную». Если VPN шёл через него, Rust уже отключил
   *  VPN и сообщил об этом; `reloadGroups` выберет другой сервер. */
  removeKey = async (key: string) => {
    try {
      await removeServer(key);
      await this.deps.reloadGroups();
    } catch (e) {
      this.deps.failed(e);
    }
  };
}
