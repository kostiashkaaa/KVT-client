<script lang="ts">
  import { slide } from "svelte/transition";
  import Icon from "./Icon.svelte";
  import Flag from "./Flag.svelte";
  import type { Group, Outcome, QuickResult, ServerSummary, SubscriptionInfo } from "./api";

  let {
    groups,
    selected = $bindable(),
    results,
    checking,
    oncheck,
    outcomes,
    fullChecking,
    fullCheckBlocked = null,
    onfullcheck,
    refreshing,
    onrefresh,
    onadd,
  }: {
    groups: Group[];
    /** Ключ выбранного сервера. */
    selected: string | null;
    results: Record<string, QuickResult>;
    /** Группа, которую сейчас пингуют. */
    checking: string | null;
    oncheck: (group: string) => void;
    /** Итоги полной проверки (приходят по одному). */
    outcomes: Record<string, Outcome>;
    /** Группа, которую сейчас проверяют полностью. */
    fullChecking: string | null;
    /** Причина, по которой полную проверку сейчас запустить нельзя. */
    fullCheckBlocked?: string | null;
    onfullcheck: (group: string) => void;
    refreshing: string | null;
    onrefresh: (group: string) => void;
    onadd: () => void;
  } = $props();

  type Cell = { text: string; tone: "" | "good" | "bad" | "muted" | "warn"; hint: string };

  function outcomeCell(o: Outcome): Cell {
    if (o.kind === "deferred") {
      return {
        text: "позже",
        tone: "muted",
        hint: `Не проверялся, чтобы не вызвать заморозку у провайдера. Повторите через ${Math.ceil(o.retry_after_secs / 60)} мин`,
      };
    }
    const ms = o.latency_ms != null ? `${o.latency_ms} мс` : "";
    switch (o.verdict) {
      case "works":
        return { text: ms || "работает", tone: "good", hint: "Работает: отклик через туннель и загрузка 200 КБ" };
      case "slow":
        return { text: ms || "медленно", tone: "warn", hint: "Работает, но отвечает медленно" };
      case "data_frozen":
        return { text: "режет DPI", tone: "bad", hint: "Соединение обрывается после первых килобайт — провайдер режет этот сервер" };
      case "tls_frozen":
        return { text: "заморожен", tone: "bad", hint: "Провайдер притормозил соединение — попробуйте позже или другой сервер" };
      case "unreachable":
        return { text: "нет связи", tone: "bad", hint: "Сервер недоступен — возможно, заблокирован его IP" };
      case "dns_failed":
        return { text: "DNS", tone: "bad", hint: "Не удалось найти адрес сервера" };
      case "rejected":
        return { text: "отклонён", tone: "bad", hint: "Сервер отклонил подключение — возможно, подписка устарела" };
      case "config_error":
        return { text: "не поддерж.", tone: "muted", hint: "Этот сервер не поддерживается ядром KVT" };
    }
  }

  function latency(r: QuickResult | undefined): Cell {
    switch (r?.kind) {
      case "reachable":
        return {
          text: `${r.latency_ms} мс`,
          tone: r.latency_ms < 300 ? "good" : "",
          hint: "Время TCP-соединения до сервера",
        };
      case "unreachable":
        return { text: "нет связи", tone: "bad", hint: "Сервер не принимает соединения — возможно, его IP заблокирован" };
      case "dns_failed":
        return { text: "DNS", tone: "bad", hint: "Не удалось найти адрес сервера" };
      case "not_applicable":
        return { text: "UDP", tone: "muted", hint: "Hysteria2 работает по UDP — проверяется только при подключении" };
      default:
        return { text: "—", tone: "muted", hint: "" };
    }
  }

  function cell(group: string, key: string): Cell {
    const o = outcomes[key];
    if (o) return outcomeCell(o);
    if (fullChecking === group || checking === group) return { text: "…", tone: "muted", hint: "Проверяется" };
    return latency(results[key]);
  }

  function label(s: ServerSummary): string {
    const parts = [s.protocol, s.transport, s.security].filter((p) => p && p !== "none" && p !== "tcp");
    return parts.join(" · ");
  }

  const GB = 2 ** 30;
  const gb = (bytes: number) => (bytes / GB).toLocaleString("ru-RU", { maximumFractionDigits: 1 });

  function usage(m: SubscriptionInfo): string | null {
    if (m.usedBytes == null || !m.totalBytes) return null;
    return `${gb(m.usedBytes)} из ${gb(m.totalBytes)} ГБ`;
  }

  /** «34 из 100 ГБ · до 19 декабря»; срок подсвечивается, когда кончается. */
  function metaParts(m: SubscriptionInfo): { text: string; soon: boolean }[] {
    const used = usage(m);
    const exp = expiry(m);
    return [...(used ? [{ text: used, soon: false }] : []), ...(exp ? [exp] : [])];
  }

  function expiry(m: SubscriptionInfo): { text: string; soon: boolean } | null {
    if (m.expire == null) return null;
    const days = Math.ceil((m.expire * 1000 - Date.now()) / 86_400_000);
    if (days < 0) return { text: "закончилась", soon: true };
    if (days === 0) return { text: "заканчивается сегодня", soon: true };
    const date = new Date(m.expire * 1000).toLocaleDateString("ru-RU", { day: "numeric", month: "long" });
    return { text: `до ${date}`, soon: days <= 3 };
  }

  // Свёрнутые группы запоминаются на этом компьютере (только вид, не настройка).
  const COLLAPSED_KEY = "kvt.collapsed";
  function loadCollapsed(): string[] {
    try {
      const v: unknown = JSON.parse(localStorage.getItem(COLLAPSED_KEY) ?? "[]");
      return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
    } catch {
      return [];
    }
  }
  let collapsed = $state<string[]>(loadCollapsed());
  function toggle(id: string) {
    collapsed = collapsed.includes(id) ? collapsed.filter((x) => x !== id) : [...collapsed, id];
    try {
      localStorage.setItem(COLLAPSED_KEY, JSON.stringify(collapsed));
    } catch {
      /* хранилище недоступно — просто не запомним */
    }
  }

  const total = $derived(groups.reduce((n, g) => n + g.servers.length, 0));

  /** Поиск появляется, когда серверов много; ищет сразу во всех группах. */
  const SEARCH_FROM = 8;
  let query = $state("");
  const searching = $derived(query.trim().length > 0);
  const visible = $derived.by(() => {
    const q = query.trim().toLowerCase();
    return groups
      .map((g) => ({ g, servers: q ? g.servers.filter((s) => s.name.toLowerCase().includes(q)) : g.servers }))
      .filter(({ servers }) => !q || servers.length > 0);
  });
  const found = $derived(visible.reduce((n, v) => n + v.servers.length, 0));
</script>

<section class="card list">
  <header class="toolbar">
    <h2>Серверы</h2>
    <span class="caption">{total}</span>
    {#if total > SEARCH_FROM}
      <input
        class="search"
        type="search"
        placeholder="Поиск по всем подпискам"
        aria-label="Поиск сервера"
        autocomplete="off"
        spellcheck="false"
        bind:value={query}
      />
      {#if searching}<span class="caption">{found} из {total}</span>{/if}
    {/if}
    <button class="btn add" onclick={onadd} title="Добавить подписку или ключ" aria-label="Добавить подписку или ключ">
      <Icon name="plus" size={16} />
    </button>
  </header>

  {#if searching && visible.length === 0}
    <p class="empty caption">Ничего не найдено</p>
  {/if}

  {#each visible as { g, servers } (g.id)}
    {@const open = searching || !collapsed.includes(g.id)}
    <div class="group">
      <div class="group-head">
        <button class="toggle" aria-expanded={open} onclick={() => toggle(g.id)} disabled={searching}>
          <span class="chevron" class:closed={!open}><Icon name="chevron" size={16} /></span>
          <span class="group-title">{g.title}</span>
          <span class="caption">{g.servers.length}</span>
        </button>
        <span class="caption meta">
          {#each metaParts(g.meta) as part, i (i)}{#if i > 0}{" · "}{/if}<span class:soon={part.soon}
              >{part.text}</span
            >{/each}
        </span>
        <div class="group-actions">
          {#if g.byUrl}
            <button
              class="btn ghost"
              disabled={refreshing !== null}
              onclick={() => onrefresh(g.id)}
              title="Обновить подписку"
              aria-label={`Обновить ${g.title}`}
            >
              <span class:spin={refreshing === g.id}><Icon name="refresh" size={16} /></span>
            </button>
          {/if}
          <!-- Подпись не меняется, поверх неё крутится кольцо — кнопки не прыгают. -->
          <button
            class="btn ghost"
            class:busy={checking === g.id}
            disabled={checking !== null || fullChecking !== null}
            onclick={() => oncheck(g.id)}
            title="Пинг: только TCP-соединение, без TLS — не привлекает внимание DPI"
          >
            Пинг
          </button>
          <button
            class="btn ghost"
            class:busy={fullChecking === g.id}
            disabled={checking !== null || fullChecking !== null || fullCheckBlocked !== null}
            onclick={() => onfullcheck(g.id)}
            title={fullCheckBlocked ??
              "Подключается к каждому серверу и скачивает 200 КБ. Серверы с одинаковым SNI проверяются по очереди, чтобы не вызвать заморозку у провайдера"}
          >
            Проверить
          </button>
        </div>
      </div>

      {#if open}
        <!-- Большие группы раскрываются сразу: анимация высоты длинного списка нагружала бы окно. -->
        <div class="group-body" transition:slide={{ duration: servers.length > 40 ? 0 : 180 }}>
        {#if g.meta.announce}
          <!-- Текст провайдера выводится только как текст, без разметки. -->
          <p class="announce">{g.meta.announce}</p>
        {/if}
        <ul role="listbox" aria-label={g.title}>
          {#each servers as s (s.key)}
            {@const l = cell(g.id, s.key)}
            <li>
              <button
                class="row"
                role="option"
                aria-selected={selected === s.key}
                class:selected={selected === s.key}
                onclick={() => (selected = s.key)}
              >
                <span class="radio" aria-hidden="true"></span>
                <Flag code={s.flag} />
                <span class="name">{s.name}</span>
                <!-- Ячейка есть всегда, чтобы колонки сетки не съезжали. -->
                <span class="warn">
                  {#if s.fingerprintAdvice && s.fingerprintAdvice !== "ok"}
                    <span
                      class="warn-icon"
                      role="img"
                      aria-label="Подозрительный отпечаток TLS"
                      title="Отпечаток TLS этого сервера чаще попадает под подозрение у ТСПУ. Попросите провайдера сменить fp на firefox или edge."
                    >
                      <Icon name="warning" size={16} />
                    </span>
                  {/if}
                </span>
                <span class="tag">{label(s)}</span>
                <!-- Новый итог проверки проявляется, а не подменяет прежний скачком. -->
                {#key l.text}
                  <span class="latency {l.tone}" title={l.hint}>{l.text}</span>
                {/key}
              </button>
            </li>
          {/each}
        </ul>
        {#if g.errors > 0}
          <p class="caption skipped">Пропущено строк с ошибками: {g.errors}</p>
        {/if}
        </div>
      {/if}
    </div>
  {/each}
</section>

<style>
  .list {
    padding-bottom: var(--space-2);
  }

  /* Панель с поиском и «+» остаётся на месте, пока прокручивается длинный список. */
  .toolbar {
    position: sticky;
    /* Прилипает к краю окна, а не к отступу страницы: сверху ничего не просвечивает. */
    top: calc(-1 * var(--page-pad-top, 0px));
    z-index: 1;
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-4) var(--space-5) var(--space-3);
    border-bottom: 1px solid var(--stroke);
    border-radius: var(--radius-m) var(--radius-m) 0 0;
    background: var(--surface);
  }

  .search {
    flex: 1;
    min-width: 0;
    max-width: 320px;
    height: 30px;
    margin-left: var(--space-3);
    padding: 0 var(--space-3);
    border: 1px solid var(--stroke);
    border-bottom-color: var(--text-3);
    border-radius: var(--radius-s);
    background: var(--surface);
    user-select: text;
    transition: border-color var(--dur-fast) var(--ease);
  }

  /* Акцентная линия снизу без изменения высоты поля. */
  .search:focus {
    outline: none;
    border-bottom-color: var(--accent);
    box-shadow: inset 0 -1px 0 var(--accent);
  }

  .add {
    width: 32px;
    margin-left: auto;
    padding: 0;
  }

  .empty {
    margin: 0;
    padding: var(--space-4) var(--space-5);
  }

  .group + .group {
    border-top: 1px solid var(--stroke);
  }

  .group-head {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-2) var(--space-3) var(--space-1) var(--space-2);
  }

  .toggle {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    min-width: 0;
    height: 32px;
    padding: 0 var(--space-2);
    border: 0;
    border-radius: var(--radius-s);
    background: transparent;
    cursor: pointer;
  }

  .toggle:hover:not(:disabled) {
    background: var(--surface-hover);
  }

  .toggle {
    transition: background-color var(--dur-fast) var(--ease);
  }

  .toggle:disabled {
    cursor: default;
  }

  .chevron {
    display: inline-flex;
    color: var(--text-2);
    transition: transform var(--dur) var(--ease);
  }

  .chevron.closed {
    transform: rotate(-90deg);
  }

  .group-title {
    overflow: hidden;
    font-weight: 600;
    white-space: nowrap;
    text-overflow: ellipsis;
  }

  .meta {
    overflow: hidden;
    white-space: nowrap;
    text-overflow: ellipsis;
  }

  .soon {
    color: var(--warn);
  }

  .group-actions {
    display: flex;
    flex: none;
    gap: var(--space-1);
    margin-left: auto;
  }

  .btn.ghost {
    min-height: 28px;
    border-color: transparent;
    background: transparent;
    color: var(--text-2);
  }

  .btn.ghost:hover:not(:disabled) {
    background: var(--surface-hover);
    color: var(--text);
  }

  .spin {
    display: inline-flex;
    animation: spin 900ms linear infinite;
  }

  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }

  .announce {
    margin: 0 var(--space-5) var(--space-2);
    padding: var(--space-2) var(--space-3);
    border-radius: var(--radius-s);
    background: var(--accent-subtle);
    white-space: pre-line;
  }

  .skipped {
    margin: 0;
    padding: 0 var(--space-5) var(--space-2);
  }

  ul {
    margin: 0;
    padding: 0 var(--space-2) var(--space-2);
    list-style: none;
  }

  .row {
    display: grid;
    grid-template-columns: 16px 20px 1fr auto auto 72px;
    align-items: center;
    gap: var(--space-3);
    width: 100%;
    min-height: 40px;
    padding: 0 var(--space-3);
    border: 0;
    border-radius: var(--radius-s);
    background: transparent;
    text-align: left;
    cursor: pointer;
    transition: background-color var(--dur-fast) var(--ease);
  }

  .row:hover {
    background: var(--surface-hover);
  }

  .row:active {
    background: var(--surface-pressed);
  }

  .row.selected {
    background: var(--accent-subtle);
  }

  /* Радиокнопка: точка выбора «наливается» плавно. */
  .radio {
    width: 14px;
    height: 14px;
    border: 1px solid var(--stroke-strong);
    border-radius: 50%;
    transition:
      border-width var(--dur-fast) var(--ease),
      border-color var(--dur-fast) var(--ease);
  }

  .selected .radio {
    border: 4px solid var(--accent);
  }

  /* Эмодзи в названиях (⚡, 🚀) — цветным шрифтом Windows. */
  .name {
    overflow: hidden;
    font-family: var(--font), "Segoe UI Emoji";
    white-space: nowrap;
    text-overflow: ellipsis;
  }

  .warn,
  .warn-icon {
    display: inline-flex;
    min-width: 16px;
    color: var(--warn);
  }

  .tag {
    font-size: 12px;
    color: var(--text-2);
    text-transform: uppercase;
    letter-spacing: 0.02em;
  }

  .latency {
    font-size: 12px;
    text-align: right;
    white-space: nowrap;
    font-variant-numeric: tabular-nums;
    color: var(--text-2);
    animation: kvt-fade var(--dur) var(--ease) backwards;
  }

  .latency.good {
    color: var(--ok);
  }

  .latency.bad {
    color: var(--danger);
  }

  .latency.warn {
    color: var(--warn);
  }

  .latency.muted {
    color: var(--text-3);
  }

  @media (max-width: 720px) {
    .group-head {
      flex-wrap: wrap;
    }

    .meta {
      order: 3;
      width: 100%;
      padding-left: var(--space-8);
    }

    .tag {
      display: none;
    }

    .row {
      grid-template-columns: 16px 20px 1fr auto 64px;
    }
  }
</style>
