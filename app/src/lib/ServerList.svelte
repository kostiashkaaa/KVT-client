<script lang="ts">
  import Icon from "./Icon.svelte";
  import type { Outcome, QuickResult, ServerSummary, SubscriptionInfo } from "./api";

  let {
    title,
    meta = null,
    servers,
    selected = $bindable(),
    results = null,
    checking = false,
    oncheck,
    outcomes = null,
    fullChecking = false,
    fullCheckBlocked = null,
    onfullcheck,
  }: {
    title: string;
    meta?: SubscriptionInfo | null;
    servers: ServerSummary[];
    selected: number | null;
    results?: QuickResult[] | null;
    checking?: boolean;
    oncheck: () => void;
    /** Результаты полной проверки (приходят по одному). */
    outcomes?: (Outcome | null)[] | null;
    fullChecking?: boolean;
    /** Причина, по которой полную проверку сейчас запустить нельзя. */
    fullCheckBlocked?: string | null;
    onfullcheck: () => void;
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

  function cell(i: number): Cell {
    const o = outcomes?.[i];
    if (o) return outcomeCell(o);
    if (fullChecking || checking) return { text: "…", tone: "muted", hint: "Проверяется" };
    return latency(results?.[i]);
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

  const GB = 2 ** 30;
  const usedShare = $derived(
    meta?.usedBytes != null && meta.totalBytes ? Math.min(1, meta.usedBytes / meta.totalBytes) : null,
  );
  const daysLeft = $derived(
    meta?.expire != null ? Math.ceil((meta.expire * 1000 - Date.now()) / 86_400_000) : null,
  );

  function gb(bytes: number): string {
    return (bytes / GB).toLocaleString("ru-RU", { maximumFractionDigits: 1 });
  }

  function expiryText(days: number): string {
    if (days < 0) return "Подписка закончилась";
    if (days === 0) return "Заканчивается сегодня";
    const date = new Date((meta?.expire ?? 0) * 1000).toLocaleDateString("ru-RU", { day: "numeric", month: "long" });
    return `До ${date}`;
  }

  /** Поиск появляется, когда серверов много. */
  const SEARCH_FROM = 8;
  let query = $state("");
  const visible = $derived.by(() => {
    const q = query.trim().toLowerCase();
    const all = servers.map((s, i) => ({ s, i }));
    return q ? all.filter(({ s }) => s.name.toLowerCase().includes(q)) : all;
  });

  function label(s: ServerSummary): string {
    const parts = [s.protocol, s.transport, s.security].filter((p) => p && p !== "none" && p !== "tcp");
    return parts.join(" · ");
  }
</script>

<section class="card list">
  <header>
    <div class="title-row">
      <h2>{title}</h2>
      <span class="caption">{servers.length} серв.</span>
      <button
        class="btn check"
        disabled={checking || fullChecking}
        onclick={oncheck}
        title="Пинг: только TCP-соединение, без TLS — не привлекает внимание DPI"
      >
        {checking ? "Пинг…" : "Пинг"}
      </button>
      <button
        class="btn"
        disabled={checking || fullChecking || fullCheckBlocked !== null}
        onclick={onfullcheck}
        title={fullCheckBlocked ??
          "Подключается к каждому серверу и скачивает 200 КБ. Серверы с одинаковым SNI проверяются по очереди, чтобы не вызвать заморозку у провайдера"}
      >
        {fullChecking ? "Проверка…" : "Полная проверка"}
      </button>
    </div>
    {#if meta && (usedShare !== null || daysLeft !== null)}
      <div class="usage">
        {#if usedShare !== null && meta.usedBytes != null && meta.totalBytes}
          <div
            class="bar"
            class:warn={usedShare > 0.9}
            role="meter"
            aria-label="Израсходовано трафика"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={Math.round(usedShare * 100)}
          >
            <span style:width={`${usedShare * 100}%`}></span>
          </div>
          <span class="caption">{gb(meta.usedBytes)} из {gb(meta.totalBytes)} ГБ</span>
        {/if}
        {#if daysLeft !== null}
          <span class="caption" class:expiring={daysLeft <= 3}>{expiryText(daysLeft)}</span>
        {/if}
      </div>
    {/if}
    {#if servers.length > SEARCH_FROM}
      <div class="search">
        <input
          type="search"
          placeholder="Поиск по названию"
          aria-label="Поиск сервера"
          autocomplete="off"
          spellcheck="false"
          bind:value={query}
        />
        {#if query.trim()}
          <span class="caption">{visible.length} из {servers.length}</span>
        {/if}
      </div>
    {/if}
  </header>

  <ul role="listbox" aria-label={title}>
    {#if visible.length === 0}
      <li class="empty caption">Ничего не найдено</li>
    {/if}
    {#each visible as { s, i } (i)}
      {@const l = cell(i)}
      <li>
        <button class="row" role="option" aria-selected={selected === i} class:selected={selected === i} onclick={() => (selected = i)}>
          <span class="radio" aria-hidden="true"></span>
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
          <span class="latency {l.tone}" title={l.hint}>{l.text}</span>
        </button>
      </li>
    {/each}
  </ul>
</section>

<style>
  /* Заголовок с кнопками остаётся на месте, пока прокручивается длинный список. */
  header {
    position: sticky;
    top: 0;
    z-index: 1;
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    padding: var(--space-4) var(--space-5) var(--space-2);
    border-radius: var(--radius-m) var(--radius-m) 0 0;
    background: var(--surface);
  }

  .search {
    display: flex;
    align-items: center;
    gap: var(--space-3);
  }

  .search input {
    flex: 1;
    max-width: 320px;
    height: 30px;
    padding: 0 var(--space-3);
    border: 1px solid var(--stroke);
    border-bottom-color: var(--text-3);
    border-radius: var(--radius-s);
    background: var(--surface);
    user-select: text;
  }

  .search input:focus {
    outline: none;
    border-bottom: 2px solid var(--accent);
  }

  .empty {
    padding: var(--space-3);
  }

  .title-row {
    display: flex;
    align-items: center;
    gap: var(--space-3);
  }

  .title-row .caption {
    white-space: nowrap;
  }

  .title-row .btn {
    min-height: 28px;
  }

  .check {
    margin-left: auto;
  }

  .usage {
    display: flex;
    align-items: center;
    gap: var(--space-3);
  }

  .bar {
    flex: 0 1 200px;
    height: 4px;
    border-radius: 2px;
    background: var(--stroke);
    overflow: hidden;
  }

  .bar span {
    display: block;
    height: 100%;
    background: var(--accent);
  }

  .bar.warn span {
    background: var(--warn);
  }

  .expiring {
    color: var(--warn);
  }

  ul {
    margin: 0;
    padding: 0 var(--space-2) var(--space-2);
    list-style: none;
  }

  .row {
    display: grid;
    grid-template-columns: 16px 1fr auto auto 72px;
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
  }

  .row:hover {
    background: var(--surface-hover);
  }

  .row.selected {
    background: var(--accent-subtle);
  }

  .radio {
    width: 14px;
    height: 14px;
    border: 1px solid var(--stroke-strong);
    border-radius: 50%;
  }

  .selected .radio {
    border: 4px solid var(--accent);
  }

  .name {
    overflow: hidden;
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
</style>
