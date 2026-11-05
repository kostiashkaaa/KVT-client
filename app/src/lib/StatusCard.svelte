<script lang="ts">
  import Flag from "./Flag.svelte";
  import {
    formatBytes,
    formatElapsed,
    strategyTitle,
    type Mode,
    type ServerSummary,
    type ServiceStatus,
    type Session,
  } from "./api";

  let {
    server,
    mode = $bindable(),
    busy,
    status,
    session,
    tunnelOk,
    serviceDown = false,
    onconnect,
    ondisconnect,
    onwhy,
    onstartservice,
  }: {
    server: ServerSummary | null;
    mode: Mode;
    busy: boolean;
    status: ServiceStatus | null;
    /** Время и трафик с «Подключить» (служба отдаёт раз в несколько секунд). */
    session: Session | null;
    /** Идут ли данные через туннель (null — ещё не проверяли). */
    tunnelOk: boolean | null;
    /** Служба KVT не отвечает: вместо «Подключить» — «Запустить службу». */
    serviceDown?: boolean;
    onconnect: () => void;
    ondisconnect: () => void;
    onwhy: () => void;
    onstartservice?: () => void;
  } = $props();

  /** Работает только zapret, без VPN. */
  const zapretOnly = $derived(status?.state === "zapret" ? status : null);
  const connected = $derived(status?.state === "connected" || zapretOnly !== null);
  /** Сервер принял подключение, но данные через туннель не идут. */
  const noData = $derived(status?.state === "connected" && tunnelOk === false);
  const tone = $derived(
    busy || status?.state === "connecting"
      ? "pending"
      : noData
        ? "warn"
        : connected
          ? "on"
          : status?.state === "failed" || serviceDown
            ? "error"
            : "off",
  );
  const title = $derived(
    tone === "pending"
      ? "Подключение…"
      : zapretOnly
        ? "Zapret работает"
        : noData
          ? "Сайты не открываются"
          : connected
            ? "Подключено"
            : serviceDown
              ? "Служба KVT не запущена"
              : tone === "error"
                ? "Ошибка"
                : "Отключено",
  );
  // Служба отвечает раз в 3 с, а секунды тикают здесь: от последнего ответа.
  let received = $state({ secs: 0, at: 0 });
  let now = $state(performance.now());
  $effect(() => {
    if (!session) return;
    const at = performance.now();
    const estimate = received.secs + (at - received.at) / 1000;
    // Служба отдаёт целые секунды: ответ чуть позади своего счёта не должен
    // откатывать время назад. Сильно меньше — это новый сеанс.
    if (session.secs > estimate || session.secs < estimate - 3) received = { secs: session.secs, at };
  });
  const showSession = $derived(connected && session !== null && !busy);
  $effect(() => {
    if (!showSession) return;
    now = performance.now();
    const timer = setInterval(() => (now = performance.now()), 1000);
    return () => clearInterval(timer);
  });
  const elapsed = $derived(formatElapsed(received.secs + Math.max(0, now - received.at) / 1000));
  const traffic = $derived(
    session?.rx != null && session.tx != null ? { rx: formatBytes(session.rx), tx: formatBytes(session.tx) } : null,
  );
  const sessionTitle = $derived(
    traffic
      ? `Принято ${traffic.rx}, отправлено ${traffic.tx} с момента подключения — весь трафик через KVT, включая сайты, которые открываются напрямую`
      : "Время с момента подключения",
  );

  const coreName = $derived(status?.state === "connected" ? (status.core === "xray" ? "Xray" : "sing-box") : null);

  const modes: { id: Mode; label: string; hint: string }[] = [
    { id: "vpn", label: "VPN", hint: "Весь заблокированный трафик через VPN" },
    { id: "hybrid", label: "Гибрид", hint: "YouTube и Discord через zapret, остальное через VPN" },
    { id: "zapret", label: "Zapret", hint: "Без VPN: только обход DPI для YouTube и Discord" },
  ];
  const modeIndex = $derived(Math.max(0, modes.findIndex((m) => m.id === mode)));
</script>

<section class="card status" aria-live="polite">
  <div class="state">
    <span class="dot {tone}" aria-hidden="true"></span>
    <div class="text">
      <h2>{title}</h2>
      <p class="muted">
        {#if serviceDown}
          Без неё KVT не подключится. Обычно служба стартует вместе с Windows.
        {:else if zapretOnly}
          Стратегия {strategyTitle(zapretOnly.strategy)} · без VPN
        {:else if mode === "zapret" && !connected}
          Обход DPI без VPN — сервер не нужен
        {:else if server}
          <!-- Без флага — без пустого места перед названием. -->
          <span class="server"
            >{#if server.flag}<Flag code={server.flag} />{/if}<span class="name">{server.name}</span
            >{#if coreName}<span class="caption">· {coreName}</span>{/if}</span
          >
        {:else}
          Выберите сервер ниже
        {/if}
      </p>
      {#if showSession}
        <p class="caption session appear" title={sessionTitle}>
          <span>{elapsed}</span>
          {#if traffic}
            <span class="sep" aria-hidden="true">·</span>
            <span aria-label="Принято">↓&nbsp;{traffic.rx}</span>
            <span aria-label="Отправлено">↑&nbsp;{traffic.tx}</span>
          {/if}
        </p>
      {/if}
      {#if noData}
        <p class="caption warn-text appear">
          Сервер принял подключение, но данные через него не идут.
          <button class="why inline" onclick={onwhy}>Почему?</button>
        </p>
      {/if}
    </div>
  </div>

  <!-- Одна кнопка: при подключении цвет меняется плавно, а не скачком. -->
  {#if serviceDown && !connected}
    <button class="btn btn-primary connect" disabled={busy} onclick={onstartservice}>
      {#if busy}<span class="spinner" aria-hidden="true"></span>{/if}
      {busy ? "Запуск…" : "Запустить службу"}
    </button>
  {:else}
  <button
    class="btn connect"
    class:btn-primary={!connected}
    disabled={busy || (!connected && !server && mode !== "zapret")}
    onclick={connected ? ondisconnect : onconnect}
  >
    {#if busy}<span class="spinner" aria-hidden="true"></span>{/if}
    {connected ? "Отключить" : busy ? "Подключение…" : "Подключить"}
  </button>
  {/if}

  <div class="modes" role="radiogroup" aria-label="Режим работы" style:--i={modeIndex}>
    <span class="thumb" aria-hidden="true"></span>
    {#each modes as m (m.id)}
      <button
        role="radio"
        aria-checked={mode === m.id}
        class:selected={mode === m.id}
        title={m.hint}
        onclick={() => (mode = m.id)}
      >
        {m.label}
      </button>
    {/each}
  </div>
  <p class="caption hint">
    {modes.find((m) => m.id === mode)?.hint}
    <button class="why" onclick={onwhy}>Почему не работает?</button>
  </p>
</section>

<style>
  .status {
    display: grid;
    grid-template-columns: 1fr auto;
    align-items: center;
    gap: var(--space-4);
    padding: var(--space-5);
  }

  /* Точка стоит по центру строки заголовка, а не между двумя строками. */
  .state {
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
    min-width: 0;
  }

  .text {
    min-width: 0;
  }

  .state p {
    margin: 2px 0 0;
  }

  .server {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
    max-width: 100%;
    vertical-align: top;
  }

  .name {
    overflow: hidden;
    font-family: var(--font), "Segoe UI Emoji";
    white-space: nowrap;
    text-overflow: ellipsis;
  }

  .server .caption {
    flex: none;
  }

  /* Цифры одной ширины — строка не дрожит, когда тикают секунды. */
  .session {
    display: flex;
    gap: var(--space-2);
    margin-top: var(--space-1);
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
  }

  .session .sep {
    color: var(--text-3);
  }

  .dot {
    flex: none;
    width: 10px;
    height: 10px;
    margin-top: 6px;
    border-radius: 50%;
    background: var(--text-3);
    transition:
      background-color var(--dur) var(--ease),
      box-shadow var(--dur) var(--ease);
  }

  .dot.on {
    background: var(--ok);
    box-shadow: 0 0 0 4px var(--ok-subtle);
  }

  /* Подключение — мягкая пульсация вместо статичной точки. */
  .dot.pending {
    background: var(--warn);
    animation: kvt-pulse 1.2s ease-in-out infinite;
  }

  .dot.warn {
    background: var(--warn);
    box-shadow: 0 0 0 4px var(--warn-subtle);
  }

  .warn-text {
    margin-top: var(--space-1);
    color: var(--warn);
  }

  .why.inline {
    margin-left: var(--space-1);
  }

  .dot.error {
    background: var(--danger);
    box-shadow: 0 0 0 4px var(--danger-subtle);
  }

  .connect {
    min-width: 148px;
    height: 36px;
  }

  /* Сегменты одной ширины — подсветка выбранного плавно переезжает. */
  .modes {
    --w: 76px;
    position: relative;
    display: inline-grid;
    grid-template-columns: repeat(3, var(--w));
    justify-self: start;
    padding: 2px;
    border: 1px solid var(--stroke);
    border-radius: var(--radius-s);
    background: var(--bg);
  }

  .thumb {
    position: absolute;
    top: 2px;
    bottom: 2px;
    left: 2px;
    width: var(--w);
    border-radius: 3px;
    background: var(--accent-subtle);
    box-shadow: inset 0 0 0 1px var(--accent);
    transform: translateX(calc(var(--i) * 100%));
    transition: transform var(--dur) var(--ease);
  }

  .modes button {
    position: relative;
    height: 28px;
    border: 0;
    border-radius: 3px;
    background: transparent;
    cursor: pointer;
    transition:
      background-color var(--dur-fast) var(--ease),
      color var(--dur-fast) var(--ease);
  }

  .modes button:hover:not(.selected) {
    background: var(--surface-hover);
  }

  /* Выбранный вариант — акцентом: в тёмной теме фон почти не отличается. */
  .modes button.selected {
    color: var(--accent);
    font-weight: 600;
  }

  .hint {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: var(--space-4);
    grid-column: 1 / -1;
    margin: calc(-1 * var(--space-2)) 0 0;
  }

  .why {
    flex: none;
    padding: 0;
    border: 0;
    background: none;
    color: var(--accent);
    font-size: 12px;
    cursor: pointer;
  }

  .why:hover {
    text-decoration: underline;
    text-underline-offset: 2px;
  }
</style>
