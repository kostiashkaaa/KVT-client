<script lang="ts">
  import Flag, { country } from "./Flag.svelte";
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
    mismatch = false,
    onconnect,
    ondisconnect,
    onwhy,
    onstartservice,
    onreinstall,
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
    /** Служба другой версии (прерванное обновление): кнопка ведёт на страницу загрузки. */
    mismatch?: boolean;
    onconnect: () => void;
    ondisconnect: () => void;
    onwhy: () => void;
    onstartservice?: () => void;
    onreinstall?: () => void;
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
            : serviceDown && mismatch
              ? "Окно и служба KVT разных версий"
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

  /** Вид круглой кнопки: выключено, идёт подключение, подключено (или без данных). */
  const power = $derived(busy ? "pending" : noData ? "on warn" : connected ? "on" : "off");
  const actionLabel = $derived(connected ? "Отключить" : busy ? "Подключение…" : "Подключить");

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
      <!-- Новый статус проявляется, а не подменяет прежний скачком. -->
      <h2>{#key title}<span class="appear">{title}</span>{/key}</h2>
      <p class="muted">
        {#if serviceDown && mismatch}
          Похоже, обновление прервалось. Установите KVT заново — настройки и подписки сохранятся.
        {:else if serviceDown}
          Без неё KVT не подключится. Обычно служба стартует вместе с Windows.
        {:else if zapretOnly}
          Стратегия {strategyTitle(zapretOnly.strategy)} · без VPN
        {:else if mode === "zapret" && !connected}
          Обход DPI без VPN — сервер не нужен
        {:else if server}
          <!-- Без флага — без пустого места перед названием. -->
          <span class="server"
            >{#if server.flag}<Flag code={server.flag} />{/if}<span class="name">{server.name}</span
            >{#if server.via}<span class="caption" title="Вход через {country(server.via)}">через {server.via.toUpperCase()}</span
            >{/if}{#if coreName}<span class="caption">· {coreName}</span>{/if}</span
          >
        {:else}
          Выберите сервер ниже
        {/if}
      </p>
      <!-- Строка сеанса занимает место всегда и только проявляется: карточка не
           меняет высоту при подключении, кнопка не съезжает. -->
      {#if noData}
        <p class="caption session warn-text appear">
          <span class="clip">Сервер принял подключение, но данные не идут</span>
          <button class="why" onclick={onwhy}>Почему?</button>
        </p>
      {:else}
        <p class="caption session" class:shown={showSession} title={showSession ? sessionTitle : undefined}>
          {#if showSession}
            <span>{elapsed}</span>
            {#if traffic}
              <span class="sep" aria-hidden="true">·</span>
              <span aria-label="Принято">↓&nbsp;{traffic.rx}</span>
              <span aria-label="Отправлено">↑&nbsp;{traffic.tx}</span>
            {/if}
          {:else}&nbsp;{/if}
        </p>
      {/if}
    </div>
  </div>

  <!-- Одно место для кнопки во всех состояниях: она не прыгает и не меняет размер. -->
  <div class="action">
    {#if serviceDown && mismatch}
      <button class="btn btn-primary" onclick={onreinstall}>Страница загрузки</button>
    {:else if serviceDown && !connected}
      <button class="btn btn-primary" disabled={busy} onclick={onstartservice}>
        {#if busy}<span class="spinner" aria-hidden="true"></span>{/if}
        {busy ? "Запуск…" : "Запустить службу"}
      </button>
    {:else}
      <button
        class="power {power}"
        disabled={busy || (!connected && !server && mode !== "zapret")}
        aria-label={actionLabel}
        title={actionLabel}
        onclick={connected ? ondisconnect : onconnect}
      >
        <!-- В момент подключения от кнопки расходится зелёная волна (один раз). -->
        {#if power !== "off" && power !== "pending"}
          <span class="wave" aria-hidden="true"></span>
        {/if}
        <!-- Кольцо: при подключении по нему бежит дуга. -->
        <svg class="ring" viewBox="0 0 80 80" aria-hidden="true">
          <circle class="track" cx="40" cy="40" r="38" />
          <circle class="arc" cx="40" cy="40" r="38" pathLength="100" />
        </svg>
        <svg class="icon" viewBox="0 0 24 24" aria-hidden="true">
          <path d="M12 3.5v8" />
          <path d="M7.1 6.6a7.5 7.5 0 1 0 9.8 0" />
        </svg>
      </button>
      <span class="caption label">
        {#key actionLabel}<span class="appear">{actionLabel}</span>{/key}
      </span>
    {/if}
  </div>

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

  /* Кнопка справа на высоту состояния и режимов, ширина постоянная. */
  .action {
    grid-column: 2;
    grid-row: 1 / 3;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--space-2);
    min-width: 132px;
  }

  .power {
    --size: 76px;
    --ring: var(--stroke-strong);
    --fill: transparent;
    --glyph: var(--accent);
    position: relative;
    display: grid;
    place-items: center;
    width: var(--size);
    height: var(--size);
    padding: 0;
    border: 0;
    border-radius: 50%;
    background: var(--fill);
    color: var(--glyph);
    cursor: pointer;
    transition:
      background-color 300ms var(--ease),
      box-shadow 300ms var(--ease),
      color 300ms var(--ease),
      transform var(--dur-fast) var(--ease);
  }

  .power.off:hover:not(:disabled) {
    --ring: var(--accent);
    background: var(--accent-subtle);
  }

  .power:active:not(:disabled) {
    transform: scale(0.96);
  }

  .power:disabled {
    cursor: default;
  }

  .power.off:disabled {
    opacity: 0.45;
  }

  /* Подключено: зелёные кольцо и значок на едва заметном зелёном фоне, без
     сплошной заливки — спокойно, но сразу понятно. */
  .power.on {
    --ring: var(--ok);
    --fill: var(--ok-subtle);
    --glyph: var(--ok);
    box-shadow: 0 0 0 5px color-mix(in srgb, var(--ok) 14%, transparent);
  }

  .power.on:hover:not(:disabled) {
    background: color-mix(in srgb, var(--ok-subtle), var(--ok) 12%);
  }

  /* Подключено, но данные не идут — то же, жёлтым. */
  .power.on.warn {
    --ring: var(--warn);
    --fill: var(--warn-subtle);
    --glyph: var(--warn);
    box-shadow: 0 0 0 5px color-mix(in srgb, var(--warn) 14%, transparent);
  }

  .power.on.warn:hover:not(:disabled) {
    background: color-mix(in srgb, var(--warn-subtle), var(--warn) 12%);
  }

  .wave {
    position: absolute;
    inset: 0;
    border-radius: 50%;
    border: 2px solid var(--ring);
    opacity: 0;
    pointer-events: none;
    animation: kvt-wave 700ms var(--ease);
  }

  @keyframes kvt-wave {
    from {
      opacity: 0.7;
      transform: scale(1);
    }
    to {
      opacity: 0;
      transform: scale(1.45);
    }
  }

  .power:focus-visible {
    outline: none;
    box-shadow: var(--focus);
  }

  .ring {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    fill: none;
    stroke-width: 2.5;
  }

  .track {
    stroke: var(--ring);
    stroke-width: 2.5;
    transition: stroke 300ms var(--ease);
  }

  /* Дуга видна только во время подключения и бежит по кругу. */
  .arc {
    stroke: var(--accent);
    stroke-linecap: round;
    stroke-dasharray: 28 72;
    opacity: 0;
    transform-origin: center;
    transition: opacity var(--dur) var(--ease);
  }

  .pending .arc {
    opacity: 1;
    animation: kvt-spin 1s linear infinite;
  }

  .pending .icon {
    animation: kvt-pulse 1.2s ease-in-out infinite;
  }

  .icon {
    width: 30px;
    height: 30px;
    fill: none;
    stroke: currentColor;
    stroke-width: 2;
    stroke-linecap: round;
    transition: transform 300ms var(--ease);
  }

  .on .icon {
    transform: scale(1.06);
  }

  /* Подъём при появлении работает только у блочных элементов. */
  h2 .appear,
  .label .appear {
    display: inline-block;
  }

  .label {
    height: 16px;
    color: var(--text-2);
    white-space: nowrap;
  }

  @keyframes kvt-spin {
    to {
      transform: rotate(360deg);
    }
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
    min-height: 16px;
    margin-top: var(--space-1);
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
    opacity: 0;
    transition: opacity var(--dur) var(--ease);
  }

  .session.shown,
  .session.warn-text {
    opacity: 1;
  }

  .clip {
    overflow: hidden;
    text-overflow: ellipsis;
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
    animation: kvt-pop 300ms var(--ease);
  }

  @keyframes kvt-pop {
    50% {
      transform: scale(1.4);
    }
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

  .dot.error {
    background: var(--danger);
    box-shadow: 0 0 0 4px var(--danger-subtle);
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
