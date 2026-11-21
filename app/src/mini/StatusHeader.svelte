<script lang="ts">
  import { t } from "../lib/i18n";
  import { formatBytes, formatElapsed, panelOpen, strategyTitle } from "../lib/api";
  import type { StatusView } from "../lib/statusView";
  import { act, panel, startServiceNow } from "./store.svelte";

  let { sv, down }: { sv: StatusView; down: boolean } = $props();

  const mode = $derived(panel.view?.mode ?? "vpn");
  const zapret = $derived(panel.status?.state === "zapret" ? panel.status : null);
  /** Служба подключает: то же нажатие отменяет подключение. */
  const cancelable = $derived(panel.status?.state === "connecting");
  const stops = $derived(sv.connected || sv.blocked);
  /** Сервер нужен всем режимам, кроме «Zapret»: без него подключаться не к чему. */
  const canConnect = $derived(mode === "zapret" || (panel.view?.server ?? null) !== null);
  const label = $derived(
    cancelable
      ? t("Отменить подключение", "Cancel connection")
      : stops
        ? t("Отключить", "Disconnect")
        : sv.tone === "pending"
          ? t("Подключение…", "Connecting…")
          : t("Подключить", "Connect"),
  );
  const hint = $derived(!stops && !cancelable && !canConnect ? t("Выберите сервер", "Pick a server") : label);

  // Служба отвечает раз в 3 с, а секунды тикают здесь: от последнего ответа.
  let now = $state(performance.now());
  const showSession = $derived(sv.connected && panel.session !== null && sv.tone !== "pending");
  $effect(() => {
    if (!showSession) return;
    now = performance.now();
    const timer = setInterval(() => (now = performance.now()), 1000);
    return () => clearInterval(timer);
  });
  const elapsed = $derived(formatElapsed(panel.received.secs + Math.max(0, now - panel.received.at) / 1000));
  const traffic = $derived(
    panel.session?.rx != null && panel.session.tx != null
      ? { rx: formatBytes(panel.session.rx), tx: formatBytes(panel.session.tx) }
      : null,
  );
  const power = $derived(sv.blocked ? "on danger" : sv.power);
</script>

<header>
  <div class="state">
    <h2 class:warn={sv.noData} class:danger={down || sv.blocked}>
      <span class="dot {sv.tone}" aria-hidden="true"></span>{#key sv.title}<span class="appear">{sv.title}</span>{/key}
    </h2>
    <p class="caption line" class:warn={sv.noData} aria-live="polite">
      {#if down && panel.mismatch}
        {t("Обновление прервалось — переустановите KVT", "The update was interrupted — reinstall KVT")}
      {:else if sv.serviceStarting || (sv.tone === "pending" && !down)}
        {t("Обычно несколько секунд", "Usually a few seconds")}
      {:else if down}
        {t("Без неё KVT не подключится", "KVT can't connect without it")}
      {:else if sv.blocked}
        {t("kill switch не выпускает трафик мимо туннеля", "the kill switch blocks traffic outside the tunnel")}
      {:else if sv.noData}
        {t("Данные через сервер не идут", "No data through the server")}
      {:else if sv.connected}
        {#if showSession}
          <span>{elapsed}</span>
          {#if traffic}
            <span class="sep" aria-hidden="true">·</span>
            <span>↓&nbsp;{traffic.rx}</span>
            <span>↑&nbsp;{traffic.tx}</span>
          {/if}
        {:else if zapret}
          {t(`Стратегия ${strategyTitle(zapret.strategy)} · без VPN`, `Strategy ${strategyTitle(zapret.strategy)} · no VPN`)}
        {/if}
      {:else}
        {mode === "zapret"
          ? t("Сервер не нужен — только обход блокировок", "No server needed — just the bypass")
          : t("Нажмите кнопку, чтобы подключиться", "Press the button to connect")}
      {/if}
    </p>
  </div>
  {#if down}
    {#if panel.mismatch}
      <button class="btn btn-primary" onclick={() => void panelOpen()}>{t("Открыть KVT", "Open KVT")}</button>
    {:else}
      <button
        class="btn btn-primary"
        class:busy={panel.starting}
        disabled={panel.starting}
        onclick={() => void startServiceNow()}
      >
        {t("Запустить службу", "Start service")}
      </button>
    {/if}
  {:else}
    <button
      class="power {power}"
      aria-label={label}
      title={hint}
      disabled={!stops && !cancelable && !canConnect}
      onclick={() => void act("toggle")}
    >
      <svg class="ring" viewBox="0 0 48 48" aria-hidden="true">
        <circle class="track" cx="24" cy="24" r="22.5" />
        <circle class="arc" cx="24" cy="24" r="22.5" pathLength="100" />
      </svg>
      <svg class="icon" viewBox="0 0 24 24" aria-hidden="true">
        <path d="M12 3.5v8" />
        <path d="M7.1 6.6a7.5 7.5 0 1 0 9.8 0" />
      </svg>
    </button>
  {/if}
</header>

<style>
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-3);
  }

  .state {
    min-width: 0;
  }

  h2 {
    display: flex;
    align-items: center;
    gap: var(--space-2);
  }

  h2.warn {
    color: var(--warn);
  }

  h2.danger {
    color: var(--danger);
  }

  h2 .appear {
    display: inline-block;
  }

  .line {
    display: flex;
    gap: var(--space-2);
    min-height: 20px;
    margin: 2px 0 0 calc(10px + var(--space-2));
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
  }

  .line.warn {
    color: var(--warn);
  }

  .sep {
    color: var(--text-3);
  }

  .dot {
    flex: none;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: var(--text-3);
    transition: background-color var(--dur) var(--ease);
  }

  .dot.on {
    background: var(--ok);
    box-shadow: 0 0 0 4px var(--ok-subtle);
  }

  .dot.pending {
    background: var(--warn);
    animation: kvt-pulse 1.2s ease-in-out infinite;
  }

  .dot.warn {
    background: var(--warn);
    box-shadow: 0 0 0 4px var(--warn-subtle);
  }

  .dot.error {
    background: var(--danger);
    box-shadow: 0 0 0 4px var(--danger-subtle);
  }

  /* Круглая кнопка — уменьшенная копия главной. */
  .power {
    --ring: var(--stroke-strong);
    --fill: transparent;
    --glyph: var(--accent);
    position: relative;
    display: grid;
    flex: none;
    place-items: center;
    width: 48px;
    height: 48px;
    padding: 0;
    border: 0;
    border-radius: 50%;
    background: var(--fill);
    color: var(--glyph);
    cursor: pointer;
    transition:
      background-color 300ms var(--ease),
      box-shadow 300ms var(--ease),
      transform var(--dur-fast) var(--ease);
  }

  .power:disabled {
    opacity: 0.5;
    cursor: default;
  }

  .power:focus-visible {
    box-shadow: var(--focus);
    outline: none;
  }

  .power.off:hover:not(:disabled) {
    --ring: var(--accent);
    background: var(--accent-subtle);
  }

  .power:active:not(:disabled) {
    transform: scale(0.96);
  }

  .power.on {
    --ring: var(--ok);
    --fill: var(--ok-subtle);
    --glyph: var(--ok);
    box-shadow: 0 0 0 4px color-mix(in srgb, var(--ok) 14%, transparent);
  }

  .power.on.warn {
    --ring: var(--warn);
    --fill: var(--warn-subtle);
    --glyph: var(--warn);
    box-shadow: 0 0 0 4px color-mix(in srgb, var(--warn) 14%, transparent);
  }

  .power.on.danger {
    --ring: var(--danger);
    --fill: var(--danger-subtle);
    --glyph: var(--danger);
    box-shadow: 0 0 0 4px color-mix(in srgb, var(--danger) 14%, transparent);
  }

  .ring {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    fill: none;
  }

  .track {
    stroke: var(--ring);
    stroke-width: 2;
    transition: stroke 300ms var(--ease);
  }

  .arc {
    stroke: var(--accent);
    stroke-width: 2;
    stroke-linecap: round;
    stroke-dasharray: 28 72;
    opacity: 0;
    transform-origin: center;
  }

  .pending .arc {
    opacity: 1;
    animation: kvt-spin 1s linear infinite;
  }

  .pending .icon {
    animation: kvt-pulse 1.2s ease-in-out infinite;
  }

  .icon {
    width: 20px;
    height: 20px;
    fill: none;
    stroke: currentColor;
    stroke-width: 2;
    stroke-linecap: round;
  }
</style>
