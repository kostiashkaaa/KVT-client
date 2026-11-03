<script lang="ts">
  import Flag from "./Flag.svelte";
  import type { Mode, ServerSummary, ServiceStatus } from "./api";

  let {
    server,
    mode = $bindable(),
    busy,
    status,
    onconnect,
    ondisconnect,
    onwhy,
  }: {
    server: ServerSummary | null;
    mode: Mode;
    busy: boolean;
    status: ServiceStatus | null;
    onconnect: () => void;
    ondisconnect: () => void;
    onwhy: () => void;
  } = $props();

  const connected = $derived(status?.state === "connected");
  const tone = $derived(
    busy || status?.state === "connecting" ? "pending" : connected ? "on" : status?.state === "failed" ? "error" : "off",
  );
  const title = $derived(
    tone === "pending" ? "Подключение…" : connected ? "Подключено" : tone === "error" ? "Ошибка" : "Отключено",
  );
  const coreName = $derived(status?.state === "connected" ? (status.core === "xray" ? "Xray" : "sing-box") : null);

  const modes: { id: Mode; label: string; hint: string }[] = [
    { id: "vpn", label: "VPN", hint: "Весь заблокированный трафик через VPN" },
    { id: "hybrid", label: "Гибрид", hint: "YouTube и Discord через zapret, остальное через VPN" },
    { id: "zapret", label: "Zapret", hint: "Без VPN: только обход DPI для YouTube и Discord" },
  ];
</script>

<section class="card status" aria-live="polite">
  <div class="state">
    <span class="dot {tone}" aria-hidden="true"></span>
    <div>
      <h2>{title}</h2>
      <p class="muted">
        {#if server}
          <span class="server"><Flag code={server.flag} />{server.name}</span>{#if coreName}<span class="caption">
              · {coreName}</span
            >{/if}
        {:else}
          Выберите сервер ниже
        {/if}
      </p>
    </div>
  </div>

  {#if connected}
    <button class="btn connect" disabled={busy} onclick={ondisconnect}>Отключить</button>
  {:else}
    <button class="btn btn-primary connect" disabled={(!server && mode !== "zapret") || busy} onclick={onconnect}>
      {busy ? "Подключение…" : "Подключить"}
    </button>
  {/if}

  <div class="modes" role="radiogroup" aria-label="Режим работы">
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

  .state {
    display: flex;
    align-items: center;
    gap: var(--space-3);
  }

  .state p {
    margin: 0;
  }

  .server {
    display: inline-flex;
    align-items: center;
    gap: var(--space-2);
  }

  .dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: var(--text-3);
  }

  .dot.on {
    background: var(--ok);
    box-shadow: 0 0 0 4px var(--ok-subtle);
  }

  .dot.pending {
    background: var(--warn);
  }

  .dot.error {
    background: var(--danger);
  }

  .connect {
    min-width: 140px;
    height: 36px;
  }

  .modes {
    display: inline-flex;
    justify-self: start;
    padding: 2px;
    border: 1px solid var(--stroke);
    border-radius: var(--radius-s);
    background: var(--bg);
  }

  .modes button {
    min-width: 72px;
    height: 28px;
    border: 0;
    border-radius: 3px;
    background: transparent;
    cursor: pointer;
  }

  .modes button:hover {
    background: var(--surface-hover);
  }

  /* Выбранный вариант — акцентом: в тёмной теме фон почти не отличается. */
  .modes button.selected {
    background: var(--accent-subtle);
    box-shadow: inset 0 0 0 1px var(--accent);
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
  }
</style>
