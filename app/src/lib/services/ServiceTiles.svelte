<script lang="ts">
  import { t } from "../i18n";
  import Icon from "../Icon.svelte";
  import type { Mode } from "../api";
  import { caption, stateText, viaHint, viaLabel } from "./format";
  import { checkNow, checkOnOpen, listenServices, reload, services } from "./store.svelte";

  let {
    mode,
    vpnState,
    onwhy,
  }: {
    mode: Mode;
    /** Состояние подключения: при его смене плитки перечитываются. */
    vpnState: string;
    /** ✗ на плитке: открыть «Почему не работает?» с этим сервисом. */
    onwhy: (service: string) => void;
  } = $props();

  listenServices();

  // Вкладка открылась — проверить, если что-то подключено и итог устарел. Режим или
  // подключение сменились — только перечитать плитки: набор и пути зависят от них,
  // а запросы Rust шлёт сам, когда VPN и zapret встали.
  let opened = false;
  $effect(() => {
    void mode;
    void vpnState;
    if (opened) void reload();
    else {
      opened = true;
      void checkOnOpen();
    }
  });

  const snap = $derived(services.snapshot);
  const busy = $derived(services.pending || (snap?.checking ?? false));
</script>

{#if snap}
  <section class="card block" aria-label={t("Сервисы", "Services")}>
    <div class="row">
      <div>
        <h2>{t("Сервисы", "Services")}</h2>
        <p class="muted">
          {t("Открывает YouTube, Discord и другие сервисы так, как это сделает браузер, и показывает, каким путём они идут: через VPN, zapret или напрямую. Один-два коротких запроса на сервис.", "Opens YouTube, Discord and other services the way a browser would and shows the path they take: through the VPN, zapret or directly. One or two short requests per service.")}
        </p>
      </div>
      <button
        class="btn"
        class:busy
        disabled={busy}
        title={snap.running === "off"
          ? t("Откроет каждый сервис напрямую, без VPN", "Opens each service directly, without the VPN")
          : undefined}
        onclick={checkNow}
      >
        <Icon name="refresh" size={16} />{busy ? t("Проверяю…", "Checking…") : t("Проверить", "Check")}
      </button>
    </div>
    <p class="caption" aria-live="polite">{caption(snap)}</p>

    <ul class="grid">
      {#each snap.tiles as tile (tile.id)}
        <li class="svc {tile.state}" title={viaHint(tile.name, tile.via)}>
          <span class="dot" aria-hidden="true"></span>
          <span class="name">{tile.name}</span>
          <span class="via">{viaLabel(tile.via)}</span>
          <span class="note">
            {#if tile.state === "slow" || tile.state === "down"}{tile.detail}{:else}{stateText(tile.state)}{/if}
          </span>
          {#if tile.state === "down"}
            <button class="why" onclick={() => onwhy(tile.id)}>{t("Почему?", "Why?")}</button>
          {/if}
        </li>
      {/each}
    </ul>

    {#if services.error}
      <p class="error">{services.error}</p>
    {/if}
  </section>
{/if}

<style>
  .block {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    padding: var(--space-5);
  }

  .row {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: var(--space-6);
  }

  .row p {
    margin: var(--space-1) 0 0;
    max-width: var(--measure);
  }

  .row .btn {
    flex: none;
  }

  .caption,
  .error {
    margin: 0;
  }

  .error {
    padding: var(--space-2) var(--space-3);
    border-left: 3px solid var(--danger);
    border-radius: var(--radius-s);
    background: var(--danger-subtle);
  }

  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
    gap: var(--space-2);
    margin: 0;
    padding: 0;
    list-style: none;
  }

  /* Плитка: точка-состояние, название, путь; под ними — что случилось. */
  .svc {
    display: grid;
    grid-template-columns: auto minmax(0, 1fr) auto;
    align-items: center;
    column-gap: var(--space-2);
    row-gap: 2px;
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--stroke);
    border-radius: var(--radius-s);
    background: var(--bg);
    cursor: default;
  }

  .svc.down {
    border-color: color-mix(in srgb, var(--danger) 45%, var(--stroke));
  }

  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--text-3);
  }

  .works .dot {
    background: var(--ok);
  }

  .slow .dot,
  .waiting .dot {
    background: var(--warn);
  }

  .down .dot {
    background: var(--danger);
  }

  .name {
    overflow: hidden;
    font-weight: 600;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .via {
    color: var(--text-3);
    font-size: 12px;
  }

  .note {
    grid-column: 2 / 4;
    color: var(--text-3);
    font-size: 12px;
  }

  .slow .note {
    color: var(--warn);
  }

  .down .note {
    color: var(--danger);
  }

  .why {
    grid-column: 2 / 4;
    justify-self: start;
    padding: 0;
    border: 0;
    background: none;
    color: var(--accent);
    font: inherit;
    font-size: 12px;
    cursor: pointer;
    text-decoration: underline;
    text-underline-offset: 2px;
  }

  .why:focus-visible {
    box-shadow: var(--focus);
    border-radius: 2px;
    outline: none;
  }

</style>
