<script lang="ts">
  import { t } from "../lib/i18n";
  import Flag from "../lib/Flag.svelte";
  import Icon from "../lib/Icon.svelte";
  import ServerName from "../lib/ServerName.svelte";
  import { panelOpen, type PanelServer } from "../lib/api";
  import { pingText, protoLabel, usageOf } from "./format";
  import { act, panel } from "./store.svelte";

  const view = $derived(panel.view);
  const server = $derived(view?.server ?? null);
  const servers = $derived(view?.servers ?? []);
  const usage = $derived(usageOf(view?.subscription ?? null));
  let open = $state(false);

  function pick(s: PanelServer) {
    open = false;
    if (s.key !== server?.key) void act(`srv:${s.key}`);
  }
</script>

<div class="server appear">
  {#if server}
    <button class="srv-row" aria-expanded={open} disabled={panel.acting !== null} onclick={() => (open = !open)}>
      {@render flag(server)}
      <span class="who">
        <span class="name"><ServerName name={server.name} /></span>
        <span class="caption">{protoLabel(server)}</span>
      </span>
      <span class="ms {server.health}">{pingText(server)}</span>
      <span class="chev" class:open><Icon name="chevron" size={16} /></span>
    </button>
  {:else}
    <!-- Сервера нет: выбирать не из чего — подписку добавляют в окне. -->
    <button class="srv-row" onclick={() => void panelOpen(servers.length > 0 ? "home" : "add")}>
      <span class="who">
        <span class="name">{servers.length > 0 ? t("Выберите сервер", "Pick a server") : t("Нет серверов", "No servers")}</span>
        <span class="caption">{servers.length > 0 ? t("В окне KVT", "In the KVT window") : t("Добавьте подписку в окне KVT", "Add a subscription in the KVT window")}</span>
      </span>
      <Icon name="external" size={14} />
    </button>
  {/if}

  {#if open}
    <ul class="list appear">
      {#each servers as s (s.key)}
        <li>
          <button class="srv-row item" class:current={s.key === server?.key} onclick={() => pick(s)}>
            {@render flag(s)}
            <span class="name"><ServerName name={s.name} /></span>
            <span class="ms {s.health}">{pingText(s)}</span>
            <span class="mark" aria-hidden="true">{s.key === server?.key ? "✓" : ""}</span>
          </button>
        </li>
      {/each}
    </ul>
    <button class="more" onclick={() => void panelOpen("home")}>
      {view && view.total > servers.length
        ? t(`Все серверы (${view.total}) в окне KVT`, `All servers (${view.total}) in the KVT window`)
        : t("Все серверы в окне KVT", "All servers in the KVT window")}<Icon name="external" size={14} />
    </button>
  {:else if usage}
    <!-- Остаток трафика подписки — тонкая полоса под сервером, чтобы лимит не был сюрпризом. -->
    <div class="usage" title={t("Остаток трафика подписки", "Subscription traffic left")}>
      <span class="caption">{usage.label}</span>
      {#if usage.percent !== null}
        <span class="meter" aria-hidden="true"><span style:width="{usage.percent}%"></span></span>
      {/if}
    </div>
  {/if}
</div>

{#snippet flag(s: PanelServer)}
  {#if s.flag}<Flag code={s.flag} width={24} />{:else}<span class="noflag" aria-hidden="true"></span>{/if}
{/snippet}

<style>
  .server {
    display: flex;
    flex-direction: column;
    border: 1px solid var(--stroke);
    border-radius: var(--radius-m);
    background: var(--surface);
    overflow: hidden;
  }

  .srv-row {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    width: 100%;
    min-height: 48px;
    padding: 0 var(--space-3);
    border: 0;
    background: transparent;
    color: inherit;
    font: inherit;
    text-align: left;
    cursor: pointer;
  }

  .srv-row:hover:not(:disabled) {
    background: var(--surface-hover);
  }

  .srv-row:focus-visible {
    box-shadow: inset var(--focus);
    outline: none;
  }

  .srv-row:disabled {
    cursor: default;
  }

  .noflag {
    flex: none;
    width: 24px;
  }

  .who {
    display: flex;
    flex: 1;
    flex-direction: column;
    min-width: 0;
  }

  .who .caption {
    line-height: 14px;
  }

  .name {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    white-space: nowrap;
    text-overflow: ellipsis;
  }

  .who .name {
    flex: none;
  }

  /* Задержка: цвет — как в списке окна, но слово остаётся словом, а не только цветом. */
  .ms {
    flex: none;
    color: var(--ok);
    font-variant-numeric: tabular-nums;
    font-size: 12px;
  }

  .ms.slow {
    color: var(--warn);
  }

  .ms.down {
    color: var(--danger);
  }

  .ms.unknown {
    color: var(--text-3);
  }

  .chev {
    display: grid;
    flex: none;
    color: var(--text-2);
    transition: transform var(--dur) var(--ease);
  }

  .chev.open {
    transform: rotate(180deg);
  }

  .usage {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: 6px var(--space-3) 8px;
    border-top: 1px solid var(--stroke);
  }

  .usage .caption {
    flex: none;
  }

  .meter {
    flex: 1;
    height: 4px;
    border-radius: 2px;
    background: var(--stroke);
    overflow: hidden;
  }

  .meter span {
    display: block;
    height: 100%;
    background: var(--accent);
  }

  .list {
    max-height: 118px;
    margin: 0;
    padding: 0;
    border-top: 1px solid var(--stroke);
    list-style: none;
    overflow-y: auto;
    scrollbar-width: thin;
  }

  .item {
    min-height: 38px;
  }

  .item.current {
    background: var(--accent-subtle);
  }

  .mark {
    flex: none;
    width: 14px;
    color: var(--accent);
    font-weight: 600;
  }

  .more {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: var(--space-2);
    width: 100%;
    min-height: 34px;
    border: 0;
    border-top: 1px solid var(--stroke);
    background: transparent;
    color: var(--accent);
    font: inherit;
    font-size: 12px;
    cursor: pointer;
  }

  .more:hover {
    background: var(--surface-hover);
  }

  .more:focus-visible {
    box-shadow: inset var(--focus);
    outline: none;
  }
</style>
