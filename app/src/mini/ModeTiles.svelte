<script lang="ts">
  import { t } from "../lib/i18n";
  import Icon, { type IconName } from "../lib/Icon.svelte";
  import type { Mode } from "../lib/api";
  import { modeHint } from "../lib/statusView";
  import { act, panel } from "./store.svelte";

  const view = $derived(panel.view);
  const mode = $derived(view?.mode ?? "vpn");
  const telegram = $derived(view?.telegram ?? false);
  const modes: { id: Mode; label: string; icon: IconName }[] = $derived([
    { id: "vpn", label: "VPN", icon: "shield" },
    { id: "hybrid", label: t("Гибрид", "Hybrid"), icon: "route" },
    { id: "zapret", label: "Zapret", icon: "bolt" },
  ]);
</script>

<!-- Режимы — крупные плитки, как переключатели в быстрых настройках Windows. -->
<div class="tiles" role="radiogroup" aria-label={t("Режим работы", "Mode")}>
  {#each modes as m (m.id)}
    <button
      role="radio"
      aria-checked={mode === m.id}
      class="tile"
      class:selected={mode === m.id}
      title={modeHint(m.id, telegram)}
      disabled={panel.acting !== null}
      onclick={() => mode !== m.id && void act(`mode:${m.id}`)}
    >
      <Icon name={m.icon} size={20} />
      <span>{m.label}</span>
    </button>
  {/each}
</div>

{#if view && mode !== "vpn"}
  <div class="zapret appear">
    <span class="z-icon" aria-hidden="true"><Icon name="bolt" size={16} /></span>
    <span class="z-text">
      {view.zapret.pickedFor
        ? t(`Zapret подобран для сети «${view.zapret.pickedFor}»`, `Zapret picked for “${view.zapret.pickedFor}”`)
        : t(`Стратегия zapret: ${view.zapret.strategy}`, `Zapret strategy: ${view.zapret.strategy}`)}
    </span>
    {#if view.zapret.pickedFor}<span class="z-ok" aria-hidden="true">✓</span>{/if}
  </div>
{/if}

<style>
  .tiles {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: var(--space-2);
  }

  .tile {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 6px;
    padding: var(--space-3) var(--space-2);
    border: 1px solid var(--stroke);
    border-radius: var(--radius-m);
    background: var(--surface);
    color: var(--text);
    cursor: pointer;
    transition:
      background-color var(--dur-fast) var(--ease),
      border-color var(--dur-fast) var(--ease),
      color var(--dur-fast) var(--ease);
  }

  .tile:hover:not(.selected):not(:disabled) {
    background: var(--surface-hover);
  }

  .tile:focus-visible {
    box-shadow: var(--focus);
    outline: none;
  }

  .tile:disabled:not(.selected) {
    opacity: 0.6;
    cursor: default;
  }

  .tile.selected {
    border-color: transparent;
    background: var(--accent);
    color: var(--accent-text);
  }

  .tile:disabled {
    cursor: default;
  }

  .zapret {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    padding: var(--space-2) var(--space-3);
    border-radius: var(--radius-m);
    background: var(--ok-subtle);
    font-size: 12px;
    line-height: 16px;
  }

  .z-icon {
    display: grid;
    color: var(--ok);
  }

  .z-text {
    flex: 1;
    min-width: 0;
  }

  .z-ok {
    color: var(--ok);
    font-weight: 600;
  }
</style>
