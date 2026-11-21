<script lang="ts">
  import { t } from "../lib/i18n";
  import type { PanelAction } from "../lib/api";
  import { act, panel } from "./store.svelte";

  const view = $derived(panel.view);
  // Те же настройки, что в «Настройках» и на вкладке Zapret.
  const chips: { id: PanelAction; label: string; on: boolean; hint: string }[] = $derived([
    {
      id: "ks",
      label: "Kill switch",
      on: view?.killSwitch ?? false,
      hint: t("Если VPN оборвётся, интернет закроется — трафик не уйдёт мимо туннеля", "If the VPN drops, the internet closes — nothing leaks outside the tunnel"),
    },
    {
      id: "auto",
      label: t("Автосмена", "Auto-switch"),
      on: view?.autoSwitch ?? false,
      hint: t("Если данные перестали идти, KVT сам переключится на рабочий сервер", "If data stops flowing, KVT switches to a working server by itself"),
    },
    {
      id: "tg",
      label: "Telegram",
      on: view?.telegram ?? false,
      hint: t("Прокси для Telegram Desktop — без VPN-сервера", "Proxy for Telegram Desktop — no VPN server needed"),
    },
  ]);
</script>

<!-- Быстрые настройки: включено — галочка и акцент, как у чипов Windows. -->
<div class="chips" role="group" aria-label={t("Быстрые настройки", "Quick settings")}>
  {#each chips as c (c.id)}
    <button
      class="chip"
      class:on={c.on}
      aria-pressed={c.on}
      title={c.hint}
      disabled={panel.acting !== null}
      onclick={() => void act(c.id)}
    >
      <span class="tick" aria-hidden="true">{c.on ? "✓" : ""}</span>{c.label}
    </button>
  {/each}
</div>

<style>
  .chips {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: var(--space-2);
  }

  .chip {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 4px;
    min-height: 32px;
    padding: 0 var(--space-2);
    border: 1px solid var(--stroke);
    border-radius: 16px;
    background: transparent;
    color: var(--text-2);
    font: inherit;
    font-size: 12px;
    white-space: nowrap;
    cursor: pointer;
    transition:
      background-color var(--dur-fast) var(--ease),
      border-color var(--dur-fast) var(--ease),
      color var(--dur-fast) var(--ease);
  }

  .chip:hover:not(:disabled) {
    background: var(--surface-hover);
  }

  .chip:focus-visible {
    box-shadow: var(--focus);
    outline: none;
  }

  .chip:disabled {
    cursor: default;
    opacity: 0.6;
  }

  .chip.on {
    border-color: var(--accent);
    background: var(--accent-subtle);
    color: var(--accent);
    font-weight: 600;
  }

  .tick {
    min-width: 10px;
    font-size: 11px;
  }

  .tick:empty {
    display: none;
  }
</style>
