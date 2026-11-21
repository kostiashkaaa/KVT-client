<script lang="ts">
  import { t } from "../lib/i18n";
  import { panelOpen } from "../lib/api";
  import Icon from "../lib/Icon.svelte";
</script>

<footer>
  <button class="foot" onclick={() => void panelOpen("why")}>
    <Icon name="help" size={14} />{t("Почему не работает?", "Why isn't it working?")}
  </button>
  <span class="spacer"></span>
  <button class="foot" onclick={() => void panelOpen()}>
    {t("Открыть KVT", "Open KVT")}<Icon name="external" size={14} />
  </button>
  <button
    class="foot icon-only"
    aria-label={t("Настройки", "Settings")}
    title={t("Настройки", "Settings")}
    onclick={() => void panelOpen("settings")}
  >
    <Icon name="settings" size={16} />
  </button>
</footer>

<style>
  footer {
    display: flex;
    align-items: center;
    gap: var(--space-1);
    margin: 0 calc(-1 * var(--space-2)) calc(-1 * var(--space-1));
    padding-top: var(--space-2);
    border-top: 1px solid var(--stroke);
  }

  .spacer {
    flex: 1;
  }

  .foot {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    min-height: 30px;
    padding: 0 var(--space-2);
    border: 0;
    border-radius: var(--radius-s);
    background: transparent;
    color: var(--text-2);
    font: inherit;
    font-size: 12px;
    cursor: pointer;
  }

  .foot:hover {
    background: var(--surface-hover);
    color: var(--text);
  }

  .foot:focus-visible {
    box-shadow: var(--focus);
    outline: none;
  }

  .foot.icon-only {
    width: 30px;
    justify-content: center;
    padding: 0;
  }
</style>
