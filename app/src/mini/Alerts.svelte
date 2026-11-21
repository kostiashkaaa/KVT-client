<script lang="ts">
  import { t } from "../lib/i18n";
  import { panelOpen } from "../lib/api";
  import Icon from "../lib/Icon.svelte";
  import type { StatusView } from "../lib/statusView";
  import { alternative, noticeAction, noticeText } from "./format";
  import { act, notice, panel } from "./store.svelte";

  let { sv, down }: { sv: StatusView; down: boolean } = $props();

  /** Сервер принял подключение, но данные не идут: сразу два выхода. */
  const problem = $derived(sv.noData && sv.tone === "warn");
  const other = $derived(alternative(panel.view?.servers ?? [], panel.view?.server?.key ?? null));
  const reminder = $derived(notice());
</script>

{#if panel.error}
  <p class="error appear" role="alert">{panel.error}</p>
{/if}

<!-- Проблема: другой сервер или объяснение причины. -->
{#if problem}
  <div class="alert appear" role="alert">
    {#if other}
      <button class="btn" onclick={() => void act(`srv:${other.key}`)}>
        <Icon name="refresh" size={14} />{t("Другой сервер", "Another server")}
      </button>
    {/if}
    <button class="btn ghost" onclick={() => void panelOpen("why")}>
      <Icon name="help" size={14} />{t("Почему?", "Why?")}
    </button>
  </div>
{/if}

{#if sv.blocked}
  <div class="alert danger appear" role="alert">
    <button class="btn btn-primary" onclick={() => void act("toggle")}>
      {t("Отключить и вернуть интернет", "Disconnect and restore the internet")}
    </button>
  </div>
{/if}

<!-- Напоминание — одна строка, не плашка: не мешает, пока не нужно. -->
{#if reminder && !down && !sv.blocked}
  <div class="notice appear" role="status">
    <Icon name="info" size={14} />
    <span class="n-text">{noticeText(reminder)}</span>
    <button class="n-act" onclick={() => void panelOpen(reminder.kind === "update" ? "home" : "subscriptions")}>
      {noticeAction(reminder)}
    </button>
  </div>
{/if}

<style>
  .error {
    margin: 0;
    padding: var(--space-2) var(--space-3);
    border-left: 3px solid var(--danger);
    border-radius: var(--radius-s);
    background: var(--danger-subtle);
    font-size: 12px;
    line-height: 16px;
  }

  .alert {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
    padding: var(--space-2) var(--space-3);
    border-left: 3px solid var(--warn);
    border-radius: var(--radius-s);
    background: var(--warn-subtle);
  }

  .alert.danger {
    border-left-color: var(--danger);
    background: var(--danger-subtle);
  }

  .alert .btn {
    min-height: 30px;
    font-size: 12px;
  }

  .alert .btn.ghost {
    border-color: transparent;
    background: transparent;
    color: var(--text);
  }

  .alert .btn.ghost:hover {
    background: color-mix(in srgb, var(--warn) 16%, transparent);
  }

  .notice {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    padding: 6px var(--space-3);
    border-radius: var(--radius-s);
    background: var(--accent-subtle);
    color: var(--accent);
    font-size: 12px;
    line-height: 16px;
  }

  .n-text {
    flex: 1;
    min-width: 0;
  }

  .n-act {
    flex: none;
    padding: 0;
    border: 0;
    background: none;
    color: inherit;
    font: inherit;
    font-weight: 600;
    cursor: pointer;
  }

  .n-act:hover {
    text-decoration: underline;
    text-underline-offset: 2px;
  }

  .n-act:focus-visible {
    box-shadow: var(--focus);
    border-radius: 2px;
    outline: none;
  }
</style>
