<script lang="ts">
  import type { Snippet } from "svelte";
  import Icon from "./Icon.svelte";

  /** Строка-предупреждение: иконка, текст и необязательная кнопка справа. */
  let {
    tone = "warn",
    children,
    action,
  }: {
    /** warn — ошибка или предупреждение, info — сообщение KVT. */
    tone?: "warn" | "info";
    children: Snippet;
    action?: Snippet;
  } = $props();
</script>

<div class="banner {tone}" role={tone === "info" ? "status" : "alert"}>
  <div class="body">
    <Icon name={tone === "info" ? "info" : "warning"} size={16} />
    <span class="text">{@render children()}</span>
  </div>
  {#if action}
    <div class="action">{@render action()}</div>
  {/if}
</div>

<style>
  .banner {
    display: flex;
    align-items: center;
    gap: var(--space-4);
    padding: var(--space-3) var(--space-4);
    border: 1px solid var(--stroke);
    border-left: 3px solid var(--warn);
    border-radius: var(--radius-s);
    background: var(--warn-subtle);
    animation: kvt-rise var(--dur) var(--ease) backwards;
  }

  .banner.info {
    border-left-color: var(--accent);
    background: var(--accent-subtle);
  }

  /* Иконка стоит по центру первой строки текста, даже если текст в несколько строк. */
  .body {
    display: flex;
    flex: 1;
    align-items: flex-start;
    gap: var(--space-3);
    min-width: 0;
  }

  .body :global(svg) {
    flex: none;
    margin-top: 2px;
    color: var(--warn);
  }

  .info .body :global(svg) {
    color: var(--accent);
  }

  .text {
    min-width: 0;
    max-width: var(--measure);
    overflow-wrap: anywhere;
    text-wrap: pretty;
  }

  .action {
    display: flex;
    flex: none;
    gap: var(--space-2);
  }
</style>
