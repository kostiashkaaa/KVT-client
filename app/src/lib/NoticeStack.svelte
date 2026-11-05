<script lang="ts">
  import Banner from "./Banner.svelte";
  import { dismiss, hover, notices } from "./notices.svelte";
</script>

<!-- Сообщения окна внизу справа на любой вкладке; не больше четырёх. -->
{#if notices.list.length > 0}
  <div class="stack" aria-live="polite">
    {#each notices.list as n (n.id)}
      <div
        class="item"
        role="presentation"
        onmouseenter={() => hover(n.id, true)}
        onmouseleave={() => hover(n.id, false)}
      >
        <Banner tone={n.tone}>
          {n.text}{#if n.count > 1}<span class="count" title="Пришло {n.count} раза">&nbsp;×{n.count}</span>{/if}
          {#snippet action()}
            {#each n.actions as a (a.label)}
              <button
                class="btn"
                class:btn-primary={a.primary}
                onclick={async () => {
                  dismiss(n.id);
                  await a.run();
                }}>{a.label}</button
              >
            {/each}
            <button class="btn" onclick={() => dismiss(n.id)}>{n.closeLabel}</button>
          {/snippet}
        </Banner>
      </div>
    {/each}
  </div>
{/if}

<style>
  /* Над содержимым вкладки, у нижнего края — как уведомления, но внутри окна. */
  .stack {
    position: fixed;
    right: var(--space-6);
    bottom: var(--space-5);
    z-index: 20;
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    width: min(560px, calc(100vw - 2 * var(--space-6) - 72px));
    pointer-events: none;
  }

  .item {
    pointer-events: auto;
    border-radius: var(--radius-s);
    background: var(--surface);
    box-shadow: 0 6px 24px rgb(0 0 0 / 0.18);
  }

  .count {
    color: var(--text-3);
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
  }
</style>
