<script lang="ts">
  import { t } from "../lib/i18n";
  import { stateText, viaHint, viaLabel } from "../lib/services/format";
  import { panel } from "./store.svelte";

  const tiles = $derived(panel.services?.tiles ?? []);
  /** Итога нет (ещё ничего не проверяли) — ряда нет: панель сама к сайтам не ходит. */
  const shown = $derived(tiles.some((tile) => tile.state !== "unknown"));
</script>

<!-- Что открывается прямо сейчас: ответ на «работает ли то, что мне надо». -->
{#if shown}
  <ul class="services" aria-label={t("Сервисы", "Services")}>
    {#each tiles as tile (tile.id)}
      <li class="svc {tile.state}" title={viaHint(tile.name, tile.via)}>
        <span class="dot" aria-hidden="true"></span><span class="name">{tile.name}</span>
        <span class="route">{viaLabel(tile.via)}</span>
        <span class="sr">{stateText(tile.state)}</span>
      </li>
    {/each}
  </ul>
{/if}

<style>
  .services {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 6px;
    margin: 0;
    padding: 0;
    list-style: none;
  }

  .svc {
    position: relative;
    display: flex;
    align-items: center;
    gap: 6px;
    height: 28px;
    padding: 0 10px;
    border: 1px solid var(--stroke);
    border-radius: 14px;
    background: var(--surface);
    color: var(--text);
    font-size: 12px;
    cursor: default;
  }

  .name {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    white-space: nowrap;
    text-overflow: ellipsis;
  }

  /* Путь — тихо справа: что именно даёт текущий режим. */
  .route {
    flex: none;
    color: var(--text-3);
    font-size: 11px;
  }

  .dot {
    flex: none;
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

  .down {
    border-color: color-mix(in srgb, var(--danger) 45%, var(--stroke));
  }

  .down .dot {
    background: var(--danger);
  }

  .down .route {
    color: var(--danger);
  }
</style>
