<script lang="ts">
  // Карточка одной подписки: сводка (трафик, срок, протоколы, замечания провайдера),
  // ссылки и части, у которых своя разметка: шапка, «Расширенные», ключи вручную.
  import { count, t } from "../i18n";
  import Icon from "../Icon.svelte";
  import { openSubscriptionLink, type SubscriptionItem } from "../api";
  import ManualKeys from "./ManualKeys.svelte";
  import SubscriptionAdvanced from "./SubscriptionAdvanced.svelte";
  import SubscriptionHead from "./SubscriptionHead.svelte";
  import SubscriptionStats from "./SubscriptionStats.svelte";
  import { customized, expiry, protocolTitle, skippedCount, skippedSummary, trouble, usage } from "./format";
  import type { ListUi } from "./ui.svelte";

  let {
    s,
    ui,
    refreshing,
    refreshingAll,
    act,
    refresh,
    reload,
  }: {
    s: SubscriptionItem;
    ui: ListUi;
    refreshing: string | null;
    refreshingAll: boolean;
    act: (fn: () => Promise<unknown>) => Promise<void>;
    refresh: (id: string) => Promise<void>;
    reload: () => Promise<void>;
  } = $props();

  const use = $derived(usage(s));
  const exp = $derived(s.expire ? expiry(s.expire) : null);
  const skipped = $derived(skippedCount(s));

  /** «Расширенные» открыты у одной подписки на всю страницу. */
  function toggleAdvanced(item: SubscriptionItem) {
    ui.advanced = ui.advanced === item.id ? null : item.id;
  }
</script>

<li class="card sub" class:problem={!!s.lastError}>
  <SubscriptionHead {s} {ui} {refreshing} {refreshingAll} {act} {refresh} {reload} />

  {#if s.lastError && s.failedAt}
    <p class="trouble appear">
      <Icon name="warning" size={16} />
      <span>{trouble(s, s.failedAt)}</span>
    </p>
  {/if}

  {#if use || exp}
    <SubscriptionStats {use} {exp} />
  {/if}

  <!-- У ручной группы протокол виден у каждого ключа — сводка не нужна. -->
  {#if s.byUrl && s.protocols.length > 0}
    <ul class="chips" aria-label={t("Протоколы серверов", "Server protocols")}>
      {#each s.protocols as p (p.protocol)}
        <li class="chip">{protocolTitle(p.protocol)}<span>{p.count}</span></li>
      {/each}
    </ul>
  {/if}

  {#if s.announce}
    <!-- Текст провайдера выводится только как текст, без разметки. -->
    <p class="announce">{s.announce}</p>
  {/if}
  {#each s.info as line, i (i)}
    <p class="caption">{line}</p>
  {/each}

  {#if s.servers === 0 && s.hidden > 0}
    <p class="caption warning">{t("Фильтр скрыл все серверы подписки — измените его в «Расширенных».", "The filter hid all of the subscription's servers — change it in “Advanced”.")}</p>
  {/if}

  <!-- Не прячем под «подробнее»: это про безопасность подключения. -->
  {#each s.warnings as w (w.reason)}
    <p class="caption warning">
      {w.count > 1
        ? count(w.count, ["сервер", "сервера", "серверов"], ["servers", "servers"])
        : t("Один сервер", "One server")}: {w.reason}
    </p>
  {/each}

  {#if skipped > 0 || s.duplicates > 0}
    <details class="skipped">
      <summary class="caption">{skippedSummary(s, skipped)}</summary>
      {#if skipped > 0}
        <ul>
          {#each s.skipped as x (x.reason)}
            <li class="caption">{x.reason}{x.count > 1 ? ` ×${x.count}` : ""}</li>
          {/each}
        </ul>
        <p class="caption">{t("KVT пропускает серверы, которые не может подключить, — остальные работают как обычно.", "KVT skips servers it can't connect to — the rest work as usual.")}</p>
      {/if}
    </details>
  {/if}

  {#if s.supportUrl || s.webPageUrl || s.byUrl}
    <div class="links">
      {#if s.byUrl}
        <button
          class="btn ghost"
          aria-expanded={ui.advanced === s.id}
          onclick={() => toggleAdvanced(s)}
        >
          <Icon name="settings" size={16} />{t(`Расширенные${customized(s) ? " · настроено" : ""}`, `Advanced${customized(s) ? " · customized" : ""}`)}
        </button>
      {/if}
      {#if s.supportUrl}
        <button class="btn ghost" onclick={() => act(() => openSubscriptionLink(s.id, "support"))}>
          <Icon name="external" size={16} />{t("Поддержка провайдера", "Provider support")}
        </button>
      {/if}
      {#if s.webPageUrl}
        <button class="btn ghost" onclick={() => act(() => openSubscriptionLink(s.id, "site"))}>
          <Icon name="external" size={16} />{t("Личный кабинет", "Account page")}
        </button>
      {/if}
    </div>
  {/if}

  {#if ui.advanced === s.id}
    <SubscriptionAdvanced {s} onclose={() => (ui.advanced = null)} onchange={reload} />
  {/if}

  {#if s.keys.length > 0}
    <ManualKeys keys={s.keys} {ui} {act} {reload} />
  {/if}
</li>

<style>
  .sub {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    padding: var(--space-4) var(--space-5);
    transition: border-color var(--dur) var(--ease);
  }

  /* Подписка не обновилась — тонкая полоса слева, как у баннеров. */
  .sub.problem {
    border-left: 3px solid var(--warn);
  }

  .caption {
    margin: 0;
  }

  .trouble {
    display: flex;
    align-items: flex-start;
    gap: var(--space-2);
    margin: 0;
    padding: var(--space-2) var(--space-3);
    border-radius: var(--radius-s);
    background: var(--warn-subtle);
    color: var(--text);
  }

  .trouble :global(svg) {
    margin-top: 1px;
    color: var(--warn);
  }

  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-1);
    margin: 0;
    padding: 0;
    list-style: none;
  }

  .chip {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 22px;
    padding: 0 var(--space-2);
    border: 1px solid var(--stroke);
    border-radius: 11px;
    font-size: 12px;
    color: var(--text-2);
  }

  .chip span {
    color: var(--text-3);
    font-variant-numeric: tabular-nums;
  }

  .announce {
    margin: 0;
    padding: var(--space-2) var(--space-3);
    border-radius: var(--radius-s);
    background: var(--accent-subtle);
    white-space: pre-line;
  }

  .warning {
    margin: 0;
    color: var(--warn);
  }

  .skipped summary {
    width: fit-content;
    cursor: pointer;
  }

  .skipped summary:hover {
    color: var(--text-2);
  }

  .skipped ul {
    margin: var(--space-1) 0;
    padding-left: var(--space-5);
  }

  .links {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-1);
    margin: calc(-1 * var(--space-1)) 0 0 calc(-1 * var(--space-2));
  }

  .btn.ghost {
    min-height: 28px;
    border-color: transparent;
    background: transparent;
    color: var(--text-2);
  }

  .btn.ghost:hover:not(:disabled) {
    background: var(--surface-hover);
    color: var(--text);
  }
</style>
