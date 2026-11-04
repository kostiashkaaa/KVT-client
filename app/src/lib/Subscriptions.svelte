<script lang="ts">
  import Banner from "./Banner.svelte";
  import Icon from "./Icon.svelte";
  import Migration from "./Migration.svelte";
  import {
    listSubscriptions,
    onSubscriptionsChanged,
    refreshSubscription,
    removeSubscription,
    type SubscriptionItem,
  } from "./api";

  /** Открывает панель добавления (та же, что у «+» на главной). */
  let { onadd }: { onadd: () => void } = $props();

  let items = $state<SubscriptionItem[]>([]);
  let refreshing = $state<string | null>(null);
  let confirmRemove = $state<string | null>(null);
  let error = $state<string | null>(null);

  async function reload() {
    items = await listSubscriptions();
  }

  $effect(() => {
    void reload();
    return onSubscriptionsChanged(() => void reload());
  });

  async function act(fn: () => Promise<unknown>) {
    error = null;
    try {
      await fn();
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
    await reload();
  }

  async function refresh(id: string) {
    refreshing = id;
    await act(() => refreshSubscription(id));
    refreshing = null;
  }

  const GB = 2 ** 30;
  const gb = (b: number) => (b / GB).toLocaleString("ru-RU", { maximumFractionDigits: 1 });

  function ago(unix: number): string {
    const min = Math.max(0, Math.round((Date.now() / 1000 - unix) / 60));
    if (min < 1) return "только что";
    if (min < 60) return `${min} мин назад`;
    const h = Math.round(min / 60);
    if (h < 24) return `${h} ч назад`;
    return `${Math.round(h / 24)} дн назад`;
  }

  function details(s: SubscriptionItem): string {
    return [
      // Перенесённая подписка, которую ещё не удалось загрузить.
      s.byUrl && s.servers === 0 ? "ещё не загружена — нажмите «Обновить» после подключения" : `${s.servers} серв.`,
      s.byUrl && s.servers === 0 ? null : `обновлена ${ago(s.updatedAt)}`,
      s.expire ? until(s.expire) : null,
      s.byUrl ? null : "без ссылки, не обновляется",
    ]
      .filter(Boolean)
      .join(" · ");
  }

  function until(unix: number): string {
    const days = Math.ceil((unix * 1000 - Date.now()) / 86_400_000);
    if (days < 0) return "закончилась";
    return `до ${new Date(unix * 1000).toLocaleDateString("ru-RU", { day: "numeric", month: "long" })}`;
  }
</script>

<div class="top">
  <p class="muted">Серверы всех подписок — в одном списке на главной. Здесь — обновление и удаление.</p>
  <button class="btn btn-primary" onclick={onadd}><Icon name="plus" size={16} />Добавить</button>
</div>

{#if error}
  <Banner>
    {error}
    {#snippet action()}
      <button class="btn" onclick={() => (error = null)}>Понятно</button>
    {/snippet}
  </Banner>
{/if}

{#if items.length > 0}
  <ul class="list">
    {#each items as s (s.id)}
      <li class="card">
        <div class="main">
          <h2 class="title">{s.title}</h2>
          <p class="caption">{details(s)}</p>
          {#if s.usedBytes != null && s.totalBytes}
            <div class="usage">
              <div class="bar" class:warn={s.usedBytes / s.totalBytes > 0.9}>
                <span style:width={`${Math.min(100, (s.usedBytes / s.totalBytes) * 100)}%`}></span>
              </div>
              <span class="caption">{gb(s.usedBytes)} из {gb(s.totalBytes)} ГБ</span>
            </div>
          {/if}
        </div>

        <div class="actions">
          {#if confirmRemove === s.id}
            <span class="caption appear">Удалить подписку?</span>
            <button class="btn danger" onclick={() => act(() => removeSubscription(s.id)).then(() => (confirmRemove = null))}>
              Удалить
            </button>
            <button class="btn" onclick={() => (confirmRemove = null)}>Отмена</button>
          {:else}
            {#if s.byUrl}
              <button
                class="btn"
                class:busy={refreshing === s.id}
                disabled={refreshing !== null}
                onclick={() => refresh(s.id)}
              >
                Обновить
              </button>
            {/if}
            <button class="btn subtle" onclick={() => (confirmRemove = s.id)} aria-label={`Удалить ${s.title}`}>
              Удалить
            </button>
          {/if}
        </div>
      </li>
    {/each}
  </ul>
  <p class="caption note">
    Ссылки подписок и ключи серверов хранятся зашифрованными (DPAPI Windows) — прочитать их может только ваша учётная
    запись. Подписки по ссылке обновляются автоматически по расписанию провайдера, не чаще раза в час.
  </p>
{/if}

<Migration />

<style>
  .list {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    margin: 0;
    padding: 0;
    list-style: none;
  }

  li {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-4);
    padding: var(--space-4) var(--space-5);
  }

  .main {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    min-width: 0;
  }

  .title {
    overflow: hidden;
    white-space: nowrap;
    text-overflow: ellipsis;
  }

  .top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-4);
  }

  .top p {
    margin: 0;
  }

  .top .btn {
    flex: none;
  }

  .caption {
    margin: 0;
  }

  .usage {
    display: flex;
    align-items: center;
    gap: var(--space-3);
  }

  .bar {
    width: 160px;
    height: 4px;
    border-radius: 2px;
    background: var(--stroke);
    overflow: hidden;
  }

  .bar span {
    display: block;
    height: 100%;
    background: var(--accent);
    transition: width 300ms var(--ease);
  }

  .bar.warn span {
    background: var(--warn);
  }

  .actions {
    display: flex;
    flex: none;
    align-items: center;
    gap: var(--space-2);
  }

  .btn.subtle {
    border-color: transparent;
    background: transparent;
    color: var(--text-2);
  }

  .btn.subtle:hover {
    background: var(--surface-hover);
    color: var(--danger);
  }

  .btn.danger {
    border-color: transparent;
    background: var(--danger);
    color: var(--accent-text);
  }

  .btn.danger:hover {
    background: var(--danger);
    opacity: 0.9;
  }

  .note {
    max-width: var(--measure);
  }

</style>
