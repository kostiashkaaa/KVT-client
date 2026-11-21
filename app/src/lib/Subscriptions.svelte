<script lang="ts">
  import { t } from "./i18n";
  import Banner from "./Banner.svelte";
  import Icon from "./Icon.svelte";
  import Migration from "./Migration.svelte";
  import SubscriptionCard from "./subscriptions/SubscriptionCard.svelte";
  import { ListUi } from "./subscriptions/ui.svelte";
  import {
    listSubscriptions,
    onSubscriptionsChanged,
    refreshAllSubscriptions,
    refreshSubscription,
    type SubscriptionItem,
  } from "./api";

  /** Открывает панель добавления (та же, что у «+» на главной). */
  let { onadd }: { onadd: () => void } = $props();

  let items = $state<SubscriptionItem[]>([]);
  let loaded = $state(false);
  let refreshing = $state<string | null>(null);
  let refreshingAll = $state(false);
  let error = $state<string | null>(null);
  /** Итог «Обновить все» — сведение, а не ошибка: причины видны у подписок. */
  let summary = $state<string | null>(null);
  /** Что открыто в карточках — одно на всю страницу. */
  const ui = new ListUi();

  async function reload() {
    items = await listSubscriptions();
    loaded = true;
  }

  $effect(() => {
    void reload();
    return onSubscriptionsChanged(() => void reload());
  });

  const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

  async function act(fn: () => Promise<unknown>) {
    error = null;
    try {
      await fn();
    } catch (e) {
      error = message(e);
    }
    await reload();
  }

  const byUrl = $derived(items.filter((s) => s.byUrl));

  async function refresh(id: string) {
    refreshing = id;
    summary = null;
    try {
      await refreshSubscription(id);
    } catch {
      // Причина остаётся у самой подписки (строка «Не обновилась…»), без второго баннера.
    }
    await reload();
    refreshing = null;
  }

  async function refreshAll() {
    refreshingAll = true;
    summary = null;
    error = null;
    try {
      const failed = await refreshAllSubscriptions();
      summary =
        failed === 0
          ? t("Все подписки обновлены.", "All subscriptions updated.")
          : t(`Не обновилось: ${failed} из ${byUrl.length} — причина указана у подписки. Серверы из прошлой версии остаются.`, `Not updated: ${failed} of ${byUrl.length} — the reason is shown on the subscription. Servers from the previous version remain.`);
    } catch (e) {
      error = message(e);
    }
    await reload();
    refreshingAll = false;
  }
</script>

<div class="top">
  <p class="muted">{t("Серверы всех подписок — в одном списке на главной. Здесь — обновление, названия и ключи, добавленные вручную.", "Servers from all subscriptions are in one list on the home page. Here you update them and manage names and manually added keys.")}</p>
  <div class="top-actions">
    {#if byUrl.length > 1}
      <button class="btn" class:busy={refreshingAll} disabled={refreshingAll || refreshing !== null} onclick={refreshAll}>
        <Icon name="refresh" size={16} />{t("Обновить все", "Update all")}
      </button>
    {/if}
    <button class="btn btn-primary" onclick={onadd}><Icon name="plus" size={16} />{t("Добавить", "Add")}</button>
  </div>
</div>

{#if error}
  <Banner>
    {error}
    {#snippet action()}
      <button class="btn" onclick={() => (error = null)}>{t("Понятно", "Got it")}</button>
    {/snippet}
  </Banner>
{/if}

{#if summary}
  <Banner tone="info">
    {summary}
    {#snippet action()}
      <button class="btn" onclick={() => (summary = null)}>{t("Скрыть", "Hide")}</button>
    {/snippet}
  </Banner>
{/if}

{#if items.length > 0}
  <ul class="list">
    {#each items as s (s.id)}
      <SubscriptionCard {s} {ui} {refreshing} {refreshingAll} {act} {refresh} {reload} />
    {/each}
  </ul>
  <p class="caption note">
    {t("Ссылки подписок и ключи серверов хранятся зашифрованными (DPAPI Windows) — прочитать их может только ваша учётная запись. Подписки по ссылке обновляются сами по расписанию провайдера, не чаще раза в час.", "Subscription links and server keys are stored encrypted (Windows DPAPI) — only your account can read them. Link subscriptions update on the provider's schedule, at most once an hour.")}
  </p>
{:else if loaded}
  <section class="card empty">
    <div class="empty-icon" aria-hidden="true"><Icon name="list" size={28} /></div>
    <h2>{t("Подписок пока нет", "No subscriptions yet")}</h2>
    <p class="muted">
      {t("Вставьте ссылку из личного кабинета провайдера или ключи серверов. Подписки из v2rayN, Hiddify и других клиентов можно перенести — ниже.", "Paste the link from your provider's account page or server keys. You can import subscriptions from v2rayN, Hiddify and other clients — below.")}
    </p>
    <button class="btn btn-primary" onclick={onadd}><Icon name="plus" size={16} />{t("Добавить подписку", "Add subscription")}</button>
  </section>
{/if}

<Migration />

<style>
  .top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-4);
  }

  .top p {
    margin: 0;
  }

  .top-actions {
    display: flex;
    flex: none;
    gap: var(--space-2);
  }

  .list {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    margin: 0;
    padding: 0;
    list-style: none;
  }

  .caption {
    margin: 0;
  }

  .note {
    max-width: var(--measure);
  }

  .empty {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-8) var(--space-6);
    text-align: center;
  }

  .empty p {
    max-width: 440px;
    margin: 0;
  }

  .empty-icon {
    color: var(--accent);
  }

  /* Узкое окно: кнопки уходят под текст. */
  @container main (max-width: 620px) {
    .top {
      flex-direction: column;
      align-items: stretch;
    }

    .top-actions {
      flex-wrap: wrap;
    }
  }
</style>
