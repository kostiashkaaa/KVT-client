<script lang="ts">
  // Шапка карточки: название (с переименованием), сведения об обновлении и кнопки
  // «Обновить» / «Удалить». Что именно открыто на странице — в `ui` (общее для карточек).
  import { t } from "../i18n";
  import Icon from "../Icon.svelte";
  import { removeSubscription, renameSubscription, type SubscriptionItem } from "../api";
  import { details } from "./format";
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

  const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

  // ── Своё название подписки ──

  let renameValue = $state("");
  let renameError = $state<string | null>(null);

  function startRename(s: SubscriptionItem) {
    ui.renaming = s.id;
    renameValue = s.title;
    renameError = null;
    ui.confirmRemove = null;
  }

  async function saveRename(id: string) {
    renameError = null;
    try {
      await renameSubscription(id, renameValue);
      ui.renaming = null;
      await reload();
    } catch (e) {
      renameError = message(e);
    }
  }

  async function resetRename(id: string) {
    renameValue = "";
    await saveRename(id);
  }

  function selectAll(node: HTMLInputElement) {
    node.focus();
    node.select();
  }
</script>

<div class="head">
  <div class="main">
    {#if ui.renaming === s.id}
      <form
        class="rename"
        onsubmit={(e) => {
          e.preventDefault();
          void saveRename(s.id);
        }}
      >
        <input
          bind:value={renameValue}
          maxlength="80"
          autocomplete="off"
          aria-label={t("Название подписки", "Subscription name")}
          placeholder={s.byUrl ? t("Пусто — название от провайдера", "Empty — the provider's name") : t("Добавлено вручную", "Added manually")}
          use:selectAll
          onkeydown={(e) => {
            if (e.key === "Escape") ui.renaming = null;
          }}
        />
        <button type="submit" class="btn btn-primary">{t("Сохранить", "Save")}</button>
        <button type="button" class="btn" onclick={() => (ui.renaming = null)}>{t("Отмена", "Cancel")}</button>
      </form>
      {#if s.renamed}
        <button class="link-btn caption" onclick={() => void resetRename(s.id)}>
          {t(`Вернуть название ${s.byUrl ? "от провайдера" : "по умолчанию"}`, `Restore the ${s.byUrl ? "provider's" : "default"} name`)}
        </button>
      {/if}
      {#if renameError}
        <p class="error-text appear">{renameError}</p>
      {/if}
    {:else}
      <div class="title-row">
        <h2 class="title" title={s.title}>{s.title}</h2>
        <button class="icon-btn" title={t("Переименовать", "Rename")} aria-label={t(`Переименовать ${s.title}`, `Rename ${s.title}`)} onclick={() => startRename(s)}>
          <Icon name="edit" size={16} />
        </button>
      </div>
    {/if}
    <p class="caption">{details(s)}</p>
  </div>

  <div class="actions">
    {#if ui.confirmRemove === s.id}
      <span class="caption appear">{s.byUrl ? t("Удалить подписку?", "Delete the subscription?") : t("Удалить все ключи?", "Delete all keys?")}</span>
      <button class="btn danger" onclick={() => act(() => removeSubscription(s.id)).then(() => (ui.confirmRemove = null))}>
        {t("Удалить", "Delete")}
      </button>
      <button class="btn" onclick={() => (ui.confirmRemove = null)}>{t("Отмена", "Cancel")}</button>
    {:else if ui.renaming !== s.id}
      {#if s.byUrl}
        <button
          class="btn"
          class:busy={refreshing === s.id || (refreshingAll && s.byUrl)}
          disabled={refreshing !== null || refreshingAll}
          onclick={() => refresh(s.id)}
        >
          {t("Обновить", "Update")}
        </button>
      {/if}
      <button class="btn subtle" onclick={() => ((ui.confirmRemove = s.id), (ui.renaming = null))} aria-label={t(`Удалить ${s.title}`, `Delete ${s.title}`)}>
        {s.byUrl ? t("Удалить", "Delete") : t("Удалить все", "Delete all")}
      </button>
    {/if}
  </div>
</div>

<style>
  .head {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: var(--space-4);
  }

  .main {
    display: flex;
    flex: 1;
    flex-direction: column;
    gap: var(--space-1);
    min-width: 0;
  }

  .title-row {
    display: flex;
    align-items: center;
    gap: var(--space-1);
    min-width: 0;
  }

  .title {
    overflow: hidden;
    white-space: nowrap;
    text-overflow: ellipsis;
  }

  /* Карандаш проявляется при наведении на карточку и при фокусе с клавиатуры. */
  .icon-btn {
    display: grid;
    flex: none;
    place-items: center;
    width: 28px;
    height: 28px;
    border: 0;
    border-radius: var(--radius-s);
    background: transparent;
    color: var(--text-3);
    cursor: pointer;
    opacity: 0;
    transition:
      opacity var(--dur-fast) var(--ease),
      background-color var(--dur-fast) var(--ease);
  }

  :global(.sub:hover) .icon-btn,
  .icon-btn:focus-visible {
    opacity: 1;
  }

  .icon-btn:hover {
    background: var(--surface-hover);
    color: var(--text);
  }

  .rename {
    display: flex;
    gap: var(--space-2);
    max-width: 520px;
  }

  .rename input {
    width: 100%;
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--stroke);
    border-bottom-color: var(--text-3);
    border-radius: var(--radius-s);
    background: var(--surface);
    user-select: text;
    transition: border-color var(--dur-fast) var(--ease);
  }

  .rename input {
    height: 32px;
    font-family: var(--font), "Segoe UI Emoji";
  }

  .rename input {
    flex: 1;
    min-width: 0;
  }

  .rename .btn {
    flex: none;
  }

  /* Как в Windows 11: снизу акцентная линия, высота поля не меняется. */
  .rename input:focus {
    outline: none;
    border-bottom-color: var(--accent);
    box-shadow: inset 0 -1px 0 var(--accent);
  }

  .link-btn {
    align-self: flex-start;
    padding: 0;
    border: 0;
    background: none;
    color: var(--accent);
    cursor: pointer;
  }

  .link-btn:hover {
    text-decoration: underline;
  }

  .caption {
    margin: 0;
  }

  .error-text {
    margin: 0;
    color: var(--danger);
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

  /* Узкое окно: кнопки карточки уходят под название. */
  @container main (max-width: 620px) {
    .head {
      flex-direction: column;
      align-items: stretch;
    }

    .actions {
      flex-wrap: wrap;
    }
  }
</style>
