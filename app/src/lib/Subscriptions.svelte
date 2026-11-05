<script lang="ts">
  import { slide } from "svelte/transition";
  import Banner from "./Banner.svelte";
  import Flag from "./Flag.svelte";
  import Icon from "./Icon.svelte";
  import Migration from "./Migration.svelte";
  import {
    listSubscriptions,
    onSubscriptionsChanged,
    refreshSubscription,
    removeSubscription,
    removeServer,
    editServer,
    type ManualKey,
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

  // ── Ключи, добавленные вручную: каждый правится и удаляется отдельно ──

  /** Ключ, который сейчас редактируется. */
  let editing = $state<string | null>(null);
  let editName = $state("");
  let editLink = $state("");
  let saving = $state(false);
  let editError = $state<string | null>(null);
  /** Ключ, удаление которого ждёт подтверждения. */
  let confirmKey = $state<string | null>(null);

  function startEdit(k: ManualKey) {
    editing = k.key;
    editName = k.name;
    editLink = "";
    editError = null;
    confirmKey = null;
  }

  async function saveEdit(key: string) {
    saving = true;
    editError = null;
    try {
      await editServer(key, editName, editLink.trim() || null);
      editing = null;
      await reload();
    } catch (e) {
      // Ошибка — у формы, а не над всей страницей: форма остаётся открытой.
      editError = e instanceof Error ? e.message : String(e);
    } finally {
      saving = false;
    }
  }

  const protocols: Record<string, string> = {
    vless: "VLESS",
    trojan: "Trojan",
    shadowsocks: "Shadowsocks",
    hysteria2: "Hysteria2",
  };
  const protocolTitle = (p: string) => protocols[p] ?? p.toUpperCase();

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
  <p class="muted">Серверы всех подписок — в одном списке на главной. Здесь — обновление, удаление и правка ключей, добавленных вручную.</p>
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
        <div class="head">
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
              {s.byUrl ? "Удалить" : "Удалить все"}
            </button>
          {/if}
        </div>
        </div>

        {#if s.keys.length > 0}
          <ul class="keys">
            {#each s.keys as k (k.key)}
              <li class="key">
                <div class="key-row">
                  <Flag code={k.flag} />
                  <div class="key-text">
                    <span class="key-name">{k.title}</span>
                    <span class="caption">{protocolTitle(k.protocol)} · {k.address}:{k.port}</span>
                  </div>
                  <div class="actions">
                    {#if confirmKey === k.key}
                      <span class="caption appear">Удалить ключ?</span>
                      <button
                        class="btn danger"
                        onclick={() => act(() => removeServer(k.key)).then(() => (confirmKey = null))}
                      >
                        Удалить
                      </button>
                      <button class="btn" onclick={() => (confirmKey = null)}>Отмена</button>
                    {:else if editing !== k.key}
                      <button class="btn" onclick={() => startEdit(k)} aria-label={`Изменить ${k.name}`}>Изменить</button>
                      <button
                        class="btn subtle"
                        onclick={() => ((confirmKey = k.key), (editing = null))}
                        aria-label={`Удалить ${k.name}`}
                      >
                        Удалить
                      </button>
                    {/if}
                  </div>
                </div>

                {#if editing === k.key}
                  <form
                    class="editor"
                    transition:slide={{ duration: 150 }}
                    onsubmit={(e) => {
                      e.preventDefault();
                      void saveEdit(k.key);
                    }}
                  >
                    <label for="name-{k.key}">Название</label>
                    <input id="name-{k.key}" bind:value={editName} maxlength="120" autocomplete="off" />
                    <label for="link-{k.key}">Новая ссылка</label>
                    <textarea
                      id="link-{k.key}"
                      bind:value={editLink}
                      rows="2"
                      spellcheck="false"
                      placeholder="vless://… — оставьте пустым, чтобы ключ остался прежним"
                    ></textarea>
                    <p class="caption">
                      Текущая ссылка не показывается: в ней пароль или UUID сервера. Если название пустое, возьмётся
                      из новой ссылки.
                    </p>
                    {#if editError}
                      <p class="error-text appear">{editError}</p>
                    {/if}
                    <div class="editor-actions">
                      <button type="submit" class="btn btn-primary" class:busy={saving} disabled={saving}>
                        Сохранить
                      </button>
                      <button type="button" class="btn" disabled={saving} onclick={() => (editing = null)}>
                        Отмена
                      </button>
                    </div>
                  </form>
                {/if}
              </li>
            {/each}
          </ul>
        {/if}
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

  .list > li {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    padding: var(--space-4) var(--space-5);
  }

  .head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-4);
  }

  /* Ключи ручной группы — строками под заголовком карточки. */
  .keys {
    display: flex;
    flex-direction: column;
    margin: 0 calc(-1 * var(--space-2));
    padding: 0;
    list-style: none;
  }

  .key {
    padding: var(--space-2);
    border-top: 1px solid var(--stroke);
  }

  .key-row {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    min-height: 32px;
  }

  .key-text {
    display: flex;
    flex: 1;
    flex-direction: column;
    min-width: 0;
  }

  .key-name {
    overflow: hidden;
    font-family: var(--font), "Segoe UI Emoji";
    white-space: nowrap;
    text-overflow: ellipsis;
  }

  .key-text .caption {
    overflow: hidden;
    white-space: nowrap;
    text-overflow: ellipsis;
  }

  .editor {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    max-width: 560px;
    padding: var(--space-3) 0 var(--space-2) calc(20px + var(--space-3));
  }

  .editor label {
    font-size: 12px;
    color: var(--text-2);
  }

  .editor input,
  .editor textarea {
    width: 100%;
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--stroke);
    border-bottom-color: var(--text-3);
    border-radius: var(--radius-s);
    background: var(--surface);
    user-select: text;
    transition: border-color var(--dur-fast) var(--ease);
  }

  .editor input {
    height: 32px;
    font-family: var(--font), "Segoe UI Emoji";
  }

  .editor textarea {
    font: 12px/18px var(--mono);
    resize: vertical;
  }

  /* Как в Windows 11: снизу акцентная линия, высота поля не меняется. */
  .editor input:focus,
  .editor textarea:focus {
    outline: none;
    border-bottom-color: var(--accent);
    box-shadow: inset 0 -1px 0 var(--accent);
  }

  .editor-actions {
    display: flex;
    gap: var(--space-2);
    margin-top: var(--space-1);
  }

  .error-text {
    margin: 0;
    color: var(--danger);
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
