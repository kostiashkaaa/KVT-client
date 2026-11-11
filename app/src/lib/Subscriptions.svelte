<script lang="ts">
  import { slide } from "svelte/transition";
  import Banner from "./Banner.svelte";
  import Flag from "./Flag.svelte";
  import ServerName from "./ServerName.svelte";
  import Icon from "./Icon.svelte";
  import Migration from "./Migration.svelte";
  import {
    listSubscriptions,
    onSubscriptionsChanged,
    openSubscriptionLink,
    refreshAllSubscriptions,
    refreshSubscription,
    removeSubscription,
    removeServer,
    renameSubscription,
    editServer,
    type ManualKey,
    type SubscriptionItem,
  } from "./api";

  /** Открывает панель добавления (та же, что у «+» на главной). */
  let { onadd }: { onadd: () => void } = $props();

  let items = $state<SubscriptionItem[]>([]);
  let loaded = $state(false);
  let refreshing = $state<string | null>(null);
  let refreshingAll = $state(false);
  let confirmRemove = $state<string | null>(null);
  let error = $state<string | null>(null);
  /** Итог «Обновить все» — сведение, а не ошибка: причины видны у подписок. */
  let summary = $state<string | null>(null);

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
          ? "Все подписки обновлены."
          : `Не обновилось: ${failed} из ${byUrl.length} — причина указана у подписки. Серверы из прошлой версии остаются.`;
    } catch (e) {
      error = message(e);
    }
    await reload();
    refreshingAll = false;
  }

  // ── Своё название подписки ──

  let renaming = $state<string | null>(null);
  let renameValue = $state("");
  let renameError = $state<string | null>(null);

  function startRename(s: SubscriptionItem) {
    renaming = s.id;
    renameValue = s.title;
    renameError = null;
    confirmRemove = null;
  }

  async function saveRename(id: string) {
    renameError = null;
    try {
      await renameSubscription(id, renameValue);
      renaming = null;
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
      editError = message(e);
    } finally {
      saving = false;
    }
  }

  // ── Тексты ──

  const protocols: Record<string, string> = {
    vless: "VLESS",
    trojan: "Trojan",
    shadowsocks: "Shadowsocks",
    hysteria2: "Hysteria2",
    vmess: "VMess",
    tuic: "TUIC",
    anytls: "AnyTLS",
    socks: "SOCKS5",
    http: "HTTP-прокси",
  };
  const protocolTitle = (p: string) => protocols[p] ?? p.toUpperCase();

  function plural(n: number, one: string, few: string, many: string): string {
    const d = n % 10;
    const dd = n % 100;
    if (d === 1 && dd !== 11) return one;
    if (d >= 2 && d <= 4 && (dd < 12 || dd > 14)) return few;
    return many;
  }

  const GB = 2 ** 30;
  const gb = (b: number) => (b / GB).toLocaleString("ru-RU", { maximumFractionDigits: b < 10 * GB ? 1 : 0 });

  function ago(unix: number): string {
    const min = Math.max(0, Math.round((Date.now() / 1000 - unix) / 60));
    if (min < 1) return "только что";
    if (min < 60) return `${min} мин назад`;
    const h = Math.round(min / 60);
    if (h < 24) return `${h} ч назад`;
    return `${Math.round(h / 24)} дн назад`;
  }

  function inFuture(unix: number): string {
    const min = Math.round((unix - Date.now() / 1000) / 60);
    if (min < 1) return "скоро";
    if (min < 60) return `через ${min} мин`;
    const h = Math.round(min / 60);
    if (h < 48) return `через ${h} ч`;
    return `через ${Math.round(h / 24)} дн`;
  }

  function details(s: SubscriptionItem): string {
    // Перенесённая подписка, которую ещё не удалось загрузить.
    if (s.byUrl && s.servers === 0) return "ещё не загружена — нажмите «Обновить», когда будет доступ к сайту провайдера";
    const servers = `${s.servers} ${plural(s.servers, "сервер", "сервера", "серверов")}`;
    if (!s.byUrl) return `${servers} · добавлены вручную, не обновляются`;
    return [servers, `обновлена ${ago(s.updatedAt)}`, s.nextUpdate ? `следующее ${inFuture(s.nextUpdate)}` : null]
      .filter(Boolean)
      .join(" · ");
  }

  type Tone = "ok" | "warn" | "danger";

  function expiry(unix: number): { text: string; tone: Tone } {
    const days = Math.ceil((unix * 1000 - Date.now()) / 86_400_000);
    const date = new Date(unix * 1000).toLocaleDateString("ru-RU", { day: "numeric", month: "long" });
    if (days < 0) return { text: `Закончилась ${date} — продлите у провайдера`, tone: "danger" };
    if (days === 0) return { text: "Заканчивается сегодня", tone: "danger" };
    const left = `осталось ${days} ${plural(days, "день", "дня", "дней")}`;
    return { text: `До ${date} · ${left}`, tone: days <= 3 ? "warn" : "ok" };
  }

  function usage(s: SubscriptionItem): { text: string; share: number | null; tone: Tone } | null {
    if (s.usedBytes == null) return null;
    if (!s.totalBytes) return { text: `Израсходовано ${gb(s.usedBytes)} ГБ · без лимита`, share: null, tone: "ok" };
    const share = s.usedBytes / s.totalBytes;
    const left = Math.max(0, s.totalBytes - s.usedBytes);
    return {
      text: share >= 1 ? `Трафик закончился: ${gb(s.totalBytes)} ГБ` : `${gb(s.usedBytes)} из ${gb(s.totalBytes)} ГБ · осталось ${gb(left)} ГБ`,
      share: Math.min(1, share),
      tone: share >= 1 ? "danger" : share > 0.9 ? "warn" : "ok",
    };
  }

  const skippedCount = (s: SubscriptionItem) => s.skipped.reduce((n, x) => n + x.count, 0);

  function skippedSummary(s: SubscriptionItem, skipped: number): string {
    return [
      skipped > 0 ? `Пропущено ${skipped} ${plural(skipped, "строка", "строки", "строк")}` : null,
      s.duplicates > 0 ? `убрано повторов: ${s.duplicates}` : null,
    ]
      .filter(Boolean)
      .join(" · ");
  }

  /** Причина неудачного обновления одной фразой, с точкой в конце. */
  function trouble(s: SubscriptionItem, at: number): string {
    const reason = s.lastError?.trim().replace(/[.!]*$/, ".") ?? "";
    const old = s.servers > 0 ? " Пока работают серверы из прошлой версии." : "";
    return `Не обновилась ${ago(at)}: ${reason}${old}`;
  }
</script>

<div class="top">
  <p class="muted">Серверы всех подписок — в одном списке на главной. Здесь — обновление, названия и ключи, добавленные вручную.</p>
  <div class="top-actions">
    {#if byUrl.length > 1}
      <button class="btn" class:busy={refreshingAll} disabled={refreshingAll || refreshing !== null} onclick={refreshAll}>
        <Icon name="refresh" size={16} />Обновить все
      </button>
    {/if}
    <button class="btn btn-primary" onclick={onadd}><Icon name="plus" size={16} />Добавить</button>
  </div>
</div>

{#if error}
  <Banner>
    {error}
    {#snippet action()}
      <button class="btn" onclick={() => (error = null)}>Понятно</button>
    {/snippet}
  </Banner>
{/if}

{#if summary}
  <Banner tone="info">
    {summary}
    {#snippet action()}
      <button class="btn" onclick={() => (summary = null)}>Скрыть</button>
    {/snippet}
  </Banner>
{/if}

{#if items.length > 0}
  <ul class="list">
    {#each items as s (s.id)}
      {@const use = usage(s)}
      {@const exp = s.expire ? expiry(s.expire) : null}
      {@const skipped = skippedCount(s)}
      <li class="card sub" class:problem={!!s.lastError}>
        <div class="head">
          <div class="main">
            {#if renaming === s.id}
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
                  aria-label="Название подписки"
                  placeholder={s.byUrl ? "Пусто — название от провайдера" : "Добавлено вручную"}
                  use:selectAll
                  onkeydown={(e) => {
                    if (e.key === "Escape") renaming = null;
                  }}
                />
                <button type="submit" class="btn btn-primary">Сохранить</button>
                <button type="button" class="btn" onclick={() => (renaming = null)}>Отмена</button>
              </form>
              {#if s.renamed}
                <button class="link-btn caption" onclick={() => void resetRename(s.id)}>
                  Вернуть название {s.byUrl ? "от провайдера" : "по умолчанию"}
                </button>
              {/if}
              {#if renameError}
                <p class="error-text appear">{renameError}</p>
              {/if}
            {:else}
              <div class="title-row">
                <h2 class="title" title={s.title}>{s.title}</h2>
                <button class="icon-btn" title="Переименовать" aria-label={`Переименовать ${s.title}`} onclick={() => startRename(s)}>
                  <Icon name="edit" size={16} />
                </button>
              </div>
            {/if}
            <p class="caption">{details(s)}</p>
          </div>

          <div class="actions">
            {#if confirmRemove === s.id}
              <span class="caption appear">{s.byUrl ? "Удалить подписку?" : "Удалить все ключи?"}</span>
              <button class="btn danger" onclick={() => act(() => removeSubscription(s.id)).then(() => (confirmRemove = null))}>
                Удалить
              </button>
              <button class="btn" onclick={() => (confirmRemove = null)}>Отмена</button>
            {:else if renaming !== s.id}
              {#if s.byUrl}
                <button
                  class="btn"
                  class:busy={refreshing === s.id || (refreshingAll && s.byUrl)}
                  disabled={refreshing !== null || refreshingAll}
                  onclick={() => refresh(s.id)}
                >
                  Обновить
                </button>
              {/if}
              <button class="btn subtle" onclick={() => ((confirmRemove = s.id), (renaming = null))} aria-label={`Удалить ${s.title}`}>
                {s.byUrl ? "Удалить" : "Удалить все"}
              </button>
            {/if}
          </div>
        </div>

        {#if s.lastError && s.failedAt}
          <p class="trouble appear">
            <Icon name="warning" size={16} />
            <span>{trouble(s, s.failedAt)}</span>
          </p>
        {/if}

        {#if use || exp}
          <div class="stats">
            {#if use}
              <div class="stat">
                {#if use.share !== null}
                  <div class="bar {use.tone}" role="progressbar" aria-label="Трафик" aria-valuenow={Math.round(use.share * 100)} aria-valuemin="0" aria-valuemax="100">
                    <span style:width={`${use.share * 100}%`}></span>
                  </div>
                {/if}
                <span class="caption {use.tone}">{use.text}</span>
              </div>
            {/if}
            {#if exp}
              <span class="caption {exp.tone}">{exp.text}</span>
            {/if}
          </div>
        {/if}

        <!-- У ручной группы протокол виден у каждого ключа — сводка не нужна. -->
        {#if s.byUrl && s.protocols.length > 0}
          <ul class="chips" aria-label="Протоколы серверов">
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

        <!-- Не прячем под «подробнее»: это про безопасность подключения. -->
        {#each s.warnings as w (w.reason)}
          <p class="caption warning">
            {w.count > 1 ? `${w.count} ${plural(w.count, "сервер", "сервера", "серверов")}` : "Один сервер"}: {w.reason}
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
              <p class="caption">KVT пропускает серверы, которые не может подключить, — остальные работают как обычно.</p>
            {/if}
          </details>
        {/if}

        {#if s.supportUrl || s.webPageUrl}
          <div class="links">
            {#if s.supportUrl}
              <button class="btn ghost" onclick={() => act(() => openSubscriptionLink(s.id, "support"))}>
                <Icon name="external" size={16} />Поддержка провайдера
              </button>
            {/if}
            {#if s.webPageUrl}
              <button class="btn ghost" onclick={() => act(() => openSubscriptionLink(s.id, "site"))}>
                <Icon name="external" size={16} />Личный кабинет
              </button>
            {/if}
          </div>
        {/if}

        {#if s.keys.length > 0}
          <ul class="keys">
            {#each s.keys as k (k.key)}
              <li class="key">
                <div class="key-row">
                  <Flag code={k.flag} />
                  <div class="key-text">
                    <span class="key-name"><ServerName name={k.title} /></span>
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
    запись. Подписки по ссылке обновляются сами по расписанию провайдера, не чаще раза в час.
  </p>
{:else if loaded}
  <section class="card empty">
    <div class="empty-icon" aria-hidden="true"><Icon name="list" size={28} /></div>
    <h2>Подписок пока нет</h2>
    <p class="muted">
      Вставьте ссылку из личного кабинета провайдера или ключи серверов. Подписки из v2rayN, Hiddify и других клиентов
      можно перенести — ниже.
    </p>
    <button class="btn btn-primary" onclick={onadd}><Icon name="plus" size={16} />Добавить подписку</button>
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

  .sub:hover .icon-btn,
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

  .rename input,
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

  .rename input,
  .editor input {
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
  .rename input:focus,
  .editor input:focus,
  .editor textarea:focus {
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

  .caption.warn {
    color: var(--warn);
  }

  .caption.danger {
    color: var(--danger);
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

  .stats {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-2) var(--space-6);
  }

  .stat {
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
    border-radius: 2px;
    background: var(--accent);
    transition: width 300ms var(--ease);
  }

  .bar.warn span {
    background: var(--warn);
  }

  .bar.danger span {
    background: var(--danger);
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

  .editor textarea {
    font: 12px/18px var(--mono);
    resize: vertical;
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

  /* Узкое окно: кнопки карточки уходят под название. */
  @container main (max-width: 620px) {
    .top,
    .head {
      flex-direction: column;
      align-items: stretch;
    }

    .top-actions,
    .actions {
      flex-wrap: wrap;
    }
  }
</style>
