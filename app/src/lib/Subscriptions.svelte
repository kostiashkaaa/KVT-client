<script lang="ts">
  import { count, locale, t } from "./i18n";
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
    setSubscriptionOptions,
    type HwidMode,
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
          ? t("Все подписки обновлены.", "All subscriptions updated.")
          : t(`Не обновилось: ${failed} из ${byUrl.length} — причина указана у подписки. Серверы из прошлой версии остаются.`, `Not updated: ${failed} of ${byUrl.length} — the reason is shown on the subscription. Servers from the previous version remain.`);
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

  // ── «Расширенные»: фильтр серверов, клиент, ID устройства ──

  /** Подписка, у которой открыты «Расширенные». */
  let advanced = $state<string | null>(null);
  let keep = $state("");
  let drop = $state("");
  let client = $state<string>("auto");
  let userAgent = $state("");
  let hwid = $state<HwidMode>("auto");
  let ownHwid = $state("");
  /** Убрать ID от провайдера при сохранении. */
  let clearOwnHwid = $state(false);
  let advancedSaving = $state(false);
  let advancedError = $state<string | null>(null);

  const clients: [string, string][] = [
    ["auto", t("Авто — подобрать самому", "Auto — pick automatically")],
    ["v2rayng", "v2rayNG"],
    ["v2rayn", "v2rayN"],
    ["hiddify", "Hiddify"],
    ["happ", "Happ"],
    ["incy", "INCY"],
    ["v2raytun", "v2RayTun"],
    ["kvt", "KVT"],
    ["custom", t("Свой User-Agent", "Custom User-Agent")],
  ];

  function toggleAdvanced(s: SubscriptionItem) {
    if (advanced === s.id) {
      advanced = null;
      return;
    }
    advanced = s.id;
    keep = s.options.keep.join(", ");
    drop = s.options.drop.join(", ");
    client = s.options.client ?? "auto";
    userAgent = s.options.userAgent ?? "";
    hwid = s.options.hwid;
    ownHwid = "";
    clearOwnHwid = false;
    advancedError = null;
  }

  /** Настроено что-то кроме значений по умолчанию — видно на кнопке. */
  const customized = (s: SubscriptionItem) =>
    s.options.keep.length + s.options.drop.length > 0 ||
    s.options.client !== null ||
    s.options.hwid !== "auto" ||
    s.options.ownHwid;

  async function saveAdvanced(id: string) {
    advancedSaving = true;
    advancedError = null;
    try {
      await setSubscriptionOptions(id, {
        keep,
        drop,
        client: client === "auto" ? null : client,
        userAgent,
        hwid,
        ownHwid: clearOwnHwid ? "" : ownHwid.trim() || null,
      });
      advanced = null;
    } catch (e) {
      // Настройки могли сохраниться, а загрузка — не пройти: причина видна у формы.
      advancedError = message(e);
    } finally {
      advancedSaving = false;
    }
    await reload();
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
    http: t("HTTP-прокси", "HTTP proxy"),
  };
  const protocolTitle = (p: string) => protocols[p] ?? p.toUpperCase();

  const GB = 2 ** 30;
  const gb = (b: number) => (b / GB).toLocaleString(locale(), { maximumFractionDigits: b < 10 * GB ? 1 : 0 });

  function ago(unix: number): string {
    const min = Math.max(0, Math.round((Date.now() / 1000 - unix) / 60));
    if (min < 1) return t("только что", "just now");
    if (min < 60) return t(`${min} мин назад`, `${min} min ago`);
    const h = Math.round(min / 60);
    if (h < 24) return t(`${h} ч назад`, `${h} h ago`);
    return t(`${Math.round(h / 24)} дн назад`, `${Math.round(h / 24)} d ago`);
  }

  function inFuture(unix: number): string {
    const min = Math.round((unix - Date.now() / 1000) / 60);
    if (min < 1) return t("скоро", "soon");
    if (min < 60) return t(`через ${min} мин`, `in ${min} min`);
    const h = Math.round(min / 60);
    if (h < 48) return t(`через ${h} ч`, `in ${h} h`);
    return t(`через ${Math.round(h / 24)} дн`, `in ${Math.round(h / 24)} d`);
  }

  function details(s: SubscriptionItem): string {
    // Перенесённая подписка, которую ещё не удалось загрузить.
    if (s.byUrl && s.servers === 0 && s.hidden === 0)
      return t("ещё не загружена — нажмите «Обновить», когда будет доступ к сайту провайдера", "not loaded yet — press “Update” once the provider's site is reachable");
    const hidden = s.hidden > 0 ? t(` (ещё ${s.hidden} скрыто фильтром)`, `(${s.hidden} more hidden by the filter)`) : "";
    const servers = `${count(s.servers, ["сервер", "сервера", "серверов"], ["server", "servers"])}${hidden}`;
    if (!s.byUrl) return t(`${servers} · добавлены вручную, не обновляются`, `${servers} · added manually, not updated`);
    return [servers, t(`обновлена ${ago(s.updatedAt)}`, `updated ${ago(s.updatedAt)}`), s.nextUpdate ? t(`следующее ${inFuture(s.nextUpdate)}`, `next ${inFuture(s.nextUpdate)}`) : null]
      .filter(Boolean)
      .join(" · ");
  }

  type Tone = "ok" | "warn" | "danger";

  function expiry(unix: number): { text: string; tone: Tone } {
    const days = Math.ceil((unix * 1000 - Date.now()) / 86_400_000);
    const date = new Date(unix * 1000).toLocaleDateString(locale(), { day: "numeric", month: "long" });
    if (days < 0) return { text: t(`Закончилась ${date} — продлите у провайдера`, `Expired ${date} — renew with your provider`), tone: "danger" };
    if (days === 0) return { text: t("Заканчивается сегодня", "Expires today"), tone: "danger" };
    const left = t(
      `осталось ${count(days, ["день", "дня", "дней"], ["", ""])}`,
      `${count(days, ["", "", ""], ["day", "days"])} left`,
    );
    return { text: t(`До ${date} · ${left}`, `Until ${date} · ${left}`), tone: days <= 3 ? "warn" : "ok" };
  }

  function usage(s: SubscriptionItem): { text: string; share: number | null; tone: Tone } | null {
    if (s.usedBytes == null) return null;
    if (!s.totalBytes) return { text: t(`Израсходовано ${gb(s.usedBytes)} ГБ · без лимита`, `Used ${gb(s.usedBytes)} GB · no limit`), share: null, tone: "ok" };
    const share = s.usedBytes / s.totalBytes;
    const left = Math.max(0, s.totalBytes - s.usedBytes);
    return {
      text: share >= 1 ? t(`Трафик закончился: ${gb(s.totalBytes)} ГБ`, `Traffic used up: ${gb(s.totalBytes)} GB`) : t(`${gb(s.usedBytes)} из ${gb(s.totalBytes)} ГБ · осталось ${gb(left)} ГБ`, `${gb(s.usedBytes)} of ${gb(s.totalBytes)} GB · ${gb(left)} GB left`),
      share: Math.min(1, share),
      tone: share >= 1 ? "danger" : share > 0.9 ? "warn" : "ok",
    };
  }

  const skippedCount = (s: SubscriptionItem) => s.skipped.reduce((n, x) => n + x.count, 0);

  function skippedSummary(s: SubscriptionItem, skipped: number): string {
    return [
      skipped > 0
        ? t(
            `Пропущено ${count(skipped, ["строка", "строки", "строк"], ["", ""])}`,
            `Skipped ${count(skipped, ["", "", ""], ["line", "lines"])}`,
          )
        : null,
      s.duplicates > 0 ? t(`убрано повторов: ${s.duplicates}`, `duplicates removed: ${s.duplicates}`) : null,
    ]
      .filter(Boolean)
      .join(" · ");
  }

  /** Причина неудачного обновления одной фразой, с точкой в конце. */
  function trouble(s: SubscriptionItem, at: number): string {
    const reason = s.lastError?.trim().replace(/[.!]*$/, ".") ?? "";
    const old = s.servers > 0 ? t(" Пока работают серверы из прошлой версии.", "Servers from the previous version still work.") : "";
    return t(`Не обновилась ${ago(at)}: ${reason}${old}`, `Not updated ${ago(at)}: ${reason}${old}`);
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
                  aria-label={t("Название подписки", "Subscription name")}
                  placeholder={s.byUrl ? t("Пусто — название от провайдера", "Empty — the provider's name") : t("Добавлено вручную", "Added manually")}
                  use:selectAll
                  onkeydown={(e) => {
                    if (e.key === "Escape") renaming = null;
                  }}
                />
                <button type="submit" class="btn btn-primary">{t("Сохранить", "Save")}</button>
                <button type="button" class="btn" onclick={() => (renaming = null)}>{t("Отмена", "Cancel")}</button>
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
            {#if confirmRemove === s.id}
              <span class="caption appear">{s.byUrl ? t("Удалить подписку?", "Delete the subscription?") : t("Удалить все ключи?", "Delete all keys?")}</span>
              <button class="btn danger" onclick={() => act(() => removeSubscription(s.id)).then(() => (confirmRemove = null))}>
                {t("Удалить", "Delete")}
              </button>
              <button class="btn" onclick={() => (confirmRemove = null)}>{t("Отмена", "Cancel")}</button>
            {:else if renaming !== s.id}
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
              <button class="btn subtle" onclick={() => ((confirmRemove = s.id), (renaming = null))} aria-label={t(`Удалить ${s.title}`, `Delete ${s.title}`)}>
                {s.byUrl ? t("Удалить", "Delete") : t("Удалить все", "Delete all")}
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
                  <div class="bar {use.tone}" role="progressbar" aria-label={t("Трафик", "Traffic")} aria-valuenow={Math.round(use.share * 100)} aria-valuemin="0" aria-valuemax="100">
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
                aria-expanded={advanced === s.id}
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

        {#if advanced === s.id}
          <form
            class="editor advanced"
            transition:slide={{ duration: 150 }}
            onsubmit={(e) => {
              e.preventDefault();
              void saveAdvanced(s.id);
            }}
          >
            <fieldset>
              <legend>{t("Серверы", "Servers")}</legend>
              <label for="keep-{s.id}">{t("Оставить только с этими словами в названии", "Keep only names with these words")}</label>
              <input id="keep-{s.id}" bind:value={keep} autocomplete="off" placeholder={t("Пусто — все. Например: NL, Германия", "Empty — all. For example: NL, Germany")} />
              <label for="drop-{s.id}">{t("Убрать с этими словами", "Remove names with these words")}</label>
              <input id="drop-{s.id}" bind:value={drop} autocomplete="off" placeholder={t("Например: резерв, test", "For example: backup, test")} />
              <p class="caption">
                {t("Слова — через запятую, регистр не важен. Код страны (NL, DE) находит сервер и по флагу.", "Separate words with commas, case doesn't matter. A country code (NL, DE) also matches a server by its flag.")}
              </p>
            </fieldset>

            <fieldset>
              <legend>{t("Клиент", "Client")}</legend>
              <label for="client-{s.id}">{t("Как KVT представляется провайдеру", "How KVT introduces itself to the provider")}</label>
              <select id="client-{s.id}" bind:value={client}>
                {#each clients as [value, label] (value)}
                  <option {value}>{label}</option>
                {/each}
              </select>
              {#if client === "custom"}
                <input
                  bind:value={userAgent}
                  maxlength="200"
                  autocomplete="off"
                  spellcheck="false"
                  aria-label={t("Свой User-Agent", "Custom User-Agent")}
                  placeholder="Happ/3.6.1"
                />
              {/if}
              <p class="caption">
                {t("Нужен, только если провайдер отдаёт серверы лишь «своему» приложению. «Авто» пробует несколько клиентов по очереди.", "Only needed if the provider gives servers to its “own” app only. “Auto” tries several clients in turn.")}
              </p>
            </fieldset>

            <fieldset>
              <legend>{t("ID устройства", "Device ID")}</legend>
              <label for="hwid-{s.id}">{t("Отправлять провайдеру", "Send to the provider")}</label>
              <select id="hwid-{s.id}" bind:value={hwid}>
                <option value="auto">{t("Когда провайдер просит", "When the provider asks")}</option>
                <option value="always">{t("Всегда", "Always")}</option>
                <option value="never">{t("Никогда", "Never")}</option>
              </select>
              {#if hwid !== "never"}
                <label for="own-{s.id}">{t("ID от провайдера", "ID from the provider")}</label>
                <input
                  id="own-{s.id}"
                  bind:value={ownHwid}
                  maxlength="128"
                  autocomplete="off"
                  spellcheck="false"
                  disabled={clearOwnHwid}
                  placeholder={s.options.ownHwid && !clearOwnHwid
                    ? t("Задан — вставьте новый, чтобы заменить", "Set — paste a new one to replace it")
                    : t("Пусто — свой ID KVT", "Empty — KVT's own ID")}
                />
                {#if s.options.ownHwid}
                  <label class="check">
                    <input type="checkbox" bind:checked={clearOwnHwid} />
                    {t("Убрать ID от провайдера", "Remove the provider's ID")}
                  </label>
                {/if}
              {/if}
              <p class="caption">
                {t(`Провайдеры с лимитом устройств отдают серверы только по ID. У KVT он свой для каждого провайдера, без имени компьютера. ${s.options.hwidSent ? "Сейчас ID отправляется." : ""}`, `Providers with a device limit give servers only by ID. KVT has its own for each provider, without the computer's name. ${s.options.hwidSent ? "The ID is being sent now." : ""}`)}
              </p>
            </fieldset>

            {#if advancedError}
              <p class="error-text appear">{advancedError}</p>
            {/if}
            <div class="editor-actions">
              <button type="submit" class="btn btn-primary" class:busy={advancedSaving} disabled={advancedSaving}>
                {t("Сохранить", "Save")}
              </button>
              <button type="button" class="btn" disabled={advancedSaving} onclick={() => (advanced = null)}>
                {t("Отмена", "Cancel")}
              </button>
            </div>
          </form>
        {/if}

        {#if s.keys.length > 0}
          <ul class="keys">
            {#each s.keys as k (k.key)}
              <li class="key">
                <div class="key-row">
                  <Flag code={k.flag} />
                  <div class="key-text">
                    <span class="key-name"><ServerName name={k.title} /></span>
                    <span class="caption">{protocolTitle(k.protocol)}{k.transport !== "tcp" ? ` · ${k.transport.toUpperCase()}` : ""}</span>
                  </div>
                  <div class="actions">
                    {#if confirmKey === k.key}
                      <span class="caption appear">{t("Удалить ключ?", "Delete the key?")}</span>
                      <button
                        class="btn danger"
                        onclick={() => act(() => removeServer(k.key)).then(() => (confirmKey = null))}
                      >
                        {t("Удалить", "Delete")}
                      </button>
                      <button class="btn" onclick={() => (confirmKey = null)}>{t("Отмена", "Cancel")}</button>
                    {:else if editing !== k.key}
                      <button class="btn" onclick={() => startEdit(k)} aria-label={t(`Изменить ${k.name}`, `Edit ${k.name}`)}>{t("Изменить", "Edit")}</button>
                      <button
                        class="btn subtle"
                        onclick={() => ((confirmKey = k.key), (editing = null))}
                        aria-label={t(`Удалить ${k.name}`, `Delete ${k.name}`)}
                      >
                        {t("Удалить", "Delete")}
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
                    <label for="name-{k.key}">{t("Название", "Name")}</label>
                    <input id="name-{k.key}" bind:value={editName} maxlength="120" autocomplete="off" />
                    <label for="link-{k.key}">{t("Новая ссылка", "New link")}</label>
                    <textarea
                      id="link-{k.key}"
                      bind:value={editLink}
                      rows="2"
                      spellcheck="false"
                      placeholder={t("vless://… — оставьте пустым, чтобы ключ остался прежним", "vless://… — leave empty to keep the current key")}
                    ></textarea>
                    <p class="caption">
                      {t("Текущая ссылка не показывается: в ней пароль или UUID сервера. Если название пустое, возьмётся из новой ссылки.", "The current link isn't shown: it contains the server's password or UUID. If the name is empty, it's taken from the new link.")}
                    </p>
                    {#if editError}
                      <p class="error-text appear">{editError}</p>
                    {/if}
                    <div class="editor-actions">
                      <button type="submit" class="btn btn-primary" class:busy={saving} disabled={saving}>
                        {t("Сохранить", "Save")}
                      </button>
                      <button type="button" class="btn" disabled={saving} onclick={() => (editing = null)}>
                        {t("Отмена", "Cancel")}
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

  .editor.advanced {
    gap: var(--space-4);
    padding-left: 0;
  }

  .advanced fieldset {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    margin: 0;
    padding: 0;
    border: 0;
  }

  .advanced legend {
    margin-bottom: var(--space-1);
    padding: 0;
    font-weight: 600;
  }

  /* Вид — общий из app.css; здесь только высота как у полей ввода. */
  .advanced select {
    height: 32px;
  }

  .advanced .check {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    color: var(--text);
  }

  .advanced input:disabled {
    opacity: 0.5;
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
