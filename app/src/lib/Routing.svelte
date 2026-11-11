<script lang="ts">
  import {
    checkRouteTarget,
    listCatalog,
    type ListAction,
    type ListInfo,
    type RoutingSettings,
  } from "./api";
  import Icon from "./Icon.svelte";
  import SiteList from "./SiteList.svelte";

  let {
    routing = $bindable(),
    connected,
    pending,
    busy,
    onapply,
  }: {
    routing: RoutingSettings;
    connected: boolean;
    /** Подключены с другими настройками маршрутизации. */
    pending: boolean;
    busy: boolean;
    onapply: () => void;
  } = $props();

  let catalog = $state<ListInfo[]>([]);
  $effect(() => {
    void listCatalog().then((c) => (catalog = c));
  });

  const groups: { kind: ListInfo["kind"]; title: string }[] = [
    { kind: "service", title: "Сервисы" },
    { kind: "category", title: "Категории" },
    { kind: "region", title: "Регионы" },
  ];

  const actions: { value: ListAction; title: string }[] = [
    { value: "proxy", title: "Через VPN" },
    { value: "direct", title: "Напрямую" },
    { value: "block", title: "Блокировать" },
  ];

  /** Должно совпадать с `MAX_CUSTOM_RULES` в kvt-core. */
  const MAX_CUSTOM = 300;

  /** Что делает пресет со списком, если пользователь ничего не выбрал. В режиме
   *  «напрямую» сайт из списка всё равно идёт через VPN, если он заблокирован. */
  function presetAction(id: string): string {
    if (routing.listMode === "compact" && id === "russia_inside") return "через VPN";
    if (routing.listMode === "compact" && id === "russia_outside") return "напрямую";
    if (id === "geoblock") return "через VPN";
    return routing.everythingElse === "proxy" ? "через VPN" : "по спискам блокировок";
  }

  function setOverride(id: string, value: string) {
    const overrides = { ...routing.overrides };
    if (value === "default") delete overrides[id];
    else overrides[id] = value as ListAction;
    routing = { ...routing, overrides };
  }

  const changedCount = $derived(Object.keys(routing.overrides).length);
  const custom = $derived(routing.custom ?? []);

  // --- Свои сайты ---
  /** Действие для нового сайта: обычно нужно противоположное «Всему остальному». */
  let draftAction = $state<ListAction | null>(null);
  const newAction = $derived<ListAction>(draftAction ?? (routing.everythingElse === "proxy" ? "direct" : "proxy"));
  const siteActions: { value: ListAction; title: string; tone: "accent" | "ok" | "danger" }[] = [
    { value: "proxy", title: "Через VPN", tone: "accent" },
    { value: "direct", title: "Напрямую", tone: "ok" },
    { value: "block", title: "Блокировать", tone: "danger" },
  ];
</script>

<div class="page">
  <section class="card block">
    <h2>Списки</h2>
    <div class="options" role="radiogroup" aria-label="Списки блокировок">
      <label class:selected={routing.listMode === "compact"}>
        <input
          type="radio"
          name="listMode"
          value="compact"
          checked={routing.listMode === "compact"}
          onchange={() => (routing = { ...routing, listMode: "compact" })}
        />
        <span class="title">Компактные</span>
        <span class="muted">
          Отобранные списки itdoginfo, как в podkop: заблокированное в России, сервисы с гео-блоком, российские сайты
          для прямого доступа. Быстро и почти без ложных срабатываний.
        </span>
      </label>
      <label class:selected={routing.listMode === "full"}>
        <input
          type="radio"
          name="listMode"
          value="full"
          checked={routing.listMode === "full"}
          onchange={() => (routing = { ...routing, listMode: "full" })}
        />
        <span class="title">Полный реестр</span>
        <span class="muted">
          Около 700 тысяч доменов из реестра блокировок (runetfreedom). Максимальный охват, но при первом подключении
          скачивается больше данных.
        </span>
      </label>
    </div>

    <h2 class="spaced">Всё остальное</h2>
    <div class="segmented" role="radiogroup" aria-label="Трафик вне списков">
      <button
        role="radio"
        aria-checked={routing.everythingElse === "proxy"}
        class:selected={routing.everythingElse === "proxy"}
        onclick={() => (routing = { ...routing, everythingElse: "proxy" })}>Через VPN, кроме России</button
      >
      <button
        role="radio"
        aria-checked={routing.everythingElse === "direct"}
        class:selected={routing.everythingElse === "direct"}
        onclick={() => (routing = { ...routing, everythingElse: "direct" })}>Напрямую</button
      >
    </div>
    <p class="caption">
      {routing.everythingElse === "proxy"
        ? "Российские сайты и IP — напрямую, всё остальное — через VPN. Обновления Windows, Defender и OneDrive тоже идут напрямую, чтобы не тратить трафик подписки."
        : "Через VPN идут только заблокированные сайты из списков; всё остальное — напрямую."}
    </p>
  </section>

  <section class="card block">
    <div class="head">
      <h2>Свои сайты</h2>
      {#if custom.length > 0}
        <span class="caption">{custom.length} из {MAX_CUSTOM}</span>
      {/if}
    </div>
    <p class="muted intro">
      Важнее списков. Сайт работает вместе с поддоменами: example.com включает и mail.example.com. Можно указать IP или
      подсеть.
    </p>
    <SiteList
      items={custom}
      actions={siteActions}
      {newAction}
      onnewaction={(a) => (draftAction = a)}
      max={MAX_CUSTOM}
      placeholder="example.com, 1.2.3.4 или 10.0.0.0/24"
      label="Сайт, IP или подсеть"
      check={checkRouteTarget}
      onchange={(next) => (routing = { ...routing, custom: next })}
      empty={routing.everythingElse === "proxy"
        ? "Например, сайт, который не пускает с VPN, — напрямую."
        : "Например, заблокированный сайт, которого нет в списках, — через VPN."}
    />
  </section>

  <section class="card block">
    <div class="head">
      <h2>Сервисы и категории</h2>
      {#if changedCount > 0}
        <button class="btn link" onclick={() => (routing = { ...routing, overrides: {} })}>
          Сбросить ({changedCount})
        </button>
      {/if}
    </div>
    <p class="muted intro">
      Списки podkop обновляются при подключении, не чаще раза в сутки, с проверкой подлинности.
    </p>

    {#each groups as g (g.kind)}
      {@const items = catalog.filter((l) => l.kind === g.kind)}
      {#if items.length > 0}
        <h3>{g.title}</h3>
        <ul>
          {#each items as l (l.id)}
            {@const own = routing.overrides[l.id]}
            <li class:changed={own !== undefined}>
              <span class="name">
                <span class="title">{l.title}</span>
                {#if l.hint}<span class="hint">{l.hint}</span>{/if}
              </span>
              <select
                aria-label={`Куда направлять: ${l.title}`}
                value={own ?? "default"}
                class={own ? `tone-${own}` : ""}
                onchange={(e) => setOverride(l.id, e.currentTarget.value)}
              >
                <option value="default">По умолчанию ({presetAction(l.id)})</option>
                {#each actions as a (a.value)}
                  <option value={a.value}>{a.title}</option>
                {/each}
              </select>
            </li>
          {/each}
        </ul>
      {/if}
    {/each}
  </section>

  {#if pending}
    <div class="apply card appear" role="status">
      <Icon name="info" size={16} />
      <span>Новые правила заработают после переподключения.</span>
      <button class="btn btn-primary" class:busy disabled={busy} onclick={onapply}>
        <Icon name="refresh" size={16} />Переподключить
      </button>
    </div>
  {:else if connected}
    <p class="caption hint">Изменения применяются при переподключении — кнопка появится здесь.</p>
  {/if}
</div>

<style>
  .page {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
    container-type: inline-size;
  }

  .block {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    padding: var(--space-5);
  }

  h2 {
    margin: 0;
  }

  h3 {
    margin: var(--space-2) 0 0;
    font: 600 12px/16px var(--font);
    color: var(--text-2);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .spaced {
    margin-top: var(--space-3);
  }

  .head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-3);
  }

  .intro,
  .caption {
    margin: 0;
    max-width: var(--measure);
  }

  .options {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: var(--space-3);
  }

  .options label {
    position: relative;
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    padding: var(--space-3) var(--space-4) var(--space-3) var(--space-8);
    border: 1px solid var(--stroke);
    border-radius: var(--radius-m);
    cursor: pointer;
    transition:
      background-color var(--dur) var(--ease),
      border-color var(--dur) var(--ease);
  }

  .options label:hover:not(.selected) {
    background: var(--surface-hover);
  }

  .options label.selected {
    border-color: var(--accent);
    background: var(--accent-subtle);
  }

  .options input {
    position: absolute;
    left: var(--space-3);
    top: 14px;
    margin: 0;
    accent-color: var(--accent);
  }

  .options .title {
    font-weight: 600;
  }

  .options .muted {
    font-size: 12px;
    line-height: 16px;
  }

  .segmented {
    display: inline-flex;
    align-self: flex-start;
    padding: 2px;
    border: 1px solid var(--stroke);
    border-radius: var(--radius-s);
    background: var(--bg);
  }

  .segmented button {
    height: 28px;
    padding: 0 var(--space-3);
    border: 0;
    border-radius: 3px;
    background: transparent;
    cursor: pointer;
    transition:
      background-color var(--dur-fast) var(--ease),
      box-shadow var(--dur-fast) var(--ease),
      color var(--dur-fast) var(--ease);
  }

  .segmented button:hover:not(.selected) {
    background: var(--surface-hover);
  }

  /* Выбранный вариант — акцентом: в тёмной теме фон почти не отличается. */
  .segmented button.selected {
    background: var(--accent-subtle);
    box-shadow: inset 0 0 0 1px var(--accent);
    color: var(--accent);
    font-weight: 600;
  }

  /* --- Списки --- */
  ul {
    margin: 0;
    padding: 0;
    list-style: none;
  }

  li {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-4);
    min-height: 44px;
    padding: var(--space-1) 0;
    border-bottom: 1px solid var(--stroke);
  }

  li:last-child {
    border-bottom: 0;
  }

  .name {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }

  .name .hint {
    font-size: 12px;
    line-height: 16px;
    color: var(--text-3);
  }

  li.changed .title {
    font-weight: 600;
  }

  select {
    flex: none;
    min-width: 236px;
  }

  /* Свой выбор виден сразу: цвет полосы слева у поля по смыслу действия. */
  select.tone-proxy {
    border-color: var(--accent);
    box-shadow: inset 3px 0 0 var(--accent);
  }

  select.tone-direct {
    border-color: var(--ok);
    box-shadow: inset 3px 0 0 var(--ok);
  }

  select.tone-block {
    border-color: var(--danger);
    box-shadow: inset 3px 0 0 var(--danger);
  }

  .link {
    min-height: 28px;
  }

  .hint {
    margin: 0;
  }

  /* Переподключение — внизу экрана, пока правят списки ниже. */
  .apply {
    position: sticky;
    bottom: var(--space-3);
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-3) var(--space-4);
    border-color: var(--accent);
    box-shadow: 0 4px 16px rgb(0 0 0 / 0.12);
  }

  .apply > span {
    flex: 1;
  }

  .apply .btn {
    flex: none;
  }

  @container (max-width: 620px) {
    .options {
      grid-template-columns: 1fr;
    }

    select {
      min-width: 0;
      max-width: 55%;
    }
  }
</style>
