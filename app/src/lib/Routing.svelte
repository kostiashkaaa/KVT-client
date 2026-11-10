<script lang="ts">
  import {
    checkRouteTarget,
    listCatalog,
    type CustomRoute,
    type ListAction,
    type ListInfo,
    type RoutingSettings,
  } from "./api";
  import Icon from "./Icon.svelte";

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
  let draft = $state("");
  /** Действие для нового сайта: обычно нужно противоположное «Всему остальному». */
  let draftAction = $state<ListAction | null>(null);
  const newAction = $derived<ListAction>(draftAction ?? (routing.everythingElse === "proxy" ? "direct" : "proxy"));
  let adding = $state(false);
  let addError = $state<string | null>(null);

  function setCustom(next: CustomRoute[]) {
    routing = { ...routing, custom: next };
  }

  async function addCustom(e: SubmitEvent) {
    e.preventDefault();
    const parts = draft.split(/[\s,;]+/).filter(Boolean);
    if (parts.length === 0) {
      addError = "Введите адрес сайта, IP или подсеть.";
      return;
    }
    adding = true;
    addError = null;
    const next = [...custom];
    const failed: string[] = [];
    let firstError: string | null = null;
    for (const part of parts) {
      try {
        const target = await checkRouteTarget(part);
        const i = next.findIndex((c) => c.target === target);
        // Уже есть — меняем действие, а не заводим второе правило.
        if (i >= 0) next.splice(i, 1);
        else if (next.length >= MAX_CUSTOM) {
          firstError ??= `Не больше ${MAX_CUSTOM} своих правил.`;
          failed.push(part);
          continue;
        }
        next.unshift({ target, action: newAction });
      } catch (err) {
        firstError ??= String(err);
        failed.push(part);
      }
    }
    setCustom(next);
    draft = failed.join(", ");
    // Неудачные адреса остаются в поле — их видно и можно поправить.
    addError = failed.length > 0 ? firstError : null;
    adding = false;
  }

  function setCustomAction(target: string, action: ListAction) {
    setCustom(custom.map((c) => (c.target === target ? { ...c, action } : c)));
  }

  function removeCustom(target: string) {
    setCustom(custom.filter((c) => c.target !== target));
  }
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
    <form class="add" onsubmit={addCustom}>
      <input
        bind:value={draft}
        placeholder="example.com, 1.2.3.4 или 10.0.0.0/24"
        aria-label="Сайт, IP или подсеть"
        autocomplete="off"
        spellcheck="false"
        disabled={adding}
        oninput={() => (addError = null)}
        aria-invalid={addError !== null}
        aria-describedby={addError ? "custom-error" : undefined}
      />
      <select aria-label="Куда направлять новый сайт" value={newAction} onchange={(e) => (draftAction = e.currentTarget.value as ListAction)}>
        {#each actions as a (a.value)}
          <option value={a.value}>{a.title}</option>
        {/each}
      </select>
      <button type="submit" class="btn btn-primary" class:busy={adding} disabled={adding || draft.trim() === ""}>
        <Icon name="plus" size={16} />Добавить
      </button>
    </form>
    {#if addError}
      <p id="custom-error" class="error" role="alert">{addError}</p>
    {/if}

    {#if custom.length > 0}
      <ul class="custom">
        {#each custom as c (c.target)}
          <li class="appear">
            <span class="target" title={c.target}>{c.target}</span>
            <select
              aria-label={`Куда направлять: ${c.target}`}
              value={c.action}
              class="tone-{c.action}"
              onchange={(e) => setCustomAction(c.target, e.currentTarget.value as ListAction)}
            >
              {#each actions as a (a.value)}
                <option value={a.value}>{a.title}</option>
              {/each}
            </select>
            <button class="btn subtle icon" onclick={() => removeCustom(c.target)} aria-label={`Удалить ${c.target}`} title="Удалить">
              <Icon name="trash" size={16} />
            </button>
          </li>
        {/each}
      </ul>
    {:else}
      <p class="caption">
        {routing.everythingElse === "proxy"
          ? "Например, сайт, который не пускает с VPN, — напрямую."
          : "Например, заблокированный сайт, которого нет в списках, — через VPN."}
      </p>
    {/if}
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

  /* --- Свои сайты --- */
  .add {
    display: flex;
    gap: var(--space-2);
  }

  .add input {
    flex: 1;
    min-width: 0;
    height: 32px;
    padding: 0 var(--space-3);
    border: 1px solid var(--stroke);
    border-bottom-color: var(--text-3);
    border-radius: var(--radius-s);
    background: var(--surface);
    user-select: text;
    transition: border-color var(--dur-fast) var(--ease);
  }

  /* Как в Windows 11: снизу акцентная линия, высота поля не меняется. */
  .add input:focus {
    outline: none;
    border-bottom-color: var(--accent);
    box-shadow: inset 0 -1px 0 var(--accent);
  }

  .add input[aria-invalid="true"] {
    border-bottom-color: var(--danger);
    box-shadow: inset 0 -1px 0 var(--danger);
  }

  .add select {
    flex: none;
    height: 32px;
    min-width: 132px;
  }

  .add .btn {
    flex: none;
  }

  .error {
    margin: calc(-1 * var(--space-1)) 0 0;
    font-size: 12px;
    line-height: 16px;
    color: var(--danger);
  }

  .custom li {
    gap: var(--space-3);
  }

  .target {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-family: var(--mono);
    font-size: 13px;
    user-select: text;
  }

  .custom select {
    min-width: 132px;
  }

  .icon {
    width: 32px;
    padding: 0;
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

    .add {
      flex-wrap: wrap;
    }

    .add input {
      flex-basis: 100%;
    }
  }
</style>
