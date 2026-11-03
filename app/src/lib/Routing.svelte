<script lang="ts">
  import { listCatalog, type ListAction, type ListInfo, type RoutingSettings } from "./api";

  let { routing = $bindable(), connected }: { routing: RoutingSettings; connected: boolean } = $props();

  let catalog = $state<ListInfo[]>([]);
  $effect(() => {
    void listCatalog().then((c) => (catalog = c));
  });

  const groups: { kind: ListInfo["kind"]; title: string }[] = [
    { kind: "service", title: "Сервисы" },
    { kind: "category", title: "Категории" },
    { kind: "region", title: "Регионы" },
  ];

  /** Что делает пресет со списком, если пользователь ничего не выбрал. */
  function presetAction(id: string): string {
    if (routing.listMode === "compact" && id === "russia_inside") return "через VPN";
    if (routing.listMode === "compact" && id === "russia_outside") return "напрямую";
    if (id === "geoblock") return "через VPN";
    return routing.everythingElse === "proxy" ? "через VPN" : "напрямую";
  }

  function setOverride(id: string, value: string) {
    const overrides = { ...routing.overrides };
    if (value === "default") delete overrides[id];
    else overrides[id] = value as ListAction;
    routing = { ...routing, overrides };
  }

  const changedCount = $derived(Object.keys(routing.overrides).length);
</script>

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
      <span class="title">Компактные (podkop)</span>
      <span class="muted">
        Отобранные вручную списки itdoginfo: заблокированное в России, сервисы с гео-блоком, российские сайты для
        прямого доступа. Быстро и почти без ложных срабатываний.
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
      <span class="title">Полный реестр (runetfreedom)</span>
      <span class="muted">
        Около 700 тысяч доменов из реестра блокировок. Максимальный охват, но при первом подключении скачивается больше
        данных.
      </span>
    </label>
  </div>

  <h2>Всё остальное</h2>
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
      ? "Российские сайты и IP — напрямую, всё остальное — через VPN."
      : "Через VPN идут только заблокированные сайты из списков; всё остальное — напрямую."}
  </p>
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
    Списки podkop обновляются автоматически при подключении, не чаще раза в сутки, с проверкой подлинности.
  </p>

  {#each groups as g (g.kind)}
    {@const items = catalog.filter((l) => l.kind === g.kind)}
    {#if items.length > 0}
      <h3>{g.title}</h3>
      <ul>
        {#each items as l (l.id)}
          <li>
            <span class="name">{l.title}</span>
            <select
              aria-label={`Куда направлять: ${l.title}`}
              value={routing.overrides[l.id] ?? "default"}
              class:changed={l.id in routing.overrides}
              onchange={(e) => setOverride(l.id, e.currentTarget.value)}
            >
              <option value="default">Как обычно ({presetAction(l.id)})</option>
              <option value="proxy">Через VPN</option>
              <option value="direct">Напрямую</option>
              <option value="block">Блокировать</option>
            </select>
          </li>
        {/each}
      </ul>
    {/if}
  {/each}
</section>

{#if connected}
  <p class="caption hint">Изменения применятся при следующем подключении.</p>
{/if}

<style>
  .block {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    padding: var(--space-5);
  }

  h3 {
    margin: var(--space-2) 0 0;
    font: 600 12px/16px var(--font);
    color: var(--text-2);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .head {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .intro,
  .caption {
    margin: 0;
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
  }

  .segmented button.selected {
    background: var(--surface);
    box-shadow: 0 0 0 1px var(--stroke);
    font-weight: 600;
  }

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
    min-height: 40px;
    border-bottom: 1px solid var(--stroke);
  }

  li:last-child {
    border-bottom: 0;
  }

  select {
    min-width: 220px;
    height: 30px;
    padding: 0 var(--space-2);
    border: 1px solid var(--stroke);
    border-radius: var(--radius-s);
    background: var(--surface);
    color: var(--text);
    font: inherit;
    cursor: pointer;
  }

  select.changed {
    border-color: var(--accent);
  }

  .link {
    min-height: 28px;
  }

  .hint {
    margin: 0;
  }

  @media (max-width: 720px) {
    .options {
      grid-template-columns: 1fr;
    }
  }
</style>
