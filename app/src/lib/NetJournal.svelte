<script lang="ts">
  import Icon from "./Icon.svelte";
  import { netLog, netLogClear, type NetEvent, type NetJournal, type NetPurpose } from "./api";

  /** Как часто обновлять журнал, пока страница открыта. */
  const REFRESH_MS = 5000;
  const PAGE = 100;

  let journal = $state<NetJournal | null>(null);
  let error = $state<string | null>(null);
  let filter = $state<Filter>("all");
  let shown = $state(PAGE);

  type Filter = "all" | "subscription" | "servers" | "tunnel" | "dns" | "zapret" | "service";

  const filters: [Filter, string][] = [
    ["all", "Все запросы"],
    ["subscription", "Подписки"],
    ["servers", "Проверки серверов"],
    ["tunnel", "Проверка туннеля"],
    ["dns", "DNS"],
    ["zapret", "Zapret"],
    ["service", "Служба: списки и обновления"],
  ];

  const purposeTitle: Record<NetPurpose, string> = {
    subscription: "Подписка",
    server_ping: "Пинг сервера",
    server_check: "Проверка сервера",
    tunnel: "Туннель",
    dns: "DNS",
    zapret: "Zapret",
    rules: "Списки",
    update: "Обновление",
  };

  const routeTitle: Record<NetEvent["route"], string> = {
    direct: "напрямую",
    tunnel: "через VPN",
    test_core: "тестовое ядро",
  };

  const outcomeTitle: Record<NetEvent["outcome"], string> = {
    ok: "успешно",
    failed: "ошибка",
    deferred: "отложено",
    frozen: "заморожено",
  };

  function matches(e: NetEvent, f: Filter): boolean {
    switch (f) {
      case "all":
        return true;
      case "servers":
        return e.purpose === "server_ping" || e.purpose === "server_check";
      case "service":
        return e.origin === "service";
      default:
        return e.purpose === f;
    }
  }

  async function load() {
    try {
      journal = await netLog();
      error = null;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  async function clear() {
    await netLogClear();
    shown = PAGE;
    await load();
  }

  $effect(() => {
    void load();
    const timer = setInterval(() => void load(), REFRESH_MS);
    return () => clearInterval(timer);
  });

  const filtered = $derived(journal ? journal.events.filter((e) => matches(e, filter)) : []);
  const visible = $derived(filtered.slice(0, shown));
  const lastHour = $derived(journal ? journal.hosts.reduce((n, h) => n + h.opened, 0) : 0);

  function time(at: number): string {
    return new Date(at).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }

  function plural(n: number, one: string, few: string, many: string): string {
    const d = n % 10;
    const dd = n % 100;
    if (d === 1 && dd !== 11) return one;
    if (d >= 2 && d <= 4 && (dd < 12 || dd > 14)) return few;
    return many;
  }

  function ago(at: number): string {
    const s = Math.max(0, Math.round((Date.now() - at) / 1000));
    if (s < 60) return `${s} с назад`;
    const m = Math.round(s / 60);
    return `${m} мин назад`;
  }
</script>

<!-- Длинный адрес переносится только после точки, а не посреди слова. -->
{#snippet hostName(host: string)}
  {#each host.split(".") as part, i (i)}{#if i > 0}.<wbr />{/if}{part}{/each}
{/snippet}

<section class="card block" aria-labelledby="journal-title">
  <div class="row">
    <div>
      <h2 id="journal-title">Сетевые запросы</h2>
      <p class="muted">
        Куда и зачем KVT выходит в сеть: подписки, проверки серверов, DNS, списки маршрутизации. Записывается только
        адрес сервера — без ссылок и ключей. Журнал хранится в памяти и пропадает после перезапуска.
      </p>
    </div>
    <div class="actions">
      <button class="btn" onclick={load}><Icon name="refresh" size={16} />Обновить</button>
      <button class="btn" disabled={!journal || journal.events.length === 0} onclick={clear}>Очистить</button>
    </div>
  </div>

  {#if error}
    <p class="error-text">{error}</p>
  {/if}

  {#if journal}
    {#if !journal.service}
      <p class="caption">Служба KVT не отвечает — показаны только запросы приложения.</p>
    {/if}

    <h3>За последний час: {lastHour} {plural(lastHour, "соединение", "соединения", "соединений")}</h3>
    {#if journal.hosts.length === 0}
      <p class="caption">За последний час KVT не выходил в сеть.</p>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th scope="col">Сервер</th>
              <th scope="col" class="num">Соединений</th>
              <th scope="col" class="num" title="Наибольшее число соединений за одну минуту">Пик в минуту</th>
              <th scope="col" class="num" title="Запросы, которые KVT отложил, чтобы не вызвать блокировку">Отложено</th>
              <th scope="col" class="num">Ошибок</th>
              <th scope="col">Последний</th>
            </tr>
          </thead>
          <tbody>
            {#each journal.hosts as h (h.host)}
              <tr>
                <th scope="row" class="host">{@render hostName(h.host)}</th>
                <td class="num">{h.opened}</td>
                <td class="num">{h.peakPerMinute}</td>
                <td class="num" class:none={h.held === 0}>{h.held}</td>
                <td class="num" class:fail={h.failed > 0} class:none={h.failed === 0}>{h.failed}</td>
                <td class="none">{ago(h.last)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <p class="caption">
        Проверки серверов и загрузка подписок открывают не больше двух новых соединений к одному серверу в минуту:
        частые соединения к одному адресу провайдер может принять за VPN и притормозить.
      </p>
    {/if}

    <div class="list-head">
      <h3>Все запросы</h3>
      <label>
        <span class="sr">Показать</span>
        <select bind:value={filter} onchange={() => (shown = PAGE)}>
          {#each filters as [value, title] (value)}
            <option {value}>{title}</option>
          {/each}
        </select>
      </label>
    </div>

    {#if filtered.length === 0}
      <p class="caption">Запросов нет.</p>
    {:else}
      <div class="table-wrap">
        <table class="events">
          <thead>
            <tr>
              <th scope="col">Время</th>
              <th scope="col">Зачем</th>
              <th scope="col">Сервер</th>
              <th scope="col">Итог</th>
              <th scope="col" class="num">мс</th>
            </tr>
          </thead>
          <tbody>
            {#each visible as e, i (i)}
              <tr>
                <td class="none">{time(e.at)}</td>
                <td>
                  {purposeTitle[e.purpose]}{#if e.origin === "service"}<span class="tag">служба</span>{/if}
                  <span class="detail">{routeTitle[e.route]}</span>
                </td>
                <td class="host">{@render hostName(e.host)}</td>
                <td class={e.outcome} title={e.detail || undefined}>
                  {outcomeTitle[e.outcome]}{#if e.detail}<span class="detail">{e.detail}</span>{/if}
                </td>
                <td class="num none">{e.ms ?? "—"}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      {#if filtered.length > shown}
        <button class="btn more" onclick={() => (shown += PAGE)}>Показать ещё ({filtered.length - shown})</button>
      {/if}
    {/if}
  {/if}
</section>

<style>
  .block {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    padding: var(--space-5);
  }

  .row {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: var(--space-6);
  }

  .row p {
    margin: var(--space-1) 0 0;
    max-width: var(--measure);
  }

  .actions {
    display: flex;
    flex: none;
    gap: var(--space-2);
  }

  h3 {
    margin: var(--space-2) 0 0;
    font-size: 14px;
    font-weight: 600;
  }

  .caption {
    margin: 0;
  }

  .error-text {
    margin: 0;
    color: var(--danger);
  }

  .list-head {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: var(--space-4);
  }

  .table-wrap {
    overflow-x: auto;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    font-variant-numeric: tabular-nums;
  }

  th,
  td {
    padding: var(--space-2) var(--space-3);
    border-bottom: 1px solid var(--stroke);
    text-align: left;
    white-space: nowrap;
  }

  thead th {
    font-weight: 400;
    color: var(--text-3);
    font-size: 12px;
    white-space: normal;
    vertical-align: bottom;
  }

  tbody th {
    font-weight: 600;
  }

  .num {
    text-align: right;
  }

  .host {
    max-width: 200px;
    white-space: normal;
  }

  .none {
    color: var(--text-3);
  }

  .fail,
  td.failed {
    color: var(--danger);
  }

  td.ok {
    color: var(--ok);
  }

  td.deferred,
  td.frozen {
    color: var(--warn);
  }

  /* Пояснение — серой строкой под итогом, обрезается, полный текст в подсказке. */
  .detail {
    display: block;
    max-width: 220px;
    overflow: hidden;
    text-overflow: ellipsis;
    font-size: 12px;
    color: var(--text-3);
  }

  .tag {
    margin-left: var(--space-2);
    padding: 0 var(--space-1);
    border: 1px solid var(--stroke);
    border-radius: var(--radius-s);
    font-size: 11px;
    color: var(--text-3);
  }

  .events td {
    vertical-align: top;
  }

  /* Окно бывает узким (от 720 px): адрес и пояснение переносятся, а не растягивают таблицу. */
  .events .host {
    max-width: 180px;
  }

  .events .detail {
    max-width: 180px;
    white-space: normal;
  }

  .more {
    align-self: flex-start;
  }

  @media (max-width: 720px) {
    .row {
      flex-direction: column;
      align-items: stretch;
    }
  }
</style>
