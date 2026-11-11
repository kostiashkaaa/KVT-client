<script lang="ts">
  import Icon from "./Icon.svelte";
  import { netLog, netLogClear, type NetEvent, type NetJournal, type NetPurpose } from "./api";

  /** Как часто обновлять журнал, пока страница открыта и окно видно. */
  const REFRESH_MS = 5000;
  const PAGE = 100;
  /** Сколько серверов сводки видно сразу: после проверки сотни серверов таблица растянулась бы на экраны. */
  const HOSTS_SHOWN = 10;

  type Filter = "all" | "problems" | "subscription" | "servers" | "tunnel" | "network" | "dns" | "zapret" | "lists";

  let journal = $state<NetJournal | null>(null);
  let error = $state<string | null>(null);
  let filter = $state<Filter>("all");
  let shown = $state(PAGE);
  let allHosts = $state(false);
  let clearing = $state(false);

  const filters: [Filter, string][] = [
    ["all", "Все запросы"],
    ["problems", "Ошибки и отложенные"],
    ["subscription", "Подписки"],
    ["servers", "Проверки серверов"],
    ["tunnel", "Проверка туннеля"],
    ["network", "Проверка сети"],
    ["dns", "DNS"],
    ["zapret", "Zapret"],
    ["lists", "Списки и обновления"],
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
    captive: "Проверка сети",
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
      case "problems":
        return e.outcome !== "ok";
      case "servers":
        return e.purpose === "server_ping" || e.purpose === "server_check";
      case "network":
        return e.purpose === "captive";
      case "lists":
        return e.purpose === "rules" || e.purpose === "update";
      default:
        return e.purpose === f;
    }
  }

  const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

  /** Номер последнего запроса: задержавшийся ответ на более ранний не затирает свежий. */
  let seq = 0;
  let loading = false;

  async function load() {
    if (loading) return;
    loading = true;
    const mine = ++seq;
    try {
      const next = await netLog();
      if (mine === seq) {
        journal = next;
        error = null;
      }
    } catch (e) {
      if (mine === seq) error = message(e);
    } finally {
      if (mine === seq) loading = false;
    }
  }

  async function clear() {
    clearing = true;
    try {
      await netLogClear();
      shown = PAGE;
      allHosts = false;
      // Ответ, начатый до очистки, уже не нужен.
      seq++;
      loading = false;
      await load();
    } catch (e) {
      error = message(e);
    } finally {
      clearing = false;
    }
  }

  $effect(() => {
    void load();
    // Окно свёрнуто в трей — службу зря не опрашиваем; вернулось — сразу обновляем.
    const refresh = () => {
      if (!document.hidden) void load();
    };
    const timer = setInterval(refresh, REFRESH_MS);
    document.addEventListener("visibilitychange", refresh);
    return () => {
      clearInterval(timer);
      document.removeEventListener("visibilitychange", refresh);
    };
  });

  const events = $derived(journal?.events ?? []);
  const counts = $derived(new Map(filters.map(([f]) => [f, events.filter((e) => matches(e, f)).length])));
  const filtered = $derived(events.filter((e) => matches(e, filter)));
  const visible = $derived(filtered.slice(0, shown));
  const hosts = $derived(journal?.hosts ?? []);
  const visibleHosts = $derived(allHosts ? hosts : hosts.slice(0, HOSTS_SHOWN));
  const lastHour = $derived(hosts.reduce((n, h) => n + h.opened, 0));

  function time(at: number): string {
    const d = new Date(at);
    const t = d.toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    // Окно работает сутками: у записей не за сегодня — ещё и дата.
    if (d.toDateString() === new Date().toDateString()) return t;
    return `${d.toLocaleDateString("ru-RU", { day: "numeric", month: "short" })} ${t}`;
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
    return `${Math.floor(s / 60)} мин назад`;
  }
</script>

<!-- Длинный адрес переносится только после точки, а не посреди слова. -->
{#snippet hostName(host: string)}
  {#each host.split(".") as part, i (i)}{#if i > 0}.<wbr />{/if}{part}{/each}
{/snippet}

<div class="page">
  <section class="card block" aria-labelledby="journal-title">
    <div class="row">
      <div>
        <h2 id="journal-title">Сетевые запросы</h2>
        <p class="muted">
          Куда и зачем KVT выходит в сеть. Записывается только адрес — без ссылок и ключей. Журнал живёт в памяти и
          пропадает после перезапуска.
        </p>
      </div>
      <div class="actions">
        <button class="btn" onclick={load}><Icon name="refresh" size={16} />Обновить</button>
        <button class="btn" class:busy={clearing} disabled={clearing || events.length === 0} onclick={clear}>
          Очистить
        </button>
      </div>
    </div>

    {#if error}
      <p class="error-text">{error}</p>
    {/if}

    {#if !journal && !error}
      <p class="caption">Загружаю журнал…</p>
    {/if}

    {#if journal}
      {#if !journal.service}
        <p class="caption">Служба KVT не отвечает — показаны только запросы приложения.</p>
      {/if}

      <h3>За последний час: {lastHour} {plural(lastHour, "соединение", "соединения", "соединений")}</h3>
      {#if hosts.length === 0}
        <p class="caption">За последний час KVT не выходил в сеть.</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">Сервер</th>
                <th scope="col" class="num">Соединений</th>
                <th scope="col" class="num" title="Наибольшее число соединений за одну минуту">Пик в минуту</th>
                <th scope="col" class="num" title="Запросы, которые KVT отложил, чтобы не вызвать блокировку">
                  Отложено
                </th>
                <th scope="col" class="num">Ошибок</th>
                <th scope="col">Последний</th>
              </tr>
            </thead>
            <tbody>
              {#each visibleHosts as h (h.host)}
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
        {#if hosts.length > HOSTS_SHOWN}
          <button class="btn more" onclick={() => (allHosts = !allHosts)}>
            {allHosts ? "Свернуть" : `Все серверы (${hosts.length})`}
          </button>
        {/if}
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
              <option {value}>{title} ({counts.get(value) ?? 0})</option>
            {/each}
          </select>
        </label>
      </div>

      {#if filtered.length === 0}
        <p class="caption">{events.length === 0 ? "Запросов пока нет." : "Таких запросов нет."}</p>
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

  /* Окно бывает узким: адрес и пояснение переносятся, а не растягивают таблицу. */
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

  @container (max-width: 620px) {
    .row {
      flex-direction: column;
      align-items: stretch;
    }
  }
</style>
