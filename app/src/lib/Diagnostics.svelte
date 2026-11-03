<script lang="ts" module>
  import type { Diagnosis, DnsReport, LeakReport } from "./api";

  // Результаты живут дольше страницы: вкладку можно сменить, а начатая проверка
  // допишет итог сюда и он будет на месте при возврате.
  const st = $state({
    diagnosis: null as Diagnosis | null,
    diagnosing: false,
    diagnoseError: null as string | null,
    dnsReport: null as DnsReport | null,
    dnsRunning: false,
    dnsError: null as string | null,
    leaks: null as LeakReport | null,
    leaking: false,
    leakError: null as string | null,
  });
</script>

<script lang="ts">
  import Icon from "./Icon.svelte";
  import {
    dnsCatalog,
    dnsCheck,
    leakTest,
    troubleshoot,
    type CheckResult,
    type DnsChoice,
    type Fix,
    type PathStatus,
    type Resolver,
  } from "./api";

  let {
    connected,
    dns = $bindable(),
    onfix,
    autorun,
    onautorun,
  }: {
    connected: boolean;
    dns: DnsChoice;
    onfix: (fix: Fix) => void;
    /** «Почему не работает?» нажали с главной: запустить проверку сразу. */
    autorun: boolean;
    onautorun: () => void;
  } = $props();


  async function diagnose() {
    if (st.diagnosing) return;
    st.diagnosing = true;
    st.diagnoseError = null;
    try {
      st.diagnosis = await troubleshoot();
    } catch (e) {
      st.diagnoseError = e instanceof Error ? e.message : String(e);
    } finally {
      st.diagnosing = false;
    }
  }

  $effect(() => {
    if (!autorun) return;
    onautorun();
    void diagnose();
  });

  function fixLabel(fix: Fix): string {
    switch (fix.kind) {
      case "connect":
        return "Подключить";
      case "disconnect":
        return "Отключить";
      case "switch_server":
        return `Переключиться на «${fix.name}»`;
      case "refresh_subscription":
        return "Обновить подписку";
      case "add_subscription":
        return "Добавить подписку";
      case "open_dns_check":
        return "Проверить DNS";
    }
  }

  function applyFix(fix: Fix) {
    if (fix.kind === "open_dns_check") {
      document.getElementById("dns-check")?.scrollIntoView({ behavior: "smooth" });
      void runDns();
      return;
    }
    onfix(fix);
  }

  // ── DNS ──
  let resolvers = $state<Resolver[]>([]);
  $effect(() => {
    void dnsCatalog().then((r) => (resolvers = r));
  });


  async function runDns() {
    if (st.dnsRunning) return;
    st.dnsRunning = true;
    st.dnsError = null;
    try {
      st.dnsReport = await dnsCheck();
    } catch (e) {
      st.dnsError = e instanceof Error ? e.message : String(e);
    } finally {
      st.dnsRunning = false;
    }
  }

  function cell(p: PathStatus): { text: string; tone: string; hint?: string } {
    switch (p.state) {
      case "works":
        return { text: `${p.ms} мс`, tone: "ok" };
      case "intercepted":
        return { text: "перехват", tone: "warning", hint: `Отвечает ${p.by}, а не этот резолвер` };
      case "blocked":
        return { text: "нет ответа", tone: "fail", hint: "Скорее всего, заблокирован провайдером" };
      case "failed":
        return { text: "ошибка", tone: "fail", hint: p.reason };
      case "not_checked":
        return { text: "—", tone: "none", hint: "Резолвер не поддерживает этот способ" };
    }
  }

  const recommended = $derived(
    st.dnsReport ? (resolvers.find((r) => r.id === st.dnsReport?.recommendedLocal) ?? null) : null,
  );

  // ── Утечки ──

  async function runLeaks() {
    st.leaking = true;
    st.leakError = null;
    try {
      st.leaks = await leakTest(connected);
    } catch (e) {
      st.leakError = e instanceof Error ? e.message : String(e);
    } finally {
      st.leaking = false;
    }
  }

  const leakRows = $derived<[string, CheckResult][]>(
    st.leaks
      ? [
          ["Маршрут IPv4", st.leaks.ipv4Route],
          ["Маршрут IPv6", st.leaks.ipv6Route],
          ["DNS", st.leaks.dns],
        ]
      : [],
  );
</script>

<section class="card block">
  <div class="row">
    <div>
      <h2>Почему не работает?</h2>
      <p class="muted">
        Проверяет по шагам сеть, службу KVT, подписку, сервер и туннель и говорит, что именно не так. К серверу уходит
        не больше одного соединения.
      </p>
    </div>
    <button class="btn btn-primary" disabled={st.diagnosing} onclick={diagnose}>
      <Icon name="help" size={16} />{st.diagnosing ? "Проверка…" : "Найти причину"}
    </button>
  </div>

  {#if st.diagnoseError}
    <p class="error-text">{st.diagnoseError}</p>
  {/if}

  {#if st.diagnosis}
    <div class="verdict {st.diagnosis.tone}" role="status">
      <div>
        <strong>{st.diagnosis.title}</strong>
        {#if st.diagnosis.detail}<p>{st.diagnosis.detail}</p>{/if}
      </div>
      {#if st.diagnosis.fix}
        {@const fix = st.diagnosis.fix}
        <button class="btn btn-primary" onclick={() => applyFix(fix)}>{fixLabel(fix)}</button>
      {/if}
    </div>
    <ol class="results steps">
      {#each st.diagnosis.steps as step (step.title)}
        <li class={step.state}>
          <strong>{step.title}</strong>
          <span>{step.detail}</span>
        </li>
      {/each}
    </ol>
  {/if}
</section>

<section class="card block" id="dns-check">
  <div class="row">
    <div>
      <h2>Проверка DNS</h2>
      <p class="muted">
        Какие DNS-серверы доступны из этой сети, не перехватывает ли провайдер запросы и не подменяет ли адреса
        заблокированных сайтов. Около 30 коротких DNS-запросов.
      </p>
    </div>
    <button
      class="btn"
      disabled={st.dnsRunning || connected}
      title={connected ? "Отключите VPN: проверка смотрит на сеть провайдера напрямую" : undefined}
      onclick={runDns}
    >
      <Icon name="globe" size={16} />{st.dnsRunning ? "Проверка…" : "Проверить DNS"}
    </button>
  </div>
  {#if connected}
    <p class="caption">Проверка DNS работает при отключённом VPN.</p>
  {/if}
  {#if st.dnsError}
    <p class="error-text">{st.dnsError}</p>
  {/if}

  {#if st.dnsReport}
    <div class="verdict {st.dnsReport.tone}" role="status">
      <div>
        <strong>{st.dnsReport.title}</strong>
        <p>{st.dnsReport.detail}</p>
      </div>
    </div>

    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">Резолвер</th>
            <th scope="col">UDP</th>
            <th scope="col">DoT</th>
            <th scope="col">DoH</th>
          </tr>
        </thead>
        <tbody>
          {#each st.dnsReport.resolvers as r (r.id)}
            <tr>
              <th scope="row">{r.title}</th>
              {#each [r.udp, r.dot, r.doh] as p, i (i)}
                {@const c = cell(p)}
                <td class={c.tone} title={c.hint}>{c.text}</td>
              {/each}
            </tr>
          {/each}
        </tbody>
      </table>
    </div>

    {#if st.dnsReport.spoofing.length > 0}
      <ul class="results">
        {#each st.dnsReport.spoofing as f (f.source + f.domain)}
          <li class="warning">
            <strong>{f.domain}: {f.source}</strong>
            <span>
              {#if f.kind === "denied"}
                отвечает «такого сайта нет», хотя он существует
              {:else}
                возвращает {f.got.join(", ")} — адрес заглушки
              {/if}
            </span>
          </li>
        {/each}
      </ul>
    {/if}

    <p class="caption">
      DNS этой сети: {st.dnsReport.systemServer ?? "не определён"}{#if st.dnsReport.systemEgress}, на самом деле отвечает {st.dnsReport.systemEgress}{/if}.
    </p>

    {#if recommended && dns.local !== recommended.id}
      <div class="suggest">
        <span>Для сайтов, которые открываются напрямую, лучше подойдёт {recommended.title}.</span>
        <button class="btn" onclick={() => (dns = { ...dns, local: recommended.id })}>Использовать</button>
      </div>
    {/if}
  {/if}
</section>

<section class="card block">
  <div class="row">
    <div>
      <h2>Проверка утечек</h2>
      <p class="muted">
        Ищет на компьютере открытые прокси других VPN-клиентов, проверяет маршруты IPv4/IPv6 и DNS. Почти всё
        проверяется локально — в интернет уходит один DNS-запрос.
      </p>
    </div>
    <button class="btn" disabled={st.leaking} onclick={runLeaks}>
      <Icon name="shield" size={16} />{st.leaking ? "Проверка…" : "Проверить"}
    </button>
  </div>

  {#if st.leakError}
    <p class="error-text">{st.leakError}</p>
  {/if}
  {#if st.leaks}
    <ul class="results">
      {#if st.leaks.openProxies.length === 0}
        <li class="ok">
          <strong>Открытые прокси</strong>
          <span>Не найдено. Программы на компьютере не смогут узнать адрес VPN-сервера через локальный порт.</span>
        </li>
      {:else}
        {#each st.leaks.openProxies as p (p.port)}
          <li class="warning">
            <strong>Открытый SOCKS5 на порту {p.port}</strong>
            <span>
              {p.process ?? "Неизвестная программа"} принимает подключения без пароля: любое приложение может узнать
              через него IP вашего VPN-сервера.{#if p.knownScanPort}
                Этот порт из списка, по которому ищут прокси.{/if}
              Включите в той программе пароль для локального прокси или используйте режим TUN.
            </span>
          </li>
        {/each}
      {/if}
      {#each leakRows as [label, r] (label)}
        <li class={r.verdict}>
          <strong>{label}</strong>
          <span>{r.detail}</span>
        </li>
      {/each}
    </ul>
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
    max-width: 560px;
  }

  .row .btn {
    flex: none;
  }

  .caption {
    margin: 0;
  }

  .error-text {
    margin: 0;
    color: var(--danger);
  }

  .verdict {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-4);
    padding: var(--space-3) var(--space-4);
    border-left: 3px solid var(--ok);
    border-radius: var(--radius-s);
    background: var(--ok-subtle);
  }

  .verdict.warning {
    border-left-color: var(--warn);
    background: var(--warn-subtle);
  }

  .verdict.error {
    border-left-color: var(--danger);
    background: var(--danger-subtle);
  }

  .verdict p {
    margin: var(--space-1) 0 0;
  }

  .verdict .btn {
    flex: none;
  }

  /* Шаги — короткие строки: название слева, итог справа. */
  .steps li {
    flex-direction: row;
    align-items: baseline;
    gap: var(--space-4);
    padding: var(--space-1) var(--space-3);
    background: transparent;
  }

  .steps li strong {
    flex: none;
    width: 150px;
    font-weight: 600;
  }

  .steps li.ok {
    background: transparent;
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
  }

  tbody th {
    font-weight: 600;
  }

  td.ok {
    color: var(--ok);
  }

  td.warning {
    color: var(--warn);
  }

  td.fail {
    color: var(--danger);
  }

  td.none {
    color: var(--text-3);
  }

  td[title] {
    cursor: help;
  }

  .suggest {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-4);
    padding: var(--space-3) var(--space-4);
    border-radius: var(--radius-s);
    background: var(--accent-subtle);
  }

  @media (max-width: 720px) {
    .row,
    .verdict,
    .suggest {
      flex-direction: column;
      align-items: stretch;
    }
  }
</style>
