<script lang="ts" module>
  import type { Diagnosis, DnsReport } from "./api";

  // Результаты живут дольше страницы: вкладку можно сменить, а начатая проверка
  // допишет итог сюда и он будет на месте при возврате.
  const st = $state({
    diagnosis: null as Diagnosis | null,
    /** Состояние службы, при котором шла проверка «Почему не работает?». */
    diagnosedIn: null as string | null,
    diagnosing: false,
    diagnoseError: null as string | null,
    dnsReport: null as DnsReport | null,
    dnsRunning: false,
    dnsError: null as string | null,
    /** Резолвер из подсказки уже выбран — показать, когда он заработает. */
    dnsApplied: false,
  });
</script>

<script lang="ts">
  import { t } from "./i18n";
  import Icon from "./Icon.svelte";
  import DiagExport from "./DiagExport.svelte";
  import PcAudit from "./PcAudit.svelte";
  import {
    dnsCatalog,
    dnsCheck,
    troubleshoot,
    type DnsChoice,
    type Fix,
    type PathStatus,
    type Resolver,
  } from "./api";

  let {
    connected,
    vpnState,
    dns = $bindable(),
    onfix,
    autorun,
    onautorun,
  }: {
    connected: boolean;
    /** Состояние службы (`status.state`): итог проверки устаревает, когда оно меняется. */
    vpnState: string;
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
    const before = vpnState;
    try {
      st.diagnosis = await troubleshoot();
      st.diagnosedIn = before;
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
        return t("Подключить", "Connect");
      case "disconnect":
        return t("Отключить", "Disconnect");
      case "switch_server":
        return t(`Переключиться на «${fix.name}»`, `Switch to “${fix.name}”`);
      case "refresh_subscription":
        return t("Обновить подписку", "Update subscription");
      case "add_subscription":
        return t("Добавить подписку", "Add subscription");
      case "open_dns_check":
        return t("Проверить DNS", "Check DNS");
      case "zapret_autoselect":
        return t("Подобрать стратегию", "Pick a strategy");
    }
  }

  /** Подключились, отключились или включили zapret после проверки: вывод и кнопка уже не про сейчас. */
  const stale = $derived(st.diagnosis !== null && st.diagnosedIn !== vpnState);

  function applyFix(fix: Fix) {
    if (fix.kind === "open_dns_check") {
      document.getElementById("dns-check")?.scrollIntoView({ behavior: "smooth" });
      // При VPN проверка DNS не запустится — подсказка об этом у её кнопки.
      if (!connected) void runDns();
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
    st.dnsApplied = false;
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
        return { text: t(`${p.ms} мс`, `${p.ms} ms`), tone: "ok" };
      case "intercepted":
        return { text: t("перехват", "intercepted"), tone: "warning", hint: t(`Отвечает ${p.by}, а не этот резолвер`, `${p.by} answers, not this resolver`) };
      case "blocked":
        return { text: t("нет ответа", "no response"), tone: "fail", hint: t("Скорее всего, заблокирован провайдером", "Most likely blocked by your ISP") };
      case "failed":
        return { text: t("ошибка", "error"), tone: "fail", hint: p.reason };
      case "not_checked":
        return { text: "—", tone: "none", hint: t("Резолвер не поддерживает этот способ", "The resolver doesn't support this method") };
    }
  }

  const recommended = $derived(
    st.dnsReport ? (resolvers.find((r) => r.id === st.dnsReport?.recommendedLocal) ?? null) : null,
  );
</script>

<div class="page">
<section class="card block">
  <div class="row">
    <div>
      <h2>{t("Почему не работает?", "Why isn't it working?")}</h2>
      <p class="muted">
        {t("По шагам проверяет сеть, службу KVT, подписку, сервер и туннель и говорит, что не так. К серверу — не больше одного соединения.", "Checks the network, the KVT service, the subscription, the server and the tunnel step by step and tells you what's wrong. At most one connection to the server.")}
      </p>
    </div>
    <button class="btn btn-primary" class:busy={st.diagnosing} disabled={st.diagnosing} onclick={diagnose}>
      <Icon name="help" size={16} />{st.diagnosis ? t("Проверить снова", "Check again") : t("Найти причину", "Find the cause")}
    </button>
  </div>

  {#if st.diagnoseError}
    <p class="error-text appear">{st.diagnoseError}</p>
  {/if}

  {#if st.diagnosis}
    <div class="verdict appear {st.diagnosis.tone}" class:stale role="status">
      <div>
        <strong>{st.diagnosis.title}</strong>
        {#if st.diagnosis.detail}<p>{st.diagnosis.detail}</p>{/if}
        {#if stale}<p class="stale-note">{t("Подключение изменилось после проверки — проверьте снова.", "The connection changed after the check — check again.")}</p>{/if}
      </div>
      {#if st.diagnosis.fix && !stale}
        {@const fix = st.diagnosis.fix}
        <button class="btn btn-primary" onclick={() => applyFix(fix)}>{fixLabel(fix)}</button>
      {/if}
    </div>
    <ol class="results steps">
      {#each st.diagnosis.steps as step, i (i)}
        <li class={step.state}>
          <strong>{step.title}</strong>
          <span>{step.detail}</span>
        </li>
      {/each}
    </ol>
  {/if}

  <div class="row export">
    <p class="caption">
      {t("Не помогло? Сохраните диагностику — журналы и итоги проверок без ключей и адресов серверов — и приложите её к сообщению об ошибке.", "Didn't help? Save diagnostics — logs and check results without keys or server addresses — and attach it to your bug report.")}
    </p>
    <DiagExport />
  </div>
</section>

<section class="card block" id="dns-check">
  <div class="row">
    <div>
      <h2>{t("Проверка DNS", "DNS check")}</h2>
      <p class="muted">
        {t("Какие DNS-серверы доступны из этой сети, не перехватывает ли провайдер запросы и не подменяет ли адреса заблокированных сайтов. Около 30 коротких запросов.", "Which DNS servers are reachable from this network, whether your ISP intercepts queries and spoofs addresses of blocked sites. About 30 short queries.")}
      </p>
    </div>
    <button
      class="btn"
      class:busy={st.dnsRunning}
      disabled={st.dnsRunning || connected}
      title={connected ? t("Отключите VPN: проверка смотрит на сеть провайдера напрямую", "Disconnect the VPN: the check looks at your ISP's network directly") : undefined}
      onclick={runDns}
    >
      <Icon name="globe" size={16} />{st.dnsReport ? t("Проверить снова", "Check again") : t("Проверить DNS", "Check DNS")}
    </button>
  </div>
  {#if connected}
    <p class="caption">{t("Работает при отключённом VPN: смотрит на сеть провайдера напрямую.", "Works with the VPN off: looks at your ISP's network directly.")}</p>
  {/if}
  {#if st.dnsError}
    <p class="error-text appear">{st.dnsError}</p>
  {/if}

  {#if st.dnsReport}
    <div class="verdict appear {st.dnsReport.tone}" role="status">
      <div>
        <strong>{st.dnsReport.title}</strong>
        <p>{st.dnsReport.detail}</p>
      </div>
    </div>

    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">{t("Резолвер", "Resolver")}</th>
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
                {t("отвечает «такого сайта нет», хотя он существует", "answers “no such site”, although it exists")}
              {:else}
                {t(`возвращает ${f.got.join(", ")} — адрес заглушки`, `returns ${f.got.join(", ")} — a block-page address`)}
              {/if}
            </span>
          </li>
        {/each}
      </ul>
    {/if}

    <p class="caption">
      {t(`DNS этой сети: ${st.dnsReport.systemServer ?? "не определён"}`, `This network's DNS: ${st.dnsReport.systemServer ?? "unknown"}`)}{#if st.dnsReport.systemEgress}{t(`, на самом деле отвечает ${st.dnsReport.systemEgress}`, `, actually answered by ${st.dnsReport.systemEgress}`)}{/if}.
    </p>

    {#if recommended && dns.local !== recommended.id}
      <div class="suggest appear">
        <span>{t(`Для сайтов, которые открываются напрямую, лучше подойдёт ${recommended.title}.`, `For sites that open directly, ${recommended.title} is a better fit.`)}</span>
        <button
          class="btn"
          onclick={() => {
            dns = { ...dns, local: recommended.id };
            st.dnsApplied = true;
          }}>{t("Использовать", "Use")}</button
        >
      </div>
    {:else if st.dnsApplied && recommended}
      <p class="caption appear">{t(`${recommended.title} выбран — заработает при следующем подключении.`, `${recommended.title} selected — it takes effect on the next connection.`)}</p>
    {/if}
  {/if}
</section>

<PcAudit {connected} />
</div>

<style>
  /* Карточки перестраиваются по ширине самой страницы, а не окна. */
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

  .row .btn {
    flex: none;
  }

  .row.export :global(.btn) {
    flex: none;
  }

  .row.export {
    align-items: center;
    padding-top: var(--space-3);
    border-top: 1px solid var(--stroke);
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

  .stale-note {
    color: var(--text-2);
  }

  @container (max-width: 620px) {
    .row,
    .verdict,
    .suggest {
      flex-direction: column;
      align-items: stretch;
    }

    .row .btn,
    .verdict .btn,
    .suggest .btn,
    .row.export :global(.btn) {
      align-self: flex-start;
    }

    .steps li {
      flex-direction: column;
      gap: 0;
    }

    .steps li strong {
      width: auto;
    }
  }
</style>
