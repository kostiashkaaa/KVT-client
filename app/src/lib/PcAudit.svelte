<script lang="ts" module>
  import type { AuditReport, LeakReport } from "./api";

  // Итог живёт дольше страницы: можно уйти на другую вкладку и вернуться.
  const st = $state({
    report: null as AuditReport | null,
    leaks: null as LeakReport | null,
    running: false,
    error: null as string | null,
  });
</script>

<script lang="ts">
  // Проверка компьютера: аудит системы (прокси, Teredo, другие VPN и сборки zapret)
  // и проверка утечек (открытые SOCKS5, маршруты и DNS) — одной кнопкой.
  import Icon from "./Icon.svelte";
  import { leakTest, pcAudit, pcAuditFix, type AuditFinding, type AuditFix } from "./api";

  let { connected }: { connected: boolean } = $props();

  const groups: [AuditFinding["group"], string][] = [
    ["leaks", "Утечки мимо VPN"],
    ["conflicts", "Программы, которые мешают"],
    ["zapret", "Другие сборки zapret"],
  ];

  /** Идёт исправление находки с этим ключом. */
  let fixing = $state<string | null>(null);
  /** Ошибки исправлений по ключу находки. */
  let fixErrors = $state<Record<string, string>>({});

  const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

  async function run() {
    if (st.running) return;
    st.running = true;
    st.error = null;
    const [audit, leaks] = await Promise.allSettled([pcAudit(), leakTest()]);
    if (audit.status === "fulfilled") st.report = audit.value;
    if (leaks.status === "fulfilled") st.leaks = leaks.value;
    const failed = [audit, leaks].find((r) => r.status === "rejected");
    st.error = failed ? message(failed.reason) : null;
    st.running = false;
  }

  async function applyFix(key: string, fix: AuditFix) {
    if (fixing) return;
    fixing = key;
    const { [key]: _, ...rest } = fixErrors;
    fixErrors = rest;
    try {
      await pcAuditFix(fix);
      await run();
    } catch (e) {
      fixErrors = { ...fixErrors, [key]: message(e) };
    } finally {
      fixing = null;
    }
  }

  function fixLabel(fix: AuditFix): string {
    switch (fix.kind) {
      case "disable_system_proxy":
        return "Выключить прокси";
      case "close_process":
        return `Закрыть ${fix.name}`;
      case "stop_zapret":
        return "Остановить";
      case "disable_user_autostart":
        return "Отключить автозапуск";
      case "service":
        switch (fix.action) {
          case "reset_win_http_proxy":
            return "Сбросить прокси";
          case "disable_teredo":
            return "Выключить Teredo";
          case "disable_zapret_service":
          case "disable_autostart":
            return "Отключить автозапуск";
        }
    }
  }

  /** Исправления, которые выполняет служба с правами администратора. */
  function needsService(fix: AuditFix): boolean {
    return fix.kind === "service" || fix.kind === "stop_zapret";
  }

  /** Итоги проверки утечек в виде находок группы «Утечки мимо VPN». */
  const leakFindings = $derived.by<AuditFinding[]>(() => {
    const l = st.leaks;
    if (!l) return [];
    const out: AuditFinding[] = [];
    if (l.openProxies.length === 0) {
      out.push({
        group: "leaks",
        level: "ok",
        title: "Открытые прокси",
        detail: "Не найдено: программы не узнают адрес VPN-сервера через локальный порт.",
        fix: null,
      });
    }
    for (const p of l.openProxies) {
      out.push({
        group: "leaks",
        level: "warning",
        title: `Открытый SOCKS5 на порту ${p.port}`,
        detail:
          `${p.process ?? "Неизвестная программа"} пускает без пароля: любое приложение узнает через него IP ` +
          `VPN-сервера.${p.knownScanPort ? " Этот порт ищут в первую очередь." : ""} Включите в той программе ` +
          "пароль для прокси или режим TUN.",
        fix: null,
      });
    }
    // Без VPN маршруты и DNS идут напрямую — это не утечка, строки не нужны.
    if (l.connected) {
      for (const [title, r] of [
        ["Маршрут IPv4", l.ipv4Route],
        ["Маршрут IPv6", l.ipv6Route],
        ["DNS", l.dns],
      ] as const) {
        out.push({ group: "leaks", level: r.verdict, title, detail: r.detail, fix: null });
      }
    }
    return out;
  });

  const findings = $derived([...leakFindings, ...(st.report?.findings ?? [])]);
  const done = $derived(st.report !== null || st.leaks !== null);
  const warnings = $derived(findings.filter((f) => f.level === "warning").length);
  /** VPN включили или выключили после проверки: маршруты и DNS уже другие. */
  const stale = $derived(st.leaks !== null && st.leaks.connected !== connected);

  function plural(n: number, one: string, few: string, many: string): string {
    const d = n % 10;
    const dd = n % 100;
    if (d === 1 && dd !== 11) return one;
    if (d >= 2 && d <= 4 && (dd < 12 || dd > 14)) return few;
    return many;
  }
</script>

<section class="card block" aria-labelledby="audit-title">
  <div class="row">
    <div>
      <h2 id="audit-title">Проверка компьютера</h2>
      <p class="muted">
        Что пускает трафик мимо VPN или мешает KVT: открытые прокси, Teredo, другие VPN и сборки zapret, а при
        подключённом VPN — маршруты и DNS. Систему только читает; исправления — по кнопке.
      </p>
    </div>
    <button class="btn" class:busy={st.running} disabled={st.running} onclick={run}>
      <Icon name="shield" size={16} />{done ? "Проверить снова" : "Проверить компьютер"}
    </button>
  </div>

  {#if st.running && !done}
    <p class="caption">Собираю сведения о системе — несколько секунд.</p>
  {/if}
  {#if st.error}
    <p class="error-text">{st.error}</p>
  {/if}

  {#if done}
    <div class="verdict" class:warning={warnings > 0} role="status">
      <strong>
        {#if warnings === 0}
          Ничего не мешает VPN
        {:else}
          {warnings}
          {plural(warnings, "проблема", "проблемы", "проблем")}
          {plural(warnings, "мешает", "мешают", "мешают")} VPN
        {/if}
      </strong>
      {#if stale}
        <p>VPN {connected ? "подключили" : "отключили"} после проверки — проверьте снова.</p>
      {/if}
    </div>

    {#each groups as [group, title] (group)}
      {@const items = findings.filter((f) => f.group === group)}
      {#if items.length > 0}
        <h3>{title}</h3>
        <ul class="results">
          {#each items as f, i (`${group}-${i}`)}
            {@const key = `${group}-${i}`}
            <li class={f.level}>
              <div class="finding">
                <div class="text">
                  <strong>{f.title}</strong>
                  <span>{f.detail}</span>
                  {#if fixErrors[key]}
                    <span class="error-text">{fixErrors[key]}</span>
                  {/if}
                </div>
                {#if f.fix}
                  {@const fix = f.fix}
                  <div class="fix">
                    <button
                      class="btn"
                      class:busy={fixing === key}
                      disabled={fixing !== null || st.running}
                      onclick={() => applyFix(key, fix)}
                    >
                      {fixLabel(fix)}
                    </button>
                    {#if needsService(fix)}
                      <span class="caption">через службу KVT</span>
                    {/if}
                  </div>
                {/if}
              </div>
            </li>
          {/each}
        </ul>
        {#if group === "leaks" && st.leaks && !st.leaks.connected}
          <p class="caption">Маршруты и DNS проверяются при подключённом VPN.</p>
        {/if}
      {/if}
    {/each}
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

  .row .btn {
    flex: none;
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

  .verdict {
    padding: var(--space-3) var(--space-4);
    border-left: 3px solid var(--ok);
    border-radius: var(--radius-s);
    background: var(--ok-subtle);
  }

  .verdict.warning {
    border-left-color: var(--warn);
    background: var(--warn-subtle);
  }

  .verdict p {
    margin: var(--space-1) 0 0;
  }

  /* Сведения (info) — нейтральная полоса: это не проблема, а то, что стоит знать. */
  .results li.info {
    border-left-color: var(--accent);
  }

  .finding {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: var(--space-4);
  }

  .text {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .fix {
    display: flex;
    flex: none;
    flex-direction: column;
    align-items: flex-end;
    gap: var(--space-1);
  }

  @container (max-width: 620px) {
    .row,
    .finding {
      flex-direction: column;
      align-items: stretch;
    }

    .row .btn {
      align-self: flex-start;
    }

    .fix {
      align-items: flex-start;
    }
  }
</style>
