<script lang="ts" module>
  import type { AuditReport } from "./api";

  // Итог живёт дольше страницы: можно уйти на другую вкладку и вернуться.
  const st = $state({
    report: null as AuditReport | null,
    running: false,
    error: null as string | null,
  });
</script>

<script lang="ts">
  import Icon from "./Icon.svelte";
  import { pcAudit, pcAuditFix, type AuditFinding, type AuditFix } from "./api";

  const groups: [AuditFinding["group"], string][] = [
    ["leaks", "Утечки мимо VPN"],
    ["conflicts", "Программы, которые мешают"],
    ["zapret", "Другие сборки zapret"],
  ];

  /** Идёт исправление находки с этим заголовком. */
  let fixing = $state<string | null>(null);
  /** Ошибки исправлений по заголовку находки. */
  let fixErrors = $state<Record<string, string>>({});

  async function run() {
    if (st.running) return;
    st.running = true;
    st.error = null;
    try {
      st.report = await pcAudit();
    } catch (e) {
      st.error = e instanceof Error ? e.message : String(e);
    } finally {
      st.running = false;
    }
  }

  async function applyFix(f: AuditFinding) {
    if (!f.fix || fixing) return;
    fixing = f.title;
    const { [f.title]: _, ...rest } = fixErrors;
    fixErrors = rest;
    try {
      await pcAuditFix(f.fix);
      await run();
    } catch (e) {
      fixErrors = { ...fixErrors, [f.title]: e instanceof Error ? e.message : String(e) };
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

  const warnings = $derived(st.report?.findings.filter((f) => f.level === "warning").length ?? 0);

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
      <h2 id="audit-title">Аудит компьютера</h2>
      <p class="muted">
        Ищет то, что пускает трафик мимо VPN или мешает KVT: забытый прокси других клиентов, Teredo, запущенные VPN
        и чужие сборки zapret. Только читает систему и ничего не отправляет в интернет; исправления — по кнопке.
      </p>
    </div>
    <button class="btn" disabled={st.running} onclick={run}>
      <Icon name="shield" size={16} />{st.running ? "Проверка…" : st.report ? "Проверить снова" : "Проверить компьютер"}
    </button>
  </div>

  {#if st.running && !st.report}
    <p class="caption">Собираю сведения о системе — это занимает несколько секунд.</p>
  {/if}
  {#if st.error}
    <p class="error-text">{st.error}</p>
  {/if}

  {#if st.report}
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
    </div>

    {#each groups as [group, title] (group)}
      {@const items = st.report.findings.filter((f) => f.group === group)}
      {#if items.length > 0}
        <h3>{title}</h3>
        <ul class="results">
          {#each items as f (f.title)}
            <li class={f.level}>
              <div class="finding">
                <div class="text">
                  <strong>{f.title}</strong>
                  <span>{f.detail}</span>
                  {#if fixErrors[f.title]}
                    <span class="error-text">{fixErrors[f.title]}</span>
                  {/if}
                </div>
                {#if f.fix}
                  {@const fix = f.fix}
                  <div class="fix">
                    <button class="btn" disabled={fixing !== null || st.running} onclick={() => applyFix(f)}>
                      {fixing === f.title ? "Исправляю…" : fixLabel(fix)}
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
    max-width: 560px;
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

  @media (max-width: 720px) {
    .row,
    .finding {
      flex-direction: column;
      align-items: stretch;
    }

    .fix {
      align-items: flex-start;
    }
  }
</style>
