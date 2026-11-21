<script lang="ts">
  // Состояние zapret и проверка: работает ли он, чужие обходы, последняя проверка,
  // «Почему не работает?» с исправлением и таблица проверки. Итоги проверок и
  // диагностики живут в zapretStore — их видно и на главной.
  import { t } from "../i18n";
  import Icon from "../Icon.svelte";
  import DiagExport from "../DiagExport.svelte";
  import {
    strategyTitle,
    type ZapretCheck,
    type ZapretChoice,
    type ZapretConflict,
    type ZapretFix,
  } from "../api";
  import { check, diagnosis, pick, runCheck, runDiagnosis, startAutoselect } from "../zapretStore.svelte";

  let {
    zapret = $bindable(),
    running,
    vpnConnected,
    networkLabel,
    busy,
    conflicts,
    stopping,
    conflictError,
    onenable,
    onstop,
    onrepair,
  }: {
    zapret: ZapretChoice;
    running: { mode: string; strategy: string } | null;
    vpnConnected: boolean;
    networkLabel: string | null;
    busy: boolean;
    conflicts: ZapretConflict[];
    stopping: boolean;
    conflictError: string | null;
    /** Включить zapret («Гибрид», если VPN уже работает). */
    onenable: () => Promise<void>;
    /** Остановить чужие обходы блокировок. */
    onstop: () => Promise<void>;
    /** Открыть подтверждение переустановки в «Версии и обслуживании». */
    onrepair: () => void;
  } = $props();

  function ago(unix: number): string {
    const min = Math.max(0, Math.round((Date.now() / 1000 - unix) / 60));
    if (min < 1) return t("только что", "just now");
    if (min < 60) return t(`${min} мин назад`, `${min} min ago`);
    const h = Math.round(min / 60);
    return h < 24 ? t(`${h} ч назад`, `${h} h ago`) : t(`${Math.round(h / 24)} дн назад`, `${Math.round(h / 24)} d ago`);
  }

  const shownCheck = $derived<ZapretCheck | null>(diagnosis.result?.check ?? check.last?.check ?? null);

  function fixLabel(fix: ZapretFix): string {
    switch (fix) {
      case "repair":
        return t("Переустановить zapret", "Reinstall zapret");
      case "stop_conflicts":
        return t("Остановить другие обходы", "Stop other bypasses");
      case "autoselect":
        return t("Подобрать стратегию", "Pick a strategy");
      case "allow_timestamps":
        return t("Разрешить TCP timestamps", "Allow TCP timestamps");
      case "enable":
        return vpnConnected ? t("Включить «Гибрид»", "Turn on Hybrid") : t("Включить zapret", "Turn on zapret");
    }
  }

  async function applyFix(fix: ZapretFix) {
    switch (fix) {
      case "repair":
        onrepair();
        break;
      case "stop_conflicts":
        await onstop();
        break;
      case "autoselect":
        void startAutoselect();
        break;
      case "allow_timestamps":
        zapret = { ...zapret, tcpTimestamps: true };
        break;
      case "enable":
        await onenable();
        break;
    }
  }
</script>

<section class="card block">
  <div class="row">
    <div class="state">
      <span class="dot" class:on={running !== null} aria-hidden="true"></span>
      <div>
        <h2>{running ? t(`Работает · режим ${running.mode}`, `Running · ${running.mode} mode`) : t("Zapret выключен", "Zapret is off")}</h2>
        <p class="muted">
          {#if running}
            {t(`Стратегия ${strategyTitle(running.strategy)}`, `Strategy ${strategyTitle(running.strategy)}`)}{#if networkLabel} {t(`· сеть ${networkLabel}`, `· network ${networkLabel}`)}{/if}
          {:else if vpnConnected}
            {t("Сейчас работает только VPN. «Гибрид» добавит zapret для YouTube и Discord, не отключая VPN.", "Only the VPN is running now. Hybrid adds zapret for YouTube and Discord without turning off the VPN.")}
          {:else}
            {t("Обход DPI для YouTube и Discord без VPN или вместе с ним (режим «Гибрид»).", "DPI bypass for YouTube and Discord without the VPN or together with it (Hybrid mode).")}
          {/if}
        </p>
      </div>
    </div>
    {#if !running}
      <button class="btn btn-primary" class:busy disabled={busy} onclick={onenable}>
        {vpnConnected ? t("Включить «Гибрид»", "Turn on Hybrid") : t("Включить zapret", "Turn on zapret")}
      </button>
    {/if}
  </div>

  {#if conflicts.length > 0}
    <div class="conflict appear" role="alert">
      <Icon name="warning" size={16} />
      <div>
        <strong>{t("Работает другой обход блокировок", "Another block bypass is running")}</strong>
        <p>
          {t(`${conflicts.map((c) => c.name).join(", ")} — вместе с ним zapret ничего не откроет. KVT остановит их, ничего не удаляя.`, `${conflicts.map((c) => c.name).join(", ")} — with it running, zapret won't open anything. KVT will stop them without deleting anything.`)}
        </p>
        {#if conflictError}<p class="bad">{conflictError}</p>{/if}
      </div>
      <button class="btn" class:busy={stopping} disabled={stopping} onclick={onstop}>{t("Остановить", "Stop")}</button>
    </div>
  {/if}

  <div class="last">
    <span class="caption">
      {#if check.last}
        {t(`Проверка ${ago(check.last.at)}: ${check.last.check.passed} из ${check.last.check.max}`, `Checked ${ago(check.last.at)}: ${check.last.check.passed} of ${check.last.check.max}`)}
        {#if check.last.strategy}{t(`со стратегией ${strategyTitle(check.last.strategy)}`, `with strategy ${strategyTitle(check.last.strategy)}`)}{:else}{t("без zapret", "without zapret")}{/if}
      {:else}
        {t("Ещё не проверялось", "Not checked yet")}
      {/if}
    </span>
    <div class="actions">
      <button class="btn" class:busy={check.running} disabled={check.running || pick.running} onclick={runCheck}>
        <Icon name="pulse" size={16} />{t("Проверить", "Check")}
      </button>
      <button class="btn" class:busy={diagnosis.running} disabled={diagnosis.running || pick.running} onclick={runDiagnosis}>
        <Icon name="help" size={16} />{t("Почему не работает?", "Why isn't it working?")}
      </button>
      {#if diagnosis.result}<DiagExport />{/if}
    </div>
  </div>
  {#if check.error}<p class="note">{check.error}</p>{/if}
  {#if diagnosis.error}<p class="note">{diagnosis.error}</p>{/if}

  {#if diagnosis.result}
    {@const d = diagnosis.result}
    <div class="verdict appear {d.tone}" role="status">
      <div>
        <strong>{d.title}</strong>
        {#if d.detail}<p>{d.detail}</p>{/if}
      </div>
      {#if d.fix}
        {@const fix = d.fix}
        <button class="btn btn-primary" onclick={() => applyFix(fix)}>{fixLabel(fix)}</button>
      {/if}
    </div>
    <ol class="results steps">
      {#each d.steps as s, i (i)}
        <li class={s.state}><strong>{s.title}</strong><span>{s.detail}</span></li>
      {/each}
    </ol>
  {/if}

  {#if shownCheck && shownCheck.targets.length > 0}
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th scope="col">{t("Что проверяется", "What's checked")}</th><th scope="col">TLS 1.3</th><th scope="col">TLS 1.2</th></tr>
        </thead>
        <tbody>
          {#each shownCheck.targets as target (target.name)}
            <tr>
              <th scope="row">{target.name}</th>
              {#each [target.tls13, target.tls12] as ms, i (i)}
                <td class={ms === null ? "fail" : "ok"}>{ms === null ? t("не открылось", "didn't open") : t(`${ms} мс`, `${ms} ms`)}</td>
              {/each}
            </tr>
          {/each}
          <tr>
            <th scope="row">{t("Загрузка больше 32 КБ", "Download over 32 KB")}</th>
            <td colspan="2" class={shownCheck.download ? "ok" : "fail"}>
              {shownCheck.download ? t("без обрыва", "no drop") : t("обрыв — похоже на заморозку DPI", "dropped — looks like DPI throttling")}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
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

  .row > .btn {
    flex: none;
  }

  h2 {
    margin: 0;
  }

  .muted,
  .caption {
    margin: 0;
  }

  /* Точка — по центру строки заголовка, а не между строками. */
  .state {
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
  }

  .state p {
    margin: 2px 0 0;
  }

  .dot {
    flex: none;
    width: 10px;
    height: 10px;
    margin-top: 6px;
    border-radius: 50%;
    background: var(--text-3);
    transition:
      background-color var(--dur) var(--ease),
      box-shadow var(--dur) var(--ease);
  }

  .dot.on {
    background: var(--ok);
    box-shadow: 0 0 0 4px var(--ok-subtle);
  }

  .last {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-4);
  }

  .actions {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
  }

  .note {
    margin: 0;
    padding: var(--space-2) var(--space-3);
    border-left: 3px solid var(--warn);
    border-radius: var(--radius-s);
    background: var(--warn-subtle);
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

  .steps li {
    flex-direction: row;
    align-items: baseline;
    gap: var(--space-4);
    padding: var(--space-1) var(--space-3);
    background: transparent;
  }

  .steps li strong {
    flex: none;
    width: 170px;
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
    font-size: 12px;
    color: var(--text-3);
  }

  tbody th {
    font-weight: 600;
  }

  td.ok {
    color: var(--ok);
  }

  td.fail {
    color: var(--danger);
  }

  .bad {
    color: var(--danger);
  }

  .conflict {
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
    padding: var(--space-3);
    border-left: 3px solid var(--warn);
    border-radius: var(--radius-s);
    background: var(--warn-subtle);
  }

  .conflict :global(svg) {
    flex: none;
    margin-top: 2px;
    color: var(--warn);
  }

  .conflict > div {
    flex: 1;
  }

  .conflict p {
    margin: 2px 0 0;
  }

  .conflict .btn {
    flex: none;
  }

  @container (max-width: 620px) {
    /* Переключатель остаётся справа от текста, поле и кнопка уходят под него. */
    .row:has(> .btn),
    .last,
    .verdict,
    .conflict {
      flex-direction: column;
      align-items: stretch;
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
