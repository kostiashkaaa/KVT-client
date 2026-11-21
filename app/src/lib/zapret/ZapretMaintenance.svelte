<script lang="ts">
  // Версия и обслуживание zapret: версия комплекта Flowseal, проверка и установка
  // обновления, переустановка с подтверждением и отчёт. Подтверждение переустановки
  // можно открыть снаружи (`confirmRepair`) — из вердикта «Почему не работает?».
  import { t } from "../i18n";
  import {
    zapretInfo,
    zapretLatest,
    zapretRepair,
    zapretUpdate,
    type FlowsealRelease,
    type MaintenanceReport,
    type ZapretInfo,
  } from "../api";
  import { pick } from "../zapretStore.svelte";

  let {
    confirmRepair = $bindable(),
    onrefresh,
  }: {
    confirmRepair: boolean;
    /** Список стратегий и чужие обходы после обновления или переустановки перечитываются. */
    onrefresh: () => Promise<void>;
  } = $props();

  const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

  let info = $state<ZapretInfo | null>(null);
  let latest = $state<FlowsealRelease | null>(null);
  let latestError = $state<string | null>(null);
  let checkingLatest = $state(false);
  let maintaining = $state<"update" | "repair" | null>(null);
  let report = $state<MaintenanceReport | null>(null);
  let maintainError = $state<string | null>(null);

  async function loadInfo() {
    info = await zapretInfo().catch(() => null);
  }
  $effect(() => void loadInfo());

  function newer(a: string, b: string): boolean {
    const pa = a.split(".").map(Number);
    const pb = b.split(".").map(Number);
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
      const x = pa[i] ?? 0;
      const y = pb[i] ?? 0;
      if (x !== y) return x > y;
    }
    return false;
  }
  const updateAvailable = $derived(latest && info ? newer(latest.version, info.version) : false);
  /** Кнопка обновления — когда есть что ставить или версию узнать не вышло (GitHub
   *  бывает доступен только через VPN, а служба скачивает и через туннель). */
  const canUpdate = $derived(updateAvailable || latestError !== null);

  async function checkLatest(force: boolean) {
    checkingLatest = true;
    latestError = null;
    try {
      latest = await zapretLatest(force);
    } catch (e) {
      latestError = message(e);
    } finally {
      checkingLatest = false;
    }
  }
  // Один запрос к GitHub при открытии вкладки (ответ кэшируется на 6 часов).
  $effect(() => void checkLatest(false));

  async function maintain(kind: "update" | "repair") {
    maintaining = kind;
    maintainError = null;
    report = null;
    confirmRepair = false;
    try {
      report = kind === "update" ? await zapretUpdate() : await zapretRepair();
      await Promise.all([loadInfo(), onrefresh()]);
    } catch (e) {
      maintainError = message(e);
    } finally {
      maintaining = null;
    }
  }

  const driverText = { missing: t("не установлен (установится при запуске)", "not installed (installs on start)"), stopped: t("установлен", "installed"), running: t("работает", "works") };
</script>

<section class="card block" id="zapret-maintenance">
  <h2>{t("Версия и обслуживание", "Version and maintenance")}</h2>
  {#if info}
    <dl class="facts">
      <dt>Flowseal</dt>
      <dd>
        {info.version}
        <span class="caption">
          {#if updateAvailable && latest}
            {t(`· доступна ${latest.version}`, `· ${latest.version} available`)}
          {:else if latest}
            {t("· последняя", "· latest")}
          {:else if latestError}
            {t("· новую версию узнать не вышло", "· couldn't check for a new version")}
          {:else if checkingLatest}
            {t("· проверка…", "· checking…")}
          {/if}
          {info.updated ? t(`(в поставке KVT — ${info.bundledVersion})`, `(shipped with KVT: ${info.bundledVersion})`) : ""}
        </span>
      </dd>
      <dt>{t("Файлы", "Files")}</dt>
      <dd class:bad={!info.ok}>{info.ok ? t(`целы, стратегий: ${info.strategies}`, `intact, strategies: ${info.strategies}`) : t(`повреждены: ${info.problem}`, `damaged: ${info.problem}`)}</dd>
      <dt>{t("Драйвер WinDivert", "WinDivert driver")}</dt>
      <dd>{driverText[info.driver]}</dd>
      {#if info.rejected.length > 0}
        <dt>{t("Пропущены", "Skipped")}</dt>
        <dd class="caption">{t(`${info.rejected.join(", ")} — неизвестные флаги winws`, `${info.rejected.join(", ")} — unknown winws flags`)}</dd>
      {/if}
    </dl>
  {:else}
    <p class="caption">{t("Служба KVT не отвечает — сведения о комплекте недоступны.", "The KVT service doesn't respond — bundle information is unavailable.")}</p>
  {/if}
  {#if latestError}<p class="caption" title={latestError}>{t(`GitHub не ответил: ${latestError}`, `GitHub didn't respond: ${latestError}`)}</p>{/if}

  <div class="actions">
    {#if canUpdate}
      <button
        class="btn btn-primary"
        class:busy={maintaining === "update"}
        disabled={maintaining !== null || pick.running}
        onclick={() => maintain("update")}
      >
        {updateAvailable && latest ? t(`Обновить до ${latest.version}`, `Update to ${latest.version}`) : t("Обновить zapret", "Update zapret")}
      </button>
    {:else}
      <button
        class="btn"
        class:busy={checkingLatest}
        disabled={checkingLatest || maintaining !== null}
        onclick={() => checkLatest(true)}
      >
        {t("Проверить обновления", "Check for updates")}
      </button>
    {/if}
    <button
      class="btn"
      class:busy={maintaining === "repair"}
      disabled={maintaining !== null || pick.running}
      onclick={() => (confirmRepair = true)}
    >
      {t("Переустановить", "Reinstall")}
    </button>
  </div>
  <p class="caption">
    {t("Обновляются стратегии и списки Flowseal, с проверкой SHA-256 и белым списком флагов. winws и WinDivert работают с правами системы — их новые версии приходят только с обновлением KVT.", "Flowseal strategies and lists are updated, with SHA-256 checks and a flag allowlist. winws and WinDivert run with system rights — their new versions only come with KVT updates.")}
  </p>

  {#if confirmRepair}
    <div class="confirm appear" role="alertdialog" aria-label={t("Переустановить zapret", "Reinstall zapret")}>
      <p>
        {t("Вернётся проверенный комплект из поставки KVT (обновление удалится), рабочие списки и драйвер WinDivert поставятся заново. Настройки и подобранные стратегии сохранятся. Если zapret работал — он перезапустится.", "The verified bundle shipped with KVT comes back (the update is removed), and the working lists and WinDivert driver are set up again. Settings and picked strategies are kept. If zapret was running, it restarts.")}
      </p>
      <div class="actions">
        <button class="btn btn-primary" onclick={() => maintain("repair")}>{t("Переустановить", "Reinstall")}</button>
        <button class="btn" onclick={() => (confirmRepair = false)}>{t("Отмена", "Cancel")}</button>
      </div>
    </div>
  {/if}
  {#if maintainError}<p class="note">{maintainError}</p>{/if}
  {#if report}
    {#if report.changed}
      <ul class="results">
        {#each report.steps as s, i (i)}
          <li class="ok"><span>{s}</span></li>
        {/each}
      </ul>
    {:else}
      <p class="caption">{report.steps[0] ?? t("Обновлять нечего.", "Nothing to update.")}</p>
    {/if}
  {/if}

  <p class="caption">
    {t("zapret работает через драйвер WinDivert. Антивирус Касперского помечает его как RiskTool — добавьте папку KVT в исключения. Античиты некоторых игр тоже реагируют на WinDivert: на время игры выберите режим «VPN». Стратегии и winws — проекты Flowseal/zapret-discord-youtube и bol-van/zapret (MIT).", "zapret works through the WinDivert driver. Kaspersky antivirus flags it as RiskTool — add the KVT folder to exclusions. Some games' anti-cheats also react to WinDivert: switch to VPN mode while playing. Strategies and winws come from the Flowseal/zapret-discord-youtube and bol-van/zapret projects (MIT).")}
  </p>
</section>

<style>
  .block {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    padding: var(--space-5);
  }

  h2 {
    margin: 0;
  }

  .caption {
    margin: 0;
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

  .bad {
    color: var(--danger);
  }

  .facts {
    display: grid;
    grid-template-columns: 160px 1fr;
    gap: var(--space-2) var(--space-4);
    margin: 0;
  }

  .facts dt {
    color: var(--text-2);
  }

  .facts dd {
    margin: 0;
  }

  .confirm {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    padding: var(--space-3) var(--space-4);
    border-left: 3px solid var(--warn);
    border-radius: var(--radius-s);
    background: var(--warn-subtle);
  }

  .confirm p {
    margin: 0;
  }

  @container (max-width: 620px) {
    .facts {
      grid-template-columns: 1fr;
    }

    .facts dd {
      margin-bottom: var(--space-1);
    }
  }
</style>
