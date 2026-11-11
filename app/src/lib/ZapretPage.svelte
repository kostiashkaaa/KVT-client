<script lang="ts">
  import { t } from "./i18n";
  import Icon from "./Icon.svelte";
  import DiagExport from "./DiagExport.svelte";
  import {
    currentNetwork,
    onNetworkChanged,
    strategyFor,
    strategyTitle,
    tgProxyLink,
    tgProxyOpen,
    tgProxyStatus,
    zapretAutoselectCancel,
    zapretConflicts,
    zapretInfo,
    zapretLatest,
    zapretRepair,
    zapretStopConflicts,
    zapretStrategies,
    zapretUpdate,
    type FlowsealRelease,
    type GameFilter,
    type MaintenanceReport,
    type TelegramRoute,
    type TgProxyStatus,
    type Mode,
    type ServiceStatus,
    type ZapretCheck,
    type ZapretChoice,
    type ZapretConflict,
    type ZapretFix,
    type ZapretInfo,
    type ZapretStrategy,
  } from "./api";
  import { check, diagnosis, listenChecks, pick, runCheck, runDiagnosis, startAutoselect } from "./zapretStore.svelte";

  let {
    zapret = $bindable(),
    mode = $bindable(),
    status,
    busy,
    onconnect,
  }: {
    zapret: ZapretChoice;
    mode: Mode;
    status: ServiceStatus | null;
    busy: boolean;
    onconnect: () => Promise<void>;
  } = $props();

  listenChecks();

  const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

  // ── Состояние ──
  let networkKey = $state<string | null>(null);
  let networkLabel = $state<string | null>(null);
  $effect(() => {
    const apply = (v: { network: { key: string; label: string } | null }) => {
      networkKey = v.network?.key ?? null;
      networkLabel = v.network?.label ?? null;
    };
    void currentNetwork().then(apply);
    return onNetworkChanged(apply);
  });

  const running = $derived(
    status?.state === "zapret"
      ? { mode: "Zapret", strategy: status.strategy }
      : status?.state === "connected" && mode === "hybrid"
        ? { mode: t("Гибрид", "Hybrid"), strategy: strategyFor(zapret, networkKey) }
        : null,
  );
  const vpnConnected = $derived(status?.state === "connected");

  /** При работающем VPN zapret добавляется «Гибридом» — VPN не отключается. */
  async function enable() {
    mode = vpnConnected ? "hybrid" : "zapret";
    await onconnect();
  }

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
        confirmRepair = true;
        document.getElementById("zapret-maintenance")?.scrollIntoView({ behavior: "smooth" });
        break;
      case "stop_conflicts":
        await stopConflicts();
        break;
      case "autoselect":
        void startAutoselect();
        break;
      case "allow_timestamps":
        zapret = { ...zapret, tcpTimestamps: true };
        break;
      case "enable":
        await enable();
        break;
    }
  }

  // ── Стратегия ──
  let strategies = $state<ZapretStrategy[]>([]);
  async function loadStrategies() {
    strategies = await zapretStrategies().catch(() => []);
  }
  $effect(() => void loadStrategies());

  const recommended = $derived(strategies.filter((s) => s.recommended));
  const others = $derived(strategies.filter((s) => !s.recommended));
  const current = $derived(strategyFor(zapret, networkKey));
  const currentInfo = $derived(strategies.find((s) => s.id === current) ?? null);
  const pickedForNetwork = $derived(networkKey !== null && zapret.byNetwork[networkKey] !== undefined);

  /** Ручной выбор действует и в этой сети: подобранная для неё стратегия забывается. */
  function choose(id: string) {
    const byNetwork = { ...zapret.byNetwork };
    if (networkKey) delete byNetwork[networkKey];
    zapret = { ...zapret, strategy: id, byNetwork };
  }

  const share = $derived(
    pick.progress && pick.progress.total > 0 ? Math.min(1, pick.progress.index / pick.progress.total) : 0,
  );

  // ── Обслуживание ──
  let info = $state<ZapretInfo | null>(null);
  let latest = $state<FlowsealRelease | null>(null);
  let latestError = $state<string | null>(null);
  let checkingLatest = $state(false);
  let maintaining = $state<"update" | "repair" | null>(null);
  let report = $state<MaintenanceReport | null>(null);
  let maintainError = $state<string | null>(null);
  let confirmRepair = $state(false);
  let conflicts = $state<ZapretConflict[]>([]);
  let stopping = $state(false);
  let conflictError = $state<string | null>(null);

  async function loadInfo() {
    info = await zapretInfo().catch(() => null);
    conflicts = await zapretConflicts().catch(() => []);
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
      await Promise.all([loadInfo(), loadStrategies()]);
    } catch (e) {
      maintainError = message(e);
    } finally {
      maintaining = null;
    }
  }

  async function stopConflicts() {
    stopping = true;
    conflictError = null;
    try {
      conflicts = await zapretStopConflicts();
      if (conflicts.length > 0) conflictError = t("Остановить не вышло — закройте эти программы сами.", "Couldn't stop them — close these apps yourself.");
    } catch (e) {
      conflictError = message(e);
    } finally {
      stopping = false;
    }
  }

  // ── Telegram ──
  let tg = $state<TgProxyStatus | null>(null);
  let tgMessage = $state<string | null>(null);
  // Прокси запускается вместе с подключением — состояние перечитывается, пока открыта вкладка.
  $effect(() => {
    if (!zapret.telegram) return;
    const load = () => void tgProxyStatus().then((s) => (tg = s)).catch(() => {});
    load();
    const timer = setInterval(load, 3000);
    return () => clearInterval(timer);
  });

  async function connectTelegram() {
    tgMessage = null;
    try {
      await tgProxyOpen();
      tgMessage = t("В Telegram откроется окно «Подключить прокси» — нажмите «Подключиться».", "Telegram will open a “Connect proxy” window — press “Connect”.");
    } catch (e) {
      tgMessage = message(e);
    }
  }

  async function copyTelegramLink() {
    tgMessage = null;
    try {
      await navigator.clipboard.writeText(await tgProxyLink());
      tgMessage = t("Ссылка скопирована. Отправьте её себе в «Избранное» в Telegram и нажмите на неё.", "Link copied. Send it to your “Saved Messages” in Telegram and tap it.");
    } catch (e) {
      tgMessage = message(e);
    }
  }

  const driverText = { missing: t("не установлен (установится при запуске)", "not installed (installs on start)"), stopped: t("установлен", "installed"), running: t("работает", "works") };
  const gameFilters: { id: GameFilter; label: string }[] = [
    { id: "off", label: t("Выключен", "Off") },
    { id: "tcp", label: "TCP" },
    { id: "udp", label: "UDP" },
    { id: "all", label: t("TCP и UDP", "TCP and UDP") },
  ];
  /** Подпись про перезапуск: в «Гибриде» вместе с zapret переподключается VPN. */
  const restartNote = $derived(
    running && running.mode !== "Zapret"
      ? t("Изменения применяются сразу: VPN и zapret переподключатся на пару секунд.", "Changes apply immediately: the VPN and zapret will reconnect for a couple of seconds.")
      : running
        ? t("Изменения применяются сразу: zapret перезапустится на пару секунд.", "Changes apply immediately: zapret will restart for a couple of seconds.")
        : null,
  );
</script>

<div class="page">
  <!-- Состояние и проверка -->
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
        <button class="btn btn-primary" class:busy disabled={busy} onclick={enable}>
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
        <button class="btn" class:busy={stopping} disabled={stopping} onclick={stopConflicts}>{t("Остановить", "Stop")}</button>
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

  <!-- Стратегия и автопроверка -->
  <section class="card block">
    <div class="row">
      <div>
        <h2>{t("Стратегия", "Strategy")}</h2>
        <p class="muted">{t("Провайдеры блокируют по-разному, поэтому для каждой сети KVT запоминает свою.", "ISPs block in different ways, so KVT remembers a strategy for each network.")}</p>
      </div>
      <select
        aria-label={t("Стратегия", "Strategy")}
        value={current}
        disabled={pick.running || strategies.length === 0}
        onchange={(e) => choose(e.currentTarget.value)}
      >
        {#if strategies.length === 0}
          <option value={current}>{strategyTitle(current)}</option>
        {/if}
        {#each recommended as s (s.id)}
          <option value={s.id}>{s.title}</option>
        {/each}
        {#if others.length > 0}
          <optgroup label={t("Flowseal не рекомендует", "Not recommended by Flowseal")}>
            {#each others as s (s.id)}
              <option value={s.id}>{s.title}</option>
            {/each}
          </optgroup>
        {/if}
      </select>
    </div>
    <p class="caption">
      {#if pickedForNetwork}
        {t(`Подобрана автоматически${networkLabel ? ` для сети ${networkLabel}` : " для этой сети"}.`, `Picked automatically${networkLabel ? ` for network ${networkLabel}` : " for this network"}.`)}
      {:else}
        {t("Выбрана для всех сетей.", "Chosen for all networks.")}
      {/if}
      {#if currentInfo?.needsTimestamps}{t("Нужны TCP timestamps.", "Needs TCP timestamps.")}{/if}
      {#if currentInfo && !currentInfo.recommended}{t("Flowseal не рекомендует эту стратегию.", "Flowseal doesn't recommend this strategy.")}{/if}
    </p>

    <div class="pick">
      {#if pick.running}
        <div class="progress">
          <div class="bar" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(share * 100)}>
            <span style:width={`${share * 100}%`}></span>
          </div>
          <span class="caption">
            {#if pick.progress}
              {pick.progress.index === 0
                ? t("Проверка без zapret…", "Checking without zapret…")
                : t(`Стратегия ${pick.progress.title} (${pick.progress.index} из ${pick.progress.total})`, `Strategy ${pick.progress.title} (${pick.progress.index} of ${pick.progress.total})`)}
              {#if pick.progress.score !== null}{t(`· ${pick.progress.score} из ${pick.progress.max}`, `· ${pick.progress.score} of ${pick.progress.max}`)}{/if}
            {:else}
              {t("Подготовка…", "Preparing…")}
            {/if}
          </span>
        </div>
        <button class="btn" onclick={() => void zapretAutoselectCancel()}>{t("Остановить подбор", "Stop picking")}</button>
      {:else}
        <p class="caption">
          {vpnConnected
            ? t("Подбор проверяет сайты напрямую — сначала отключите VPN.", "Picking checks sites directly — disconnect the VPN first.")
            : t("Проверка без zapret, затем стратегии по порядку Flowseal до первой, с которой открывается всё. До трёх минут.", "A check without zapret, then strategies in Flowseal's order until the first one that opens everything. Up to three minutes.")}
        </p>
        <button class="btn" disabled={vpnConnected} onclick={startAutoselect}>{t("Подобрать автоматически", "Pick automatically")}</button>
      {/if}
    </div>
    {#if pick.error}<p class="note">{pick.error}</p>{/if}
    {#if pick.result && !pick.running}
      {@const r = pick.result}
      <div class="result appear" class:good={r.best !== null || r.baseline === r.max}>
        <p>
          {#if r.cancelled && !r.best}
            {t("Подбор остановлен.", "Picking stopped.")}
          {:else if r.best}
            {t(`Лучше всего работает ${r.bestTitle}: ${r.score} из ${r.max} (без zapret — ${r.baseline}). Выбрана для этой сети.`, `${r.bestTitle} works best: ${r.score} of ${r.max} (without zapret — ${r.baseline}). Chosen for this network.`)}
          {:else if r.baseline === r.max}
            {t("Discord и YouTube открываются и без zapret — в этой сети он не нужен.", "Discord and YouTube open even without zapret — it isn't needed on this network.")}
          {:else}
            {t(`Ни одна стратегия не помогла (${r.baseline} из ${r.max} без zapret). Нажмите «Почему не работает?» или переустановите zapret.`, `No strategy helped (${r.baseline} of ${r.max} without zapret). Press “Why isn't it working?” or reinstall zapret.`)}
          {/if}
        </p>
        {#if r.best && !running && !vpnConnected}
          <button class="btn btn-primary" class:busy disabled={busy} onclick={enable}>{t("Включить zapret", "Turn on zapret")}</button>
        {/if}
      </div>
      {#if r.tried.length > 0}
        <ul class="tried">
          {#each r.tried as tried (tried.id)}
            <li class:best={tried.id === r.best}>
              <span class="name" title={tried.title}>{tried.title}</span>
              <span class="meter"><span style:width={`${(tried.passed / r.max) * 100}%`}></span></span>
              <span class="caption">{t(`${tried.passed} из ${r.max}`, `${tried.passed} of ${r.max}`)}</span>
            </li>
          {/each}
        </ul>
      {/if}
    {/if}

    <div class="divider"></div>
    <div class="row">
      <div>
        <span>{t("Проверять, работает ли zapret", "Check whether zapret works")}</span>
        <p class="caption">{t("Раз в полчаса и после смены сети — 13 коротких запросов к Discord и YouTube.", "Every half hour and after a network change — 13 short requests to Discord and YouTube.")}</p>
      </div>
      <label class="switch">
        <input type="checkbox" role="switch" checked={zapret.autoCheck} onchange={(e) => (zapret = { ...zapret, autoCheck: e.currentTarget.checked })} />
        <span aria-hidden="true"></span><span class="sr">{t("Проверять, работает ли zapret", "Check whether zapret works")}</span>
      </label>
    </div>
    <div class="row" class:disabled={!zapret.autoCheck}>
      <div>
        <span>{t("Подбирать новую, если текущая перестала работать", "Pick a new one if the current one stops working")}</span>
        <p class="caption">{t("Только в режиме «Zapret». В «Гибриде» KVT предупредит: подбор остановил бы VPN.", "Zapret mode only. In Hybrid, KVT will warn you instead: picking would stop the VPN.")}</p>
      </div>
      <label class="switch">
        <input
          type="checkbox"
          role="switch"
          disabled={!zapret.autoCheck}
          checked={zapret.autoPick}
          onchange={(e) => (zapret = { ...zapret, autoPick: e.currentTarget.checked })}
        />
        <span aria-hidden="true"></span><span class="sr">{t("Подбирать стратегию автоматически", "Pick a strategy automatically")}</span>
      </label>
    </div>
  </section>

  <!-- Telegram -->
  <section class="card block">
    <div class="row">
      <div>
        <h2>Telegram</h2>
        <p class="muted">
          {t("Telegram Desktop ходит через прокси KVT в любом режиме — подключите его один раз. Работают сообщения, фото и видео; звонки через прокси не идут.", "Telegram Desktop goes through KVT's proxy in any mode — connect it once. Messages, photos and videos work; calls don't go through the proxy.")}
        </p>
      </div>
      <label class="switch">
        <input type="checkbox" role="switch" checked={zapret.telegram} onchange={(e) => (zapret = { ...zapret, telegram: e.currentTarget.checked })} />
        <span aria-hidden="true"></span><span class="sr">{t("Прокси для Telegram", "Telegram proxy")}</span>
      </label>
    </div>
    {#if zapret.telegram}
      <div class="tg">
        <div class="state">
          <span class="dot" class:on={tg?.running} aria-hidden="true"></span>
          <div>
            {#if tg?.running}
              <strong>{t("Прокси работает", "Proxy is running")}</strong>
            {:else if tg?.error}
              <strong>{t("Прокси не запустился", "The proxy didn't start")}</strong>
              <p class="caption">{tg.error}</p>
            {:else if status?.state === "connected" || status?.state === "zapret"}
              <strong>{t("Прокси запускается…", "The proxy is starting…")}</strong>
            {:else}
              <strong>{t("Прокси выключен", "Proxy is off")}</strong>
              <p class="caption">{t("Запустится, когда KVT подключится.", "It starts when KVT connects.")}</p>
            {/if}
          </div>
        </div>
        <div class="actions">
          <button class="btn btn-primary" disabled={!tg?.running} onclick={connectTelegram}>{t("Подключить Telegram", "Connect Telegram")}</button>
          <button class="btn" onclick={copyTelegramLink}>{t("Скопировать ссылку", "Copy link")}</button>
        </div>
      </div>
      {#if tgMessage}<p class="caption">{tgMessage}</p>{/if}
      <div class="row">
        <div>
          <span>{t("Путь Telegram в «Гибриде»", "Telegram's route in Hybrid")}</span>
          <p class="caption">
            {zapret.telegramRoute === "direct"
              ? t("Мимо VPN, как в «Zapret»: сервер не нагружается. Если прямой путь закрыт — запасной через Cloudflare.", "Around the VPN, as in Zapret mode: the server isn't loaded. If the direct route is blocked, a fallback goes through Cloudflare.")
              : t("Через VPN; если сервер не отвечает, прокси сам уйдёт на запасной путь через Cloudflare, без переподключения.", "Via the VPN; if the server doesn't respond, the proxy switches to the Cloudflare fallback itself, without reconnecting.")}
          </p>
        </div>
        <select
          aria-label={t("Путь Telegram в «Гибриде»", "Telegram's route in Hybrid")}
          value={zapret.telegramRoute}
          onchange={(e) => (zapret = { ...zapret, telegramRoute: e.currentTarget.value as TelegramRoute })}
        >
          <option value="direct">{t("Мимо VPN", "Around the VPN")}</option>
          <option value="vpn_first">{t("Сначала VPN", "VPN first")}</option>
        </select>
      </div>
      <p class="caption">
        {t("Прокси работает, пока запущен KVT (и в трее). Если закрыть KVT или выключить прокси здесь, уберите прокси и в настройках Telegram — иначе он не подключится.", "The proxy runs while KVT is running (including in the tray). If you quit KVT or turn off the proxy here, remove the proxy in Telegram's settings too — otherwise it won't connect.")}
      </p>
    {/if}
  </section>

  <!-- Параметры -->
  <section class="card block">
    <h2>{t("Параметры", "Options")}</h2>
    <div class="row">
      <div>
        <span>{t("Игровой фильтр", "Game filter")}</span>
        <p class="caption">{t("Обход на всех портах выше 1024 — для игр и голоса. Без нужды не включайте.", "Bypass on all ports above 1024 — for games and voice. Don't turn on unless needed.")}</p>
      </div>
      <select
        aria-label={t("Игровой фильтр", "Game filter")}
        value={zapret.gameFilter}
        onchange={(e) => (zapret = { ...zapret, gameFilter: e.currentTarget.value as GameFilter })}
      >
        {#each gameFilters as g (g.id)}
          <option value={g.id}>{g.label}</option>
        {/each}
      </select>
    </div>
    <div class="row">
      <div>
        <span>{t("Обход по IP-списку Flowseal", "Bypass by Flowseal's IP list")}</span>
        <p class="caption">
          {t("Не только по доменам, а по всем адресам из ipset-all. Помогает, когда сервис ходит по IP (игры, голос), но может замедлить другие сайты.", "Not just by domain but by every address in ipset-all. Helps when a service connects by IP (games, voice), but may slow down other sites.")}
        </p>
      </div>
      <label class="switch">
        <input type="checkbox" role="switch" checked={zapret.ipset} onchange={(e) => (zapret = { ...zapret, ipset: e.currentTarget.checked })} />
        <span aria-hidden="true"></span><span class="sr">{t("Обход по IP-списку", "Bypass by IP list")}</span>
      </label>
    </div>
    <div class="row">
      <div>
        <span>{t("Разрешить включать TCP timestamps", "Allow turning on TCP timestamps")}</span>
        <p class="caption">
          {t("Они нужны части стратегий. Flowseal включает их при каждом запуске, KVT — только с разрешения. Это обычная настройка TCP, она остаётся включённой.", "Some strategies need them. Flowseal turns them on at every start, KVT only with your permission. It's a regular TCP setting and stays on.")}
        </p>
      </div>
      <label class="switch">
        <input
          type="checkbox"
          role="switch"
          checked={zapret.tcpTimestamps}
          onchange={(e) => (zapret = { ...zapret, tcpTimestamps: e.currentTarget.checked })}
        />
        <span aria-hidden="true"></span><span class="sr">{t("Разрешить включать TCP timestamps", "Allow turning on TCP timestamps")}</span>
      </label>
    </div>
    {#if restartNote}<p class="caption">{restartNote}</p>{/if}
  </section>

  <!-- Версия и обслуживание -->
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

  .row > .btn,
  .row > select {
    flex: none;
  }

  .row > select {
    min-width: 220px;
  }

  .head {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: var(--space-3);
  }

  h2 {
    margin: 0;
  }

  .divider {
    height: 1px;
    margin: var(--space-1) 0;
    background: var(--stroke);
  }

  .tg {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-4);
    padding: var(--space-3) var(--space-4);
    border-radius: var(--radius-s);
    background: var(--surface-hover);
  }

  .tg .state {
    align-items: center;
  }

  .tg .dot {
    margin-top: 0;
  }

  .row.disabled {
    opacity: 0.55;
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

  .pick {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-4);
  }

  .pick .btn {
    flex: none;
  }

  .progress {
    display: flex;
    flex: 1;
    flex-direction: column;
    gap: var(--space-1);
    min-width: 0;
  }

  .bar,
  .meter {
    display: block;
    height: 4px;
    border-radius: 2px;
    background: var(--stroke);
    overflow: hidden;
  }

  .bar span,
  .meter span {
    display: block;
    height: 100%;
    background: var(--accent);
    transition: width 300ms var(--ease);
  }

  .result {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-4);
    margin: 0;
    padding: var(--space-2) var(--space-3);
    border-left: 3px solid var(--warn);
    border-radius: var(--radius-s);
    background: var(--warn-subtle);
  }

  .result p {
    margin: 0;
  }

  .result .btn {
    flex: none;
  }

  .result.good {
    border-left-color: var(--ok);
    background: var(--ok-subtle);
  }

  .tried {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    margin: 0;
    padding: 0;
    list-style: none;
  }

  .tried li {
    display: grid;
    grid-template-columns: minmax(0, 240px) 1fr 72px;
    align-items: center;
    gap: var(--space-3);
    padding: 2px var(--space-2);
    border-radius: var(--radius-s);
  }

  .tried .name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .tried li.best {
    background: var(--ok-subtle);
  }

  .tried li.best .meter span {
    background: var(--ok);
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
    .row:has(> select),
    .row:has(> .btn),
    .last,
    .pick,
    .verdict,
    .result,
    .tg,
    .conflict {
      flex-direction: column;
      align-items: stretch;
    }

    .facts {
      grid-template-columns: 1fr;
    }

    .facts dd {
      margin-bottom: var(--space-1);
    }

    .steps li {
      flex-direction: column;
      gap: 0;
    }

    .steps li strong {
      width: auto;
    }

    .tried li {
      grid-template-columns: 1fr 64px;
    }

    .tried .meter {
      display: none;
    }
  }
</style>
