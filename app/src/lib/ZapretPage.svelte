<script lang="ts">
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
        ? { mode: "Гибрид", strategy: strategyFor(zapret, networkKey) }
        : null,
  );
  const vpnConnected = $derived(status?.state === "connected");

  async function enable() {
    mode = "zapret";
    await onconnect();
  }

  function ago(unix: number): string {
    const min = Math.max(0, Math.round((Date.now() / 1000 - unix) / 60));
    if (min < 1) return "только что";
    if (min < 60) return `${min} мин назад`;
    const h = Math.round(min / 60);
    return h < 24 ? `${h} ч назад` : `${Math.round(h / 24)} дн назад`;
  }

  const shownCheck = $derived<ZapretCheck | null>(diagnosis.result?.check ?? check.last?.check ?? null);

  function fixLabel(fix: ZapretFix): string {
    switch (fix) {
      case "repair":
        return "Переустановить zapret";
      case "stop_conflicts":
        return "Остановить другие обходы";
      case "autoselect":
        return "Подобрать стратегию";
      case "allow_timestamps":
        return "Разрешить TCP timestamps";
      case "enable":
        return "Включить zapret";
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

  // ── Списки ──
  const DOMAIN = /^(?=.{1,253}$)([a-z0-9-]{1,63})(\.[a-z0-9-]{1,63})*$/;
  function parseDomains(text: string): { ok: string[]; bad: string[] } {
    const ok: string[] = [];
    const bad: string[] = [];
    for (const raw of text.split(/[\s,;]+/)) {
      const d = raw.trim().toLowerCase().replace(/^\*\./, "").replace(/^https?:\/\//, "").replace(/\/.*$/, "");
      if (!d) continue;
      if (DOMAIN.test(d)) {
        if (!ok.includes(d)) ok.push(d);
      } else bad.push(raw);
    }
    return { ok, bad };
  }
  let badUser = $state<string[]>([]);
  let badExclude = $state<string[]>([]);

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
    try {
      conflicts = await zapretStopConflicts();
    } catch {
      /* служба недоступна — список останется прежним */
    } finally {
      stopping = false;
    }
  }

  // ── Telegram ──
  let tg = $state<TgProxyStatus | null>(null);
  let tgMessage = $state<string | null>(null);
  // Прокси запускается вместе с zapret — состояние перечитывается, пока открыта вкладка.
  $effect(() => {
    const load = () => void tgProxyStatus().then((s) => (tg = s)).catch(() => {});
    load();
    const timer = setInterval(load, 3000);
    return () => clearInterval(timer);
  });

  async function connectTelegram() {
    tgMessage = null;
    try {
      await tgProxyOpen();
      tgMessage = "В Telegram откроется окно «Подключить прокси» — нажмите «Подключиться».";
    } catch (e) {
      tgMessage = message(e);
    }
  }

  async function copyTelegramLink() {
    tgMessage = null;
    try {
      await navigator.clipboard.writeText(await tgProxyLink());
      tgMessage = "Ссылка скопирована. Отправьте её себе в «Избранное» в Telegram и нажмите на неё.";
    } catch (e) {
      tgMessage = message(e);
    }
  }

  const driverText = { missing: "не установлен (установится при запуске)", stopped: "установлен", running: "работает" };
  const gameFilters: { id: GameFilter; label: string }[] = [
    { id: "off", label: "Выключен" },
    { id: "tcp", label: "TCP" },
    { id: "udp", label: "UDP" },
    { id: "all", label: "TCP и UDP" },
  ];
</script>

<!-- Состояние и проверка -->
<section class="card block">
  <div class="row">
    <div class="state">
      <span class="dot" class:on={running !== null} aria-hidden="true"></span>
      <div>
        <h2>{running ? `Работает · режим ${running.mode}` : "Zapret выключен"}</h2>
        <p class="muted">
          {#if running}
            Стратегия {strategyTitle(running.strategy)}{#if networkLabel} · сеть {networkLabel}{/if}
          {:else if vpnConnected}
            Сейчас работает VPN без zapret. Включите режим «Гибрид» или «Zapret».
          {:else}
            Обход DPI для YouTube и Discord без VPN или вместе с ним (режим «Гибрид»).
          {/if}
        </p>
      </div>
    </div>
    {#if !running}
      <button class="btn btn-primary" class:busy disabled={busy} onclick={enable}>Включить zapret</button>
    {/if}
  </div>

  <div class="last">
    <span class="caption">
      {#if check.last}
        Последняя проверка {ago(check.last.at)}: Discord и YouTube — {check.last.check.passed} из {check.last.check.max}
        {#if check.last.strategy}(стратегия {strategyTitle(check.last.strategy)}){:else}(без zapret){/if}
      {:else}
        Ещё не проверялось
      {/if}
    </span>
    <div class="actions">
      <button class="btn" class:busy={check.running} disabled={check.running || pick.running} onclick={runCheck}>
        <Icon name="pulse" size={16} />Проверить сейчас
      </button>
      <button class="btn" class:busy={diagnosis.running} disabled={diagnosis.running || pick.running} onclick={runDiagnosis}>
        <Icon name="help" size={16} />Почему не работает?
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
          <tr><th scope="col">Что проверяется</th><th scope="col">TLS 1.3</th><th scope="col">TLS 1.2</th></tr>
        </thead>
        <tbody>
          {#each shownCheck.targets as t (t.name)}
            <tr>
              <th scope="row">{t.name}</th>
              {#each [t.tls13, t.tls12] as ms, i (i)}
                <td class={ms === null ? "fail" : "ok"}>{ms === null ? "не открылось" : `${ms} мс`}</td>
              {/each}
            </tr>
          {/each}
          <tr>
            <th scope="row">Загрузка больше 32 КБ</th>
            <td colspan="2" class={shownCheck.download ? "ok" : "fail"}>
              {shownCheck.download ? "без обрыва" : "обрыв — похоже на заморозку DPI"}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  {/if}
</section>

<!-- Стратегия -->
<section class="card block">
  <div class="row">
    <div>
      <h2>Стратегия</h2>
      <p class="muted">
        Набор приёмов обхода DPI. Провайдеры блокируют по-разному, поэтому для каждой сети KVT запоминает свою.
      </p>
    </div>
    <select
      aria-label="Стратегия"
      value={current}
      disabled={pick.running || strategies.length === 0}
      onchange={(e) => choose(e.currentTarget.value)}
    >
      {#if strategies.length === 0}
        <option value={current}>{strategyTitle(current)}</option>
      {/if}
      {#each strategies as s (s.id)}
        <option value={s.id}>{s.title}{s.recommended ? "" : " (не рекомендуется)"}</option>
      {/each}
    </select>
  </div>
  <p class="caption">
    {pickedForNetwork ? "Подобрана автоматически для этой сети." : "Выбрана для всех сетей."}
    {#if currentInfo?.needsTimestamps}Нужны TCP timestamps.{/if}
    {#if currentInfo && !currentInfo.recommended}Flowseal не рекомендует эту стратегию.{/if}
    {#if running && running.strategy !== current}Применится при переподключении.{/if}
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
              ? "Проверка без zapret…"
              : `Стратегия ${pick.progress.title} (${pick.progress.index} из ${pick.progress.total})`}
            {#if pick.progress.score !== null}· {pick.progress.score} из {pick.progress.max}{/if}
          {:else}
            Подготовка…
          {/if}
        </span>
      </div>
      <button class="btn" onclick={() => void zapretAutoselectCancel()}>Остановить подбор</button>
    {:else}
      <p class="caption">
        Автоподбор: сначала проверка без zapret, затем стратегии по порядку Flowseal — до первой, при которой
        открывается всё (13 проверок на стратегию). До трёх минут.
      </p>
      <button
        class="btn"
        disabled={vpnConnected}
        title={vpnConnected ? "Отключите VPN: подбор проверяет сайты напрямую" : undefined}
        onclick={startAutoselect}
      >
        Подобрать автоматически
      </button>
    {/if}
  </div>
  {#if vpnConnected && !pick.running}
    <p class="caption">Подбор работает при отключённом VPN: в гибриде он остановил бы туннель.</p>
  {/if}
  {#if pick.error}<p class="note">{pick.error}</p>{/if}
  {#if pick.result && !pick.running}
    {@const r = pick.result}
    <p class="result appear" class:good={r.best !== null || r.baseline === r.max}>
      {#if r.cancelled && !r.best}
        Подбор остановлен.
      {:else if r.best}
        Лучше всего работает {r.bestTitle}: {r.score} из {r.max} (без zapret — {r.baseline}). Выбрана для этой сети.
      {:else if r.baseline === r.max}
        Discord и YouTube открываются и без zapret — в этой сети он не нужен.
      {:else}
        Ни одна стратегия не помогла ({r.baseline} из {r.max} без zapret). Нажмите «Почему не работает?» или
        переустановите zapret.
      {/if}
    </p>
    {#if r.tried.length > 0}
      <ul class="tried">
        {#each r.tried as t (t.id)}
          <li class:best={t.id === r.best}>
            <span>{t.title}</span>
            <span class="meter"><span style:width={`${(t.passed / r.max) * 100}%`}></span></span>
            <span class="caption">{t.passed} из {r.max}</span>
          </li>
        {/each}
      </ul>
    {/if}
  {/if}
</section>

<!-- Telegram -->
<section class="card block">
  <div class="row">
    <div>
      <h2>Telegram</h2>
      <p class="caption">
        Telegram Desktop ходит через прокси на этом компьютере в любом режиме — один раз подключили, и больше его не
        перенастраивать. В «Zapret» прокси обходится без VPN-сервера. Работают сообщения, фото и видео; звонки
        через прокси не идут.
      </p>
    </div>
    <label class="switch">
      <input type="checkbox" role="switch" checked={zapret.telegram} onchange={(e) => (zapret = { ...zapret, telegram: e.currentTarget.checked })} />
      <span aria-hidden="true"></span><span class="sr">Прокси для Telegram</span>
    </label>
  </div>
  {#if zapret.telegram}
    <div class="state">
      <span class="dot" class:on={tg?.running}></span>
      <div>
        {#if tg?.running}
          <strong>Прокси работает</strong>
          <p class="caption">Подключите Telegram один раз — дальше он сам будет ходить через прокси.</p>
        {:else if tg?.error}
          <strong>Прокси не запустился</strong>
          <p class="caption">{tg.error}</p>
        {:else if status?.state === "connected" || status?.state === "zapret"}
          <strong>Прокси запускается…</strong>
        {:else}
          <strong>Прокси выключен</strong>
          <p class="caption">Запустится, когда KVT подключится — в любом режиме.</p>
        {/if}
      </div>
    </div>
    <div class="row">
      <div>
        <span>Путь Telegram в «Гибриде»</span>
        <p class="caption">
          {#if zapret.telegramRoute === "direct"}
            Всегда мимо VPN, как в режиме «Zapret»: меньше нагрузки на сервер. Если прямой путь к Telegram закрыт,
            прокси уйдёт на запасной через Cloudflare.
          {:else}
            Сначала через VPN. Если через сервер Telegram не отвечает, прокси сам переключится на запасной путь через
            Cloudflare мимо VPN — без переподключения. Медленный, но работающий VPN запасной путь не включает.
          {/if}
          В режиме «VPN» прокси всегда ходит через VPN, в «Zapret» — без него.
        </p>
      </div>
      <select
        aria-label="Путь Telegram в «Гибриде»"
        value={zapret.telegramRoute}
        onchange={(e) => (zapret = { ...zapret, telegramRoute: e.currentTarget.value as TelegramRoute })}
      >
        <option value="direct">Мимо VPN</option>
        <option value="vpn_first">Сначала VPN</option>
      </select>
    </div>
    <div class="actions">
      <button class="btn btn-primary" disabled={!tg?.running} onclick={connectTelegram}>Подключить Telegram</button>
      <button class="btn" onclick={copyTelegramLink}>Скопировать ссылку</button>
    </div>
    {#if tgMessage}<p class="caption">{tgMessage}</p>{/if}
    <p class="caption">
      Только Telegram Desktop на этом компьютере. Прокси работает, пока запущен KVT (в том числе в трее): если закрыть
      KVT или выключить прокси, Telegram с этой настройкой не подключится — выключите прокси в настройках Telegram.
    </p>
  {/if}
</section>

<!-- Автоматически -->
<section class="card block">
  <h2>Автоматически</h2>
  <div class="row">
    <div>
      <span>Проверять, работает ли zapret</span>
      <p class="caption">Раз в полчаса и после смены сети — 13 коротких запросов к Discord и YouTube.</p>
    </div>
    <label class="switch">
      <input type="checkbox" role="switch" checked={zapret.autoCheck} onchange={(e) => (zapret = { ...zapret, autoCheck: e.currentTarget.checked })} />
      <span aria-hidden="true"></span><span class="sr">Проверять, работает ли zapret</span>
    </label>
  </div>
  <div class="row" class:disabled={!zapret.autoCheck}>
    <div>
      <span>Подбирать стратегию, если текущая перестала работать</span>
      <p class="caption">В режиме «Zapret». В гибриде KVT только предупредит: подбор остановил бы VPN.</p>
    </div>
    <label class="switch">
      <input
        type="checkbox"
        role="switch"
        disabled={!zapret.autoCheck}
        checked={zapret.autoPick}
        onchange={(e) => (zapret = { ...zapret, autoPick: e.currentTarget.checked })}
      />
      <span aria-hidden="true"></span><span class="sr">Подбирать стратегию автоматически</span>
    </label>
  </div>
</section>

<!-- Списки -->
<section class="card block">
  <h2>Списки</h2>
  <p class="muted">
    Flowseal уже знает домены Discord и YouTube. Здесь — свои дополнения: по одному домену в строке, поддомены
    включаются сами.
  </p>
  <div class="lists">
    <label>
      <span>Обходить через zapret</span>
      <textarea
        rows="4"
        spellcheck="false"
        placeholder="twitch.tv"
        value={zapret.userDomains.join("\n")}
        onchange={(e) => {
          const r = parseDomains(e.currentTarget.value);
          badUser = r.bad;
          zapret = { ...zapret, userDomains: r.ok };
        }}
      ></textarea>
      {#if badUser.length > 0}<span class="caption bad">Пропущено: {badUser.join(", ")}</span>{/if}
    </label>
    <label>
      <span>Никогда не трогать</span>
      <textarea
        rows="4"
        spellcheck="false"
        placeholder="bank.ru"
        value={zapret.excludeDomains.join("\n")}
        onchange={(e) => {
          const r = parseDomains(e.currentTarget.value);
          badExclude = r.bad;
          zapret = { ...zapret, excludeDomains: r.ok };
        }}
      ></textarea>
      {#if badExclude.length > 0}<span class="caption bad">Пропущено: {badExclude.join(", ")}</span>{/if}
    </label>
  </div>
  <p class="caption">Адреса VPN-серверов KVT исключает сам — zapret их не трогает.</p>
  <div class="row">
    <div>
      <span>Обход по IP-списку Flowseal</span>
      <p class="caption">
        zapret обрабатывает все адреса из списка ipset-all, а не только домены. Помогает, когда сервис ходит по IP
        (игры, голос), но может замедлить другие сайты.
      </p>
    </div>
    <label class="switch">
      <input type="checkbox" role="switch" checked={zapret.ipset} onchange={(e) => (zapret = { ...zapret, ipset: e.currentTarget.checked })} />
      <span aria-hidden="true"></span><span class="sr">Обход по IP-списку</span>
    </label>
  </div>
</section>

<!-- Параметры -->
<section class="card block">
  <h2>Параметры</h2>
  <div class="row">
    <div>
      <span>Игровой фильтр</span>
      <p class="caption">Обход для всех портов выше 1024 — для игр и голоса. Без нужды не включайте.</p>
    </div>
    <select
      aria-label="Игровой фильтр"
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
      <span>Разрешить включать TCP timestamps</span>
      <p class="caption">
        Части стратегий они нужны. Flowseal включает их при каждом запуске; KVT — только если разрешено. Это
        стандартная настройка TCP, она остаётся включённой.
      </p>
    </div>
    <label class="switch">
      <input
        type="checkbox"
        role="switch"
        checked={zapret.tcpTimestamps}
        onchange={(e) => (zapret = { ...zapret, tcpTimestamps: e.currentTarget.checked })}
      />
      <span aria-hidden="true"></span><span class="sr">Разрешить включать TCP timestamps</span>
    </label>
  </div>
  <p class="caption">Изменения применяются сразу: работающий zapret перезапустится.</p>
</section>

<!-- Версия и обслуживание -->
<section class="card block" id="zapret-maintenance">
  <h2>Версия и обслуживание</h2>
  {#if info}
    <dl class="facts">
      <dt>Версия Flowseal</dt>
      <dd>
        {info.version}
        <span class="caption">{info.updated ? `обновлено (в поставке KVT — ${info.bundledVersion})` : "из поставки KVT"}</span>
      </dd>
      <dt>Последняя версия</dt>
      <dd>
        {#if latest}
          {latest.version}
          <span class="caption">{updateAvailable ? "доступно обновление" : "установлена последняя"}</span>
        {:else if latestError}
          <span class="caption">не удалось узнать: {latestError}</span>
        {:else}
          <span class="caption">проверка…</span>
        {/if}
      </dd>
      <dt>Файлы</dt>
      <dd class:bad={!info.ok}>{info.ok ? `целы, стратегий: ${info.strategies}` : `повреждены: ${info.problem}`}</dd>
      <dt>Драйвер WinDivert</dt>
      <dd>{driverText[info.driver]}</dd>
      {#if info.rejected.length > 0}
        <dt>Пропущены</dt>
        <dd class="caption">{info.rejected.join(", ")} — неизвестные флаги winws</dd>
      {/if}
    </dl>
  {:else}
    <p class="caption">Служба KVT не отвечает — сведения о комплекте недоступны.</p>
  {/if}

  <div class="actions">
    <button
      class="btn"
      class:busy={checkingLatest}
      disabled={checkingLatest || maintaining !== null}
      onclick={() => checkLatest(true)}
    >
      Проверить обновления
    </button>
    <button
      class="btn"
      class:btn-primary={updateAvailable}
      class:busy={maintaining === "update"}
      disabled={maintaining !== null || pick.running}
      onclick={() => maintain("update")}
    >
      Обновить zapret
    </button>
    <button
      class="btn"
      class:busy={maintaining === "repair"}
      disabled={maintaining !== null || pick.running}
      onclick={() => (confirmRepair = true)}
    >
      Переустановить
    </button>
  </div>
  <p class="caption">
    Обновление берёт из релиза Flowseal стратегии и списки (SHA-256 сверяется с GitHub, стратегии — с белым списком).
    winws и WinDivert работают с правами системы, поэтому KVT ставит только проверенные версии — новые приходят с
    обновлением KVT.
  </p>

  {#if confirmRepair}
    <div class="confirm appear" role="alertdialog" aria-label="Переустановить zapret">
      <p>
        Переустановка остановит zapret, вернёт проверенный комплект из поставки KVT (обновление удалится), сбросит
        рабочие списки и драйвер WinDivert. Ваши настройки и подобранные стратегии сохранятся. Если zapret работал,
        он запустится снова.
      </p>
      <div class="actions">
        <button class="btn btn-primary" onclick={() => maintain("repair")}>Да, переустановить</button>
        <button class="btn" onclick={() => (confirmRepair = false)}>Отмена</button>
      </div>
    </div>
  {/if}
  {#if maintainError}<p class="note">{maintainError}</p>{/if}
  {#if report}
    <ul class="results">
      {#each report.steps as s, i (i)}
        <li class="ok"><span>{s}</span></li>
      {/each}
    </ul>
  {/if}

  {#if conflicts.length > 0}
    <div class="conflict" role="alert">
      <Icon name="warning" size={16} />
      <div>
        <strong>Работает другой обход блокировок</strong>
        <p>{conflicts.map((c) => c.name).join(", ")} — вместе с zapret KVT ничего не откроется. KVT остановит их, ничего не удаляя.</p>
      </div>
      <button class="btn" class:busy={stopping} disabled={stopping} onclick={stopConflicts}>Остановить</button>
    </div>
  {/if}

  <p class="caption">
    zapret работает через драйвер WinDivert. Антивирус Касперского помечает его как RiskTool — добавьте папку KVT в
    исключения. Античиты некоторых игр тоже реагируют на WinDivert: на время игры выберите режим VPN. Стратегии и winws —
    проект Flowseal/zapret-discord-youtube и bol-van/zapret (MIT).
  </p>
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

  .row > .btn,
  .row > select {
    flex: none;
  }

  .row > select {
    min-width: 220px;
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
    margin: 0;
    padding: var(--space-2) var(--space-3);
    border-left: 3px solid var(--warn);
    border-radius: var(--radius-s);
    background: var(--warn-subtle);
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
    grid-template-columns: 180px 1fr 80px;
    align-items: center;
    gap: var(--space-3);
    padding: 2px var(--space-2);
    border-radius: var(--radius-s);
  }

  .tried li.best {
    background: var(--ok-subtle);
  }

  .tried li.best .meter span {
    background: var(--ok);
  }

  .lists {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: var(--space-4);
  }

  .lists label {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  textarea {
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--stroke);
    border-bottom-color: var(--text-3);
    border-radius: var(--radius-s);
    background: var(--surface);
    font: 12px/18px var(--mono);
    resize: vertical;
    user-select: text;
    transition: border-color var(--dur-fast) var(--ease);
  }

  textarea:focus {
    outline: none;
    border-bottom-color: var(--accent);
    box-shadow: inset 0 -1px 0 var(--accent);
  }

  .bad {
    color: var(--danger);
  }

  .facts {
    display: grid;
    grid-template-columns: 180px 1fr;
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

  .conflict p {
    margin: 2px 0 0;
  }

  .conflict .btn {
    flex: none;
    margin-left: auto;
  }

  @media (max-width: 720px) {
    .row,
    .last,
    .pick,
    .verdict {
      flex-direction: column;
      align-items: stretch;
    }

    .lists,
    .facts {
      grid-template-columns: 1fr;
    }

    .tried li {
      grid-template-columns: 1fr 64px;
    }

    .tried .meter {
      display: none;
    }
  }
</style>
