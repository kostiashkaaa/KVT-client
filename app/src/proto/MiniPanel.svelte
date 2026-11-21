<script lang="ts">
  import { t } from "../lib/i18n";
  import Flag from "../lib/Flag.svelte";
  import Icon, { type IconName } from "../lib/Icon.svelte";
  import { formatBytes, formatElapsed, type Mode } from "../lib/api";

  let {
    connected = $bindable(true),
    mode = $bindable("hybrid"),
    network = "Home 5G",
    /** Сервер принял подключение, но данные не идут. */
    noData = false,
    /** Кадр «Подключение…» (для галереи). */
    connecting = false,
    /** Службы KVT нет. */
    serviceDown = false,
    /** Ядро остановилось, kill switch держит интернет закрытым. */
    blocked = false,
    /** Одно напоминание под заголовком: новая версия или скоро конец подписки. */
    notice = null,
  }: {
    connected?: boolean;
    mode?: Mode;
    network?: string;
    noData?: boolean;
    connecting?: boolean;
    serviceDown?: boolean;
    blocked?: boolean;
    notice?: "update" | "expiring" | null;
  } = $props();

  interface Srv {
    key: string;
    flag: string;
    name: string;
    proto: string;
    ms: number;
  }
  const servers: Srv[] = [
    { key: "nl", flag: "nl", name: t("Нидерланды", "Netherlands"), proto: "VLESS · REALITY", ms: 38 },
    { key: "de", flag: "de", name: t("Германия", "Germany"), proto: "VLESS · REALITY", ms: 47 },
    { key: "fi", flag: "fi", name: t("Финляндия", "Finland"), proto: "VLESS · XHTTP", ms: 52 },
    { key: "se", flag: "se", name: t("Швеция", "Sweden"), proto: "VLESS · REALITY", ms: 61 },
    { key: "pl", flag: "pl", name: t("Польша", "Poland"), proto: "VLESS · REALITY", ms: 66 },
  ];

  let selected = $state("nl");
  let listOpen = $state(false);
  // Пропсы задают только начальное состояние кадра, дальше панель живёт сама.
  // svelte-ignore state_referenced_locally
  let busy = $state(connecting);
  // svelte-ignore state_referenced_locally
  let stuck = $state(noData);
  // svelte-ignore state_referenced_locally
  let down = $state(serviceDown);
  let secs = $state(4327);
  const server = $derived(servers.find((s) => s.key === selected) ?? servers[0]!);

  // Быстрые переключатели: те же настройки, что в «Настройках» и на вкладке Zapret.
  let killSwitch = $state(true);
  let autoSwitch = $state(true);
  let telegram = $state(true);

  // Секунды и трафик идут сами — как у живой службы.
  $effect(() => {
    if (!connected || blocked) return;
    const timer = setInterval(() => (secs += 1), 1000);
    return () => clearInterval(timer);
  });
  const rx = $derived(1.24 * 2 ** 30 + secs * 90_000);
  const tx = $derived(84.1 * 2 ** 20 + secs * 6_000);

  const modes: { id: Mode; label: string; icon: IconName; hint: string }[] = $derived([
    { id: "vpn", label: "VPN", icon: "shield", hint: t("Весь заблокированный трафик через VPN", "All blocked traffic via VPN") },
    { id: "hybrid", label: t("Гибрид", "Hybrid"), icon: "route", hint: t("YouTube и Discord через zapret, остальное через VPN", "YouTube and Discord via zapret, the rest via VPN") },
    { id: "zapret", label: "Zapret", icon: "bolt", hint: t("Без VPN: только обход блокировок для YouTube и Discord", "No VPN: only the bypass for YouTube and Discord") },
  ]);

  const problem = $derived(connected && !busy && stuck && mode !== "zapret" && !blocked);
  const tone = $derived(
    down || blocked ? "error" : busy ? "pending" : problem ? "warn" : connected ? "on" : "off",
  );
  const title = $derived(
    down
      ? t("Служба KVT не запущена", "The KVT service isn't running")
      : blocked
        ? t("Интернет закрыт", "Internet blocked")
        : busy
          ? t("Подключение…", "Connecting…")
          : problem
            ? t("Сайты не открываются", "Sites don't open")
            : connected
              ? mode === "zapret"
                ? t("Zapret работает", "Zapret is on")
                : t("Подключено", "Connected")
              : t("Отключено", "Disconnected"),
  );
  const power = $derived(busy ? "pending" : blocked ? "on danger" : problem ? "on warn" : connected ? "on" : "off");

  const chips = $derived([
    { id: "ks", label: "Kill switch", on: killSwitch, hint: t("Если VPN оборвётся, интернет закроется — трафик не уйдёт мимо туннеля", "If the VPN drops, the internet closes — nothing leaks outside the tunnel") },
    { id: "auto", label: t("Автосмена", "Auto-switch"), on: autoSwitch, hint: t("Если данные перестали идти, KVT сам переключится на рабочий сервер", "If data stops flowing, KVT switches to a working server by itself") },
    { id: "tg", label: "Telegram", on: telegram, hint: t("Прокси для Telegram Desktop — без VPN-сервера", "Proxy for Telegram Desktop — no VPN server needed") },
  ]);

  /** Путь сервиса зависит от режима: так видно, что именно даёт каждый режим. */
  type Route = "vpn" | "zapret" | "proxy" | "none";
  type SvcState = "ok" | "fail" | "check" | "idle";

  const routeText: Record<Route, string> = $derived({
    vpn: t("через VPN", "via VPN"),
    zapret: t("через zapret", "via zapret"),
    proxy: t("через прокси KVT", "via the KVT proxy"),
    none: t("в этом режиме не откроется — нужен VPN", "won't open in this mode — VPN needed"),
  });

  const routeShort: Record<Route, string> = $derived({
    vpn: "VPN",
    zapret: "zapret",
    proxy: t("прокси", "proxy"),
    none: t("нужен VPN", "VPN needed"),
  });

  const services = $derived.by(() => {
    const viaBypass: Route = mode === "vpn" ? "vpn" : "zapret";
    const list: { name: string; route: Route }[] = [
      { name: "YouTube", route: viaBypass },
      { name: "Discord", route: viaBypass },
      { name: "Telegram", route: mode !== "vpn" && telegram ? "proxy" : mode === "zapret" ? "none" : "vpn" },
      { name: "Instagram", route: mode === "zapret" ? "none" : "vpn" },
    ];
    return list.map((s) => {
      const state: SvcState = !connected || down || blocked
        ? "idle"
        : busy
          ? "check"
          : s.route === "none" || (stuck && s.route === "vpn")
            ? "fail"
            : "ok";
      return { ...s, state, short: routeShort[s.route], hint: `${s.name} — ${routeText[s.route]}` };
    });
  });

  function flip(id: string) {
    if (id === "ks") killSwitch = !killSwitch;
    else if (id === "auto") autoSwitch = !autoSwitch;
    else telegram = !telegram;
  }

  function toggle() {
    if (busy) return;
    if (connected) {
      connected = false;
      stuck = false;
      return;
    }
    busy = true;
    setTimeout(() => {
      busy = false;
      connected = true;
      secs = 0;
    }, 1200);
  }

  /** Короткое «Подключение…» при смене режима или сервера — как в окне. */
  function reconnect() {
    if (!connected) return;
    busy = true;
    stuck = false;
    setTimeout(() => (busy = false), 900);
  }

  function setMode(m: Mode) {
    if (m === mode) return;
    mode = m;
    if (m === "zapret") listOpen = false;
    reconnect();
  }

  function pickServer(key: string) {
    selected = key;
    listOpen = false;
    if (mode !== "zapret") reconnect();
  }

  /** «Другой сервер» при проблеме: следующий по пингу. */
  function nextServer() {
    const i = servers.findIndex((s) => s.key === selected);
    pickServer(servers[(i + 1) % servers.length]!.key);
  }

  function startService() {
    down = false;
  }
</script>

<div class="panel" role="dialog" aria-label="KVT">
  <header>
    <div class="state">
      <h2 class:warn={problem} class:danger={down || blocked}>
        <span class="dot {tone}" aria-hidden="true"></span>{#key title}<span class="appear">{title}</span>{/key}
      </h2>
      <p class="caption line" class:warn={problem}>
        {#if down}
          {t("Без неё KVT не подключится", "KVT can't connect without it")}
        {:else if blocked}
          {t("kill switch не выпускает трафик мимо туннеля", "the kill switch blocks traffic outside the tunnel")}
        {:else if busy}
          {t("Обычно несколько секунд", "Usually a few seconds")}
        {:else if problem}
          {t("Данные через сервер не идут", "No data through the server")}
        {:else if connected}
          <span>{formatElapsed(secs)}</span>
          <span class="sep" aria-hidden="true">·</span>
          <span>↓&nbsp;{formatBytes(Math.round(rx))}</span>
          <span>↑&nbsp;{formatBytes(Math.round(tx))}</span>
        {:else}
          {mode === "zapret" ? t("Сервер не нужен — только обход блокировок", "No server needed — just the bypass") : t("Нажмите кнопку, чтобы подключиться", "Press the button to connect")}
        {/if}
      </p>
    </div>
    {#if down}
      <button class="btn btn-primary" onclick={startService}>{t("Запустить службу", "Start service")}</button>
    {:else}
      <button
        class="power {power}"
        aria-label={connected ? t("Отключить", "Disconnect") : t("Подключить", "Connect")}
        title={connected ? t("Отключить", "Disconnect") : t("Подключить", "Connect")}
        onclick={toggle}
      >
        <svg class="ring" viewBox="0 0 48 48" aria-hidden="true">
          <circle class="track" cx="24" cy="24" r="22.5" />
          <circle class="arc" cx="24" cy="24" r="22.5" pathLength="100" />
        </svg>
        <svg class="icon" viewBox="0 0 24 24" aria-hidden="true">
          <path d="M12 3.5v8" />
          <path d="M7.1 6.6a7.5 7.5 0 1 0 9.8 0" />
        </svg>
      </button>
    {/if}
  </header>

  <!-- Проблема: сразу два выхода — другой сервер или объяснение причины. -->
  {#if problem}
    <div class="alert appear" role="alert">
      <button class="btn" onclick={nextServer}><Icon name="refresh" size={14} />{t("Другой сервер", "Another server")}</button>
      <button class="btn ghost" onclick={() => {}}><Icon name="help" size={14} />{t("Почему?", "Why?")}</button>
    </div>
  {/if}

  {#if blocked}
    <div class="alert danger appear" role="alert">
      <button class="btn btn-primary" onclick={() => (connected = false)}>{t("Отключить и вернуть интернет", "Disconnect and restore the internet")}</button>
    </div>
  {/if}

  {#if notice && !down && !blocked}
    <div class="notice appear" role="status">
      <Icon name="info" size={14} />
      <span class="n-text">
        {notice === "update" ? t("Вышла KVT 0.9.8", "KVT 0.9.8 is out") : t("Подписка «Мой VPN» заканчивается через 3 дня", "“My VPN” expires in 3 days")}
      </span>
      <button class="n-act">{notice === "update" ? t("Скачать", "Download") : t("Подробнее", "Details")}</button>
    </div>
  {/if}

  {#if !down && !blocked}
    <div class="tiles" role="radiogroup" aria-label={t("Режим работы", "Mode")}>
      {#each modes as m (m.id)}
        <button role="radio" aria-checked={mode === m.id} class="tile" class:selected={mode === m.id} title={m.hint} onclick={() => setMode(m.id)}>
          <Icon name={m.icon} size={20} />
          <span>{m.label}</span>
        </button>
      {/each}
    </div>

    {#if mode !== "vpn"}
      <div class="zapret appear">
        <span class="z-icon" aria-hidden="true"><Icon name="bolt" size={16} /></span>
        <span class="z-text">{t(`Zapret подобран для сети «${network}»`, `Zapret picked for “${network}”`)}</span>
        <span class="z-ok" aria-hidden="true">✓</span>
      </div>
    {/if}

    {#if mode !== "zapret"}
      <div class="server appear">
        <button class="srv-row" aria-expanded={listOpen} onclick={() => (listOpen = !listOpen)}>
          <Flag code={server.flag} width={24} />
          <span class="who">
            <span class="name">{server.name}</span>
            <span class="caption">{server.proto}</span>
          </span>
          <span class="ms">{server.ms} {t("мс", "ms")}</span>
          <span class="chev" class:open={listOpen}><Icon name="chevron" size={16} /></span>
        </button>
        {#if listOpen}
          <ul class="list appear">
            {#each servers as s (s.key)}
              <li>
                <button class="srv-row item" class:current={s.key === selected} onclick={() => pickServer(s.key)}>
                  <Flag code={s.flag} width={24} />
                  <span class="name">{s.name}</span>
                  <span class="ms">{s.ms} {t("мс", "ms")}</span>
                  <span class="mark" aria-hidden="true">{s.key === selected ? "✓" : ""}</span>
                </button>
              </li>
            {/each}
          </ul>
          <button class="more">{t("Все серверы в окне KVT", "All servers in the KVT window")}<Icon name="external" size={14} /></button>
        {:else}
          <div class="usage" title={t("Остаток трафика подписки", "Subscription traffic left")}>
            <span class="caption">{t("Мой VPN · 34 из 200 ГБ", "My VPN · 34 of 200 GB")}</span>
            <span class="meter" aria-hidden="true"><span style:width="17%"></span></span>
          </div>
        {/if}
      </div>
    {/if}

    <!-- Что открывается прямо сейчас: ответ на «работает ли то, что мне надо». -->
    <ul class="services" aria-label={t("Сервисы", "Services")}>
      {#each services as s (s.name)}
        <li class="svc {s.state}" title={s.hint}>
          <span class="s-dot" aria-hidden="true"></span><span class="s-name">{s.name}</span>
          <span class="s-route">{s.short}</span>
          <span class="sr">{s.state === "ok" ? t("работает", "works") : s.state === "fail" ? t("не работает", "doesn't work") : t("не проверено", "not checked")}</span>
        </li>
      {/each}
    </ul>

    <div class="chips" role="group" aria-label={t("Быстрые настройки", "Quick settings")}>
      {#each chips as c (c.id)}
        <button class="chip" class:on={c.on} aria-pressed={c.on} title={c.hint} onclick={() => flip(c.id)}>
          <span class="tick" aria-hidden="true">{c.on ? "✓" : ""}</span>{c.label}
        </button>
      {/each}
    </div>
  {/if}

  <footer>
    <button class="foot"><Icon name="help" size={14} />{t("Почему не работает?", "Why isn't it working?")}</button>
    <span class="spacer"></span>
    <button class="foot">{t("Открыть KVT", "Open KVT")}<Icon name="external" size={14} /></button>
    <button class="foot icon-only" aria-label={t("Настройки", "Settings")} title={t("Настройки", "Settings")}><Icon name="settings" size={16} /></button>
  </footer>
</div>

<style>
  /* Окошко как у быстрых настроек Windows 11. В приложении под ним будет Mica/Acrylic —
     здесь размытие подложки только имитирует его. */
  .panel {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    width: 360px;
    padding: var(--space-4) var(--space-4) var(--space-2);
    border: 1px solid var(--stroke);
    border-radius: 8px;
    background: color-mix(in srgb, var(--surface) 86%, transparent);
    backdrop-filter: blur(28px) saturate(1.4);
    box-shadow: 0 8px 32px rgb(0 0 0 / 0.32);
  }

  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-3);
  }

  .state {
    min-width: 0;
  }

  h2 {
    display: flex;
    align-items: center;
    gap: var(--space-2);
  }

  h2.warn {
    color: var(--warn);
  }

  h2.danger {
    color: var(--danger);
  }

  h2 .appear {
    display: inline-block;
  }

  .line {
    display: flex;
    gap: var(--space-2);
    margin: 2px 0 0 calc(10px + var(--space-2));
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
  }

  .line.warn {
    color: var(--warn);
  }

  .sep {
    color: var(--text-3);
  }

  .dot {
    flex: none;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: var(--text-3);
    transition: background-color var(--dur) var(--ease);
  }

  .dot.on {
    background: var(--ok);
    box-shadow: 0 0 0 4px var(--ok-subtle);
  }

  .dot.pending {
    background: var(--warn);
    animation: kvt-pulse 1.2s ease-in-out infinite;
  }

  .dot.warn {
    background: var(--warn);
    box-shadow: 0 0 0 4px var(--warn-subtle);
  }

  .dot.error {
    background: var(--danger);
    box-shadow: 0 0 0 4px var(--danger-subtle);
  }

  /* Круглая кнопка — уменьшенная копия главной. */
  .power {
    --ring: var(--stroke-strong);
    --fill: transparent;
    --glyph: var(--accent);
    position: relative;
    display: grid;
    flex: none;
    place-items: center;
    width: 48px;
    height: 48px;
    padding: 0;
    border: 0;
    border-radius: 50%;
    background: var(--fill);
    color: var(--glyph);
    cursor: pointer;
    transition:
      background-color 300ms var(--ease),
      box-shadow 300ms var(--ease),
      transform var(--dur-fast) var(--ease);
  }

  .power.off:hover {
    --ring: var(--accent);
    background: var(--accent-subtle);
  }

  .power:active {
    transform: scale(0.96);
  }

  .power.on {
    --ring: var(--ok);
    --fill: var(--ok-subtle);
    --glyph: var(--ok);
    box-shadow: 0 0 0 4px color-mix(in srgb, var(--ok) 14%, transparent);
  }

  .power.on.warn {
    --ring: var(--warn);
    --fill: var(--warn-subtle);
    --glyph: var(--warn);
    box-shadow: 0 0 0 4px color-mix(in srgb, var(--warn) 14%, transparent);
  }

  .power.on.danger {
    --ring: var(--danger);
    --fill: var(--danger-subtle);
    --glyph: var(--danger);
    box-shadow: 0 0 0 4px color-mix(in srgb, var(--danger) 14%, transparent);
  }

  .alert.danger {
    border-left-color: var(--danger);
    background: var(--danger-subtle);
  }

  .ring {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    fill: none;
  }

  .track {
    stroke: var(--ring);
    stroke-width: 2;
    transition: stroke 300ms var(--ease);
  }

  .arc {
    stroke: var(--accent);
    stroke-width: 2;
    stroke-linecap: round;
    stroke-dasharray: 28 72;
    opacity: 0;
    transform-origin: center;
  }

  .pending .arc {
    opacity: 1;
    animation: kvt-spin 1s linear infinite;
  }

  .pending .icon {
    animation: kvt-pulse 1.2s ease-in-out infinite;
  }

  .icon {
    width: 20px;
    height: 20px;
    fill: none;
    stroke: currentColor;
    stroke-width: 2;
    stroke-linecap: round;
  }

  /* Что делать при проблеме — под заголовком, на виду. */
  .alert {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
    padding: var(--space-2) var(--space-3);
    border-left: 3px solid var(--warn);
    border-radius: var(--radius-s);
    background: var(--warn-subtle);
  }

  .alert .btn {
    min-height: 30px;
    font-size: 12px;
  }

  .alert .btn.ghost {
    border-color: transparent;
    background: transparent;
    color: var(--text);
  }

  .alert .btn.ghost:hover {
    background: color-mix(in srgb, var(--warn) 16%, transparent);
  }

  /* Режимы — крупные плитки, как переключатели в быстрых настройках Windows. */
  .tiles {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: var(--space-2);
  }

  .tile {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 6px;
    padding: var(--space-3) var(--space-2);
    border: 1px solid var(--stroke);
    border-radius: var(--radius-m);
    background: var(--surface);
    color: var(--text);
    cursor: pointer;
    transition:
      background-color var(--dur-fast) var(--ease),
      border-color var(--dur-fast) var(--ease),
      color var(--dur-fast) var(--ease);
  }

  .tile:hover:not(.selected) {
    background: var(--surface-hover);
  }

  .tile.selected {
    border-color: transparent;
    background: var(--accent);
    color: var(--accent-text);
  }

  .zapret {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    padding: var(--space-2) var(--space-3);
    border-radius: var(--radius-m);
    background: var(--ok-subtle);
    font-size: 12px;
    line-height: 16px;
  }

  .z-icon {
    display: grid;
    color: var(--ok);
  }

  .z-text {
    flex: 1;
    min-width: 0;
  }

  .z-ok {
    color: var(--ok);
    font-weight: 600;
  }

  .server {
    display: flex;
    flex-direction: column;
    border: 1px solid var(--stroke);
    border-radius: var(--radius-m);
    background: var(--surface);
    overflow: hidden;
  }

  .srv-row {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    width: 100%;
    min-height: 48px;
    padding: 0 var(--space-3);
    border: 0;
    background: transparent;
    text-align: left;
    cursor: pointer;
  }

  .srv-row:hover {
    background: var(--surface-hover);
  }

  .who {
    display: flex;
    flex: 1;
    flex-direction: column;
    min-width: 0;
  }

  .who .caption {
    line-height: 14px;
  }

  .name {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    white-space: nowrap;
    text-overflow: ellipsis;
  }

  .who .name {
    flex: none;
  }

  .ms {
    flex: none;
    color: var(--ok);
    font-variant-numeric: tabular-nums;
    font-size: 12px;
  }

  .chev {
    display: grid;
    flex: none;
    color: var(--text-2);
    transition: transform var(--dur) var(--ease);
  }

  .chev.open {
    transform: rotate(180deg);
  }

  /* Остаток трафика подписки — тонкая полоса под сервером, чтобы лимит не был сюрпризом. */
  .usage {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: 6px var(--space-3) 8px;
    border-top: 1px solid var(--stroke);
  }

  .usage .caption {
    flex: none;
  }

  .meter {
    flex: 1;
    height: 4px;
    border-radius: 2px;
    background: var(--stroke);
    overflow: hidden;
  }

  .meter span {
    display: block;
    height: 100%;
    background: var(--accent);
  }

  .list {
    max-height: 118px;
    margin: 0;
    padding: 0;
    border-top: 1px solid var(--stroke);
    list-style: none;
    overflow-y: auto;
    scrollbar-width: thin;
  }

  .item {
    min-height: 38px;
  }

  .item.current {
    background: var(--accent-subtle);
  }

  .mark {
    flex: none;
    width: 14px;
    color: var(--accent);
    font-weight: 600;
  }

  .more {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: var(--space-2);
    width: 100%;
    min-height: 34px;
    border: 0;
    border-top: 1px solid var(--stroke);
    background: transparent;
    color: var(--accent);
    font-size: 12px;
    cursor: pointer;
  }

  .more:hover {
    background: var(--surface-hover);
  }

  /* Напоминание — одна строка, не плашка: не мешает, пока не нужно. */
  .notice {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    padding: 6px var(--space-3);
    border-radius: var(--radius-s);
    background: var(--accent-subtle);
    color: var(--accent);
    font-size: 12px;
    line-height: 16px;
  }

  .n-text {
    flex: 1;
    min-width: 0;
  }

  .n-act {
    flex: none;
    padding: 0;
    border: 0;
    background: none;
    color: inherit;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
  }

  .n-act:hover {
    text-decoration: underline;
    text-underline-offset: 2px;
  }

  /* Сервисы: точка — работает, не работает или ещё не проверено. */
  .services {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 6px;
    margin: 0;
    padding: 0;
    list-style: none;
  }

  .svc {
    position: relative;
    display: flex;
    align-items: center;
    gap: 6px;
    height: 28px;
    padding: 0 10px 0 10px;
    border: 1px solid var(--stroke);
    border-radius: 14px;
    background: var(--surface);
    color: var(--text);
    font-size: 12px;
    cursor: default;
  }

  .s-name {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    white-space: nowrap;
    text-overflow: ellipsis;
  }

  /* Путь — тихо справа: что именно даёт текущий режим. */
  .s-route {
    flex: none;
    color: var(--text-3);
    font-size: 11px;
  }

  .svc.fail .s-route {
    color: var(--danger);
  }

  .s-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--text-3);
  }

  .svc.ok .s-dot {
    background: var(--ok);
  }

  .svc.fail {
    border-color: color-mix(in srgb, var(--danger) 45%, var(--stroke));
    color: var(--text);
  }

  .svc.fail .s-dot {
    background: var(--danger);
  }

  .svc.check .s-dot {
    background: var(--warn);
    animation: kvt-pulse 1.2s ease-in-out infinite;
  }

  /* Только для экранного диктора. */
  .sr {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip-path: inset(50%);
  }

  /* Быстрые настройки: включено — галочка и акцент, как у чипов Windows. */
  .chips {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: var(--space-2);
  }

  .chip {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 4px;
    min-height: 32px;
    padding: 0 var(--space-2);
    border: 1px solid var(--stroke);
    border-radius: 16px;
    background: transparent;
    color: var(--text-2);
    font-size: 12px;
    white-space: nowrap;
    cursor: pointer;
    transition:
      background-color var(--dur-fast) var(--ease),
      border-color var(--dur-fast) var(--ease),
      color var(--dur-fast) var(--ease);
  }

  .chip:hover {
    background: var(--surface-hover);
  }

  .chip.on {
    border-color: var(--accent);
    background: var(--accent-subtle);
    color: var(--accent);
    font-weight: 600;
  }

  .tick {
    min-width: 10px;
    font-size: 11px;
  }

  .tick:empty {
    display: none;
  }

  footer {
    display: flex;
    align-items: center;
    gap: var(--space-1);
    margin: 0 calc(-1 * var(--space-2)) calc(-1 * var(--space-1));
    padding-top: var(--space-2);
    border-top: 1px solid var(--stroke);
  }

  .spacer {
    flex: 1;
  }

  .foot {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    min-height: 30px;
    padding: 0 var(--space-2);
    border: 0;
    border-radius: var(--radius-s);
    background: transparent;
    color: var(--text-2);
    font-size: 12px;
    cursor: pointer;
  }

  .foot:hover {
    background: var(--surface-hover);
    color: var(--text);
  }

  .foot.icon-only {
    width: 30px;
    justify-content: center;
    padding: 0;
  }
</style>
