<script lang="ts">
  import Icon from "./Icon.svelte";
  import {
    aboutInfo,
    openLink,
    zapretInfo,
    type About,
    autostartEnabled,
    setAutostart,
    currentNetwork,
    dnsCatalog,
    onNetworkChanged,
    type DnsChoice,
    type Mode,
    type NetworkProfile,
    type NetworkView,
    type OnJoin,
    type Resolver,
  } from "./api";

  let {
    killSwitch = $bindable(),
    autoSwitch = $bindable(),
    dns = $bindable(),
    networks = $bindable(),
    notifications = $bindable(),
    connectOnStart = $bindable(),
    onrestartonboarding,
  }: {
    killSwitch: boolean;
    autoSwitch: boolean;
    dns: DnsChoice;
    networks: NetworkProfile[];
    notifications: boolean;
    connectOnStart: boolean;
    /** Показать подсказки первого запуска снова. */
    onrestartonboarding: () => void;
  } = $props();

  let about = $state<About | null>(null);
  let flowseal = $state<string | null>(null);
  let linkError = $state<string | null>(null);
  $effect(() => {
    void aboutInfo().then((a) => (about = a));
    void zapretInfo()
      .then((z) => (flowseal = z.version))
      .catch(() => (flowseal = null));
  });
  const coreTitles: Record<string, string> = { xray: "Xray", "sing-box": "sing-box", wintun: "Wintun" };
  async function open(target: "source" | "releases" | "licenses") {
    linkError = null;
    try {
      await openLink(target);
    } catch (e) {
      linkError = String(e);
    }
  }

  // Автозапуск хранится в реестре Windows: его можно выключить и в «Диспетчере задач».
  let autostart = $state(false);
  let autostartError = $state<string | null>(null);
  $effect(() => {
    void autostartEnabled().then((v) => (autostart = v));
  });
  async function toggleAutostart(enabled: boolean) {
    autostartError = null;
    try {
      await setAutostart(enabled);
      autostart = enabled;
    } catch (e) {
      autostartError = String(e);
      autostart = await autostartEnabled();
    }
  }

  let resolvers = $state<Resolver[]>([]);
  $effect(() => {
    void dnsCatalog().then((r) => (resolvers = r));
  });
  const tunnelResolvers = $derived(resolvers.filter((r) => r.tunnel));

  let here = $state<NetworkView>({ network: null, profile: null });
  $effect(() => {
    void currentNetwork().then((v) => (here = v));
    return onNetworkChanged((v) => (here = v));
  });

  const known = $derived(here.network ? networks.some((p) => p.key === here.network?.key) : false);

  function remember() {
    const n = here.network;
    if (!n || known) return;
    networks = [...networks, { key: n.key, name: n.label, onJoin: "nothing", mode: null }];
  }

  function update(key: string, patch: Partial<NetworkProfile>) {
    networks = networks.map((p) => (p.key === key ? { ...p, ...patch } : p));
  }

  function forget(key: string) {
    networks = networks.filter((p) => p.key !== key);
  }

  const kinds = { wifi: "Wi-Fi", ethernet: "Кабель", mobile: "Мобильная сеть", other: "Сеть" } as const;
  const onJoinOptions: { id: OnJoin; label: string }[] = [
    { id: "nothing", label: "Не трогать VPN" },
    { id: "connect", label: "Включать VPN" },
    { id: "disconnect", label: "Выключать VPN" },
  ];
  const modeOptions: { id: Mode | ""; label: string }[] = [
    { id: "", label: "Не менять режим" },
    { id: "vpn", label: "Режим VPN" },
    { id: "hybrid", label: "Режим «Гибрид»" },
    { id: "zapret", label: "Режим Zapret" },
  ];
</script>

<section class="card block">
  <div class="row">
    <div>
      <h2>Kill switch</h2>
      <p class="muted">
        Если VPN оборвётся, интернет будет закрыт, пока вы не нажмёте «Отключить». Ни один запрос не уйдёт мимо
        туннеля. Если сама служба KVT остановится, Windows снимет блокировку автоматически.
      </p>
    </div>
    <label class="switch">
      <input type="checkbox" role="switch" bind:checked={killSwitch} />
      <span aria-hidden="true"></span>
      <span class="sr">Kill switch</span>
    </label>
  </div>
  <p class="caption">Изменение применится при следующем подключении.</p>
</section>

<section class="card block">
  <div class="row">
    <div>
      <h2>Автопереключение сервера</h2>
      <p class="muted">
        Раз в минуту KVT проверяет одним маленьким запросом, идут ли данные через туннель. Если сервер перестал
        отвечать, KVT подключится к следующему рабочему серверу подписки — не чаще трёх раз за полчаса.
      </p>
    </div>
    <label class="switch">
      <input type="checkbox" role="switch" bind:checked={autoSwitch} />
      <span aria-hidden="true"></span>
      <span class="sr">Автопереключение сервера</span>
    </label>
  </div>
</section>

<section class="card block">
  <h2>Работа в фоне</h2>
  <div class="row">
    <div>
      <h3>Запускать вместе с Windows</h3>
      <p class="muted">KVT стартует свёрнутым в трей — окно не появляется.</p>
    </div>
    <label class="switch">
      <input
        type="checkbox"
        role="switch"
        checked={autostart}
        onchange={(e) => void toggleAutostart(e.currentTarget.checked)}
      />
      <span aria-hidden="true"></span>
      <span class="sr">Запускать вместе с Windows</span>
    </label>
  </div>
  {#if autostartError}
    <p class="caption error-text">{autostartError}</p>
  {/if}
  <div class="row">
    <div>
      <h3>Подключаться при запуске</h3>
      <p class="muted">К выбранному серверу, в выбранном режиме — как кнопка «Подключить».</p>
    </div>
    <label class="switch">
      <input type="checkbox" role="switch" bind:checked={connectOnStart} />
      <span aria-hidden="true"></span>
      <span class="sr">Подключаться при запуске</span>
    </label>
  </div>
  <div class="row">
    <div>
      <h3>Уведомления Windows</h3>
      <p class="muted">
        Пока окно закрыто: сервер заменён, соединение прервано, zapret перестал справляться. Без звука. Когда окно
        открыто, сообщения видны в нём.
      </p>
    </div>
    <label class="switch">
      <input type="checkbox" role="switch" bind:checked={notifications} />
      <span aria-hidden="true"></span>
      <span class="sr">Уведомления Windows</span>
    </label>
  </div>
</section>

<section class="card block">
  <h2>DNS</h2>
  <div class="field">
    <label for="dns-local">
      <span>Для сайтов, которые открываются напрямую</span>
      <span class="caption">Обычный DNS. Российский резолвер отдаёт ближайшие узлы российских CDN.</span>
    </label>
    <select id="dns-local" value={dns.local} onchange={(e) => (dns = { ...dns, local: e.currentTarget.value })}>
      {#each resolvers as r (r.id)}
        <option value={r.id}>{r.title} · {r.udp}</option>
      {/each}
    </select>
  </div>
  <div class="field">
    <label for="dns-remote">
      <span>Для всего остального</span>
      <span class="caption">Зашифрованный DoH внутри туннеля: провайдер не видит, какие сайты вы открываете.</span>
    </label>
    <select id="dns-remote" value={dns.remote} onchange={(e) => (dns = { ...dns, remote: e.currentTarget.value })}>
      {#each tunnelResolvers as r (r.id)}
        <option value={r.id}>{r.title} (DoH)</option>
      {/each}
    </select>
  </div>
  <p class="caption">Изменения применятся при следующем подключении. Подсказку даст «Проверка DNS» в разделе «Проверка».</p>
</section>

<section class="card block">
  <h2>Сети</h2>
  <p class="muted intro">
    KVT узнаёт сеть по роутеру и может сам включать VPN дома, выключать его в доверенной сети или менять режим.
  </p>

  <div class="here">
    <Icon name="wifi" size={16} />
    {#if here.network}
      <span>Сейчас: <strong>{here.network.label}</strong> <span class="caption">· {kinds[here.network.kind]}</span></span>
      {#if !known}
        <button class="btn" onclick={remember}>Запомнить эту сеть</button>
      {/if}
    {:else}
      <span class="muted">Нет подключения к сети</span>
    {/if}
  </div>

  {#if networks.length > 0}
    <ul class="profiles">
      {#each networks as p (p.key)}
        <li class:current={p.key === here.network?.key}>
          <input
            class="name"
            aria-label="Название сети"
            value={p.name}
            maxlength="40"
            onchange={(e) => update(p.key, { name: e.currentTarget.value.trim() || p.name })}
          />
          <select
            aria-label="При подключении к сети"
            value={p.onJoin}
            onchange={(e) => update(p.key, { onJoin: e.currentTarget.value as OnJoin })}
          >
            {#each onJoinOptions as o (o.id)}
              <option value={o.id}>{o.label}</option>
            {/each}
          </select>
          <select
            aria-label="Режим в этой сети"
            value={p.mode ?? ""}
            onchange={(e) => update(p.key, { mode: (e.currentTarget.value || null) as Mode | null })}
          >
            {#each modeOptions as o (o.id)}
              <option value={o.id}>{o.label}</option>
            {/each}
          </select>
          <button class="btn forget" aria-label="Забыть сеть «{p.name}»" onclick={() => forget(p.key)}>Забыть</button>
        </li>
      {/each}
    </ul>
  {/if}
</section>

<section class="card block">
  <h2>О программе</h2>
  {#if about}
    <dl class="versions">
      <dt>KVT</dt>
      <dd>{about.version}</dd>
      {#each Object.entries(about.cores) as [id, version] (id)}
        <dt>{coreTitles[id] ?? id}</dt>
        <dd>{version}</dd>
      {/each}
      {#if flowseal}
        <dt>zapret (Flowseal)</dt>
        <dd>{flowseal}</dd>
      {/if}
    </dl>
  {/if}
  <p class="muted">
    KVT — свободная программа под лицензией GPL-3.0. В составе: Xray (MPL-2.0), sing-box (GPL-3.0), Wintun, WinDivert
    (LGPL-3.0), zapret и Flowseal (MIT), flag-icons (MIT), Tauri (MIT / Apache-2.0). Новые версии — на странице
    загрузки: KVT сам ничего не скачивает.
  </p>
  <div class="links">
    <button class="btn" onclick={onrestartonboarding}>Подсказки первого запуска</button>
    <button class="btn" onclick={() => void open("releases")}>Страница загрузки</button>
    <button class="btn" onclick={() => void open("source")}>Исходники</button>
    {#if about?.licenses}
      <button class="btn" onclick={() => void open("licenses")}>Тексты лицензий</button>
    {/if}
  </div>
  {#if linkError}
    <p class="caption error-text">{linkError}</p>
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

  .row p,
  .intro {
    margin: var(--space-1) 0 0;
    max-width: var(--measure);
  }

  .caption {
    margin: 0;
  }

  .field {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-4);
  }

  .field label {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .field select {
    flex: none;
    min-width: 220px;
  }

  .here {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    min-height: 32px;
  }

  .here .btn {
    margin-left: auto;
  }

  /* Высота строки как у h2: переключатель справа встаёт по центру заголовка. */
  h3 {
    font-size: 14px;
    line-height: 22px;
  }

  .error-text {
    color: var(--danger);
  }

  .versions {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: var(--space-1) var(--space-4);
    margin: 0;
    font-variant-numeric: tabular-nums;
  }

  .versions dt {
    color: var(--text-2);
  }

  .versions dd {
    margin: 0;
    user-select: text;
  }

  .links {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
  }

  .profiles {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    margin: 0;
    padding: 0;
    list-style: none;
  }

  .profiles li {
    display: grid;
    grid-template-columns: minmax(120px, 1fr) auto auto auto;
    align-items: center;
    gap: var(--space-2);
    padding: var(--space-2);
    border: 1px solid var(--stroke);
    border-radius: var(--radius-s);
  }

  .profiles li.current {
    border-color: var(--accent);
  }

  .name {
    min-width: 0;
    height: 30px;
    padding: 0 var(--space-2);
    border: 1px solid transparent;
    border-radius: var(--radius-s);
    background: transparent;
    user-select: text;
  }

  .name:hover,
  .name:focus {
    border-color: var(--stroke);
    background: var(--surface);
  }

  @media (max-width: 720px) {
    .field {
      flex-direction: column;
      align-items: stretch;
    }

    .profiles li {
      grid-template-columns: 1fr;
    }
  }
</style>
