<script lang="ts">
  import { fade } from "svelte/transition";
  import Banner from "./lib/Banner.svelte";
  import NavRail, { type Page } from "./lib/NavRail.svelte";
  import StatusCard from "./lib/StatusCard.svelte";
  import ServerList from "./lib/ServerList.svelte";
  import AddSubscription from "./lib/AddSubscription.svelte";
  import Settings from "./lib/Settings.svelte";
  import Routing from "./lib/Routing.svelte";
  import Subscriptions from "./lib/Subscriptions.svelte";
  import Diagnostics from "./lib/Diagnostics.svelte";
  import NetJournal from "./lib/NetJournal.svelte";
  import ZapretCard from "./lib/ZapretCard.svelte";
  import ZapretPage from "./lib/ZapretPage.svelte";
  import { startAutoselect } from "./lib/zapretStore.svelte";
  import {
    addSubscription,
    connect,
    disconnect,
    quickCheck,
    fullCheck,
    serviceStatus,
    setChoice,
    snapshot,
    onSubscriptionsChanged,
    onChoiceChanged,
    onWatchdog,
    onZapretAuto,
    onTunnelState,
    takeNotices,
    tunnelState,
    refreshSubscription,
    defaultRouting,
    defaultDns,
    defaultZapret,
    type ZapretChoice,
    type Choice,
    type DnsChoice,
    type Fix,
    type Group,
    type NetworkProfile,
    type Outcome,
    type WatchdogEvent,
    type RoutingSettings,
    type ServiceStatus,
    type Mode,
    type QuickResult,
  } from "./lib/api";

  let page = $state<Page>("home");
  let mode = $state<Mode>("vpn");
  /** Все подписки и ручные ключи — группами в одном списке. */
  let groups = $state<Group[]>([]);
  /** Ключ выбранного сервера. */
  let selected = $state<string | null>(null);
  let busy = $state(false);
  /** Ошибка на главной; `why` — ошибка подключения, к ней уместно «Почему не работает?». */
  let error = $state<{ text: string; why: boolean } | null>(null);
  /** Ошибка добавления подписки — показывается рядом с формой, а не на главной. */
  let addError = $state<string | null>(null);
  let mainEl = $state<HTMLElement | null>(null);

  // У каждой вкладки своя прокрутка: новая открывается сверху.
  $effect(() => {
    void page;
    mainEl?.scrollTo({ top: 0 });
  });
  let results = $state<Record<string, QuickResult>>({});
  let checking = $state<string | null>(null);
  let outcomes = $state<Record<string, Outcome>>({});
  let fullChecking = $state<string | null>(null);
  let refreshing = $state<string | null>(null);
  /** Открыта панель добавления (кнопка «+»). */
  let adding = $state(false);

  let killSwitch = $state(false);
  let routing = $state<RoutingSettings>(defaultRouting());
  let dns = $state<DnsChoice>(defaultDns());
  let autoSwitch = $state(true);
  let networks = $state<NetworkProfile[]>([]);
  let zapret = $state<ZapretChoice>(defaultZapret());
  let restored = $state(false);

  const allServers = $derived(groups.flatMap((g) => g.servers));
  const server = $derived(allServers.find((s) => s.key === selected) ?? null);
  const firstKey = () => groups.find((g) => g.servers.length > 0)?.servers[0]?.key ?? null;

  function applyChoice(c: Choice) {
    selected = c.server ?? firstKey();
    mode = c.mode ?? "vpn";
    killSwitch = c.killSwitch;
    routing = { ...defaultRouting(), ...c.routing };
    dns = { ...defaultDns(), ...c.dns };
    autoSwitch = c.autoSwitch ?? true;
    networks = c.networks ?? [];
    zapret = { ...defaultZapret(), ...c.zapret };
  }

  /** Rust хранит выбор целиком: отправляем все поля, иначе остальные сбросятся. */
  function currentChoice(): Choice {
    return {
      server: selected,
      mode,
      killSwitch,
      routing: $state.snapshot(routing),
      dns: $state.snapshot(dns),
      autoSwitch,
      networks: $state.snapshot(networks),
      zapret: $state.snapshot(zapret),
    };
  }

  // Окно могло быть закрыто (WebView выгружен) — восстанавливаем состояние из Rust.
  $effect(() => {
    void snapshot()
      .then((snap) => {
        groups = snap.groups;
        if (snap.choice) applyChoice(snap.choice);
        else selected = firstKey();
      })
      .finally(() => (restored = true));
  });

  // Сервер или режим сменились не из окна: автопереключение или профиль сети.
  $effect(() =>
    onChoiceChanged(() => {
      void snapshot().then((snap) => {
        groups = snap.groups;
        if (!snap.choice) return;
        applyChoice(snap.choice);
        // Автопереключение уже подключилось к новому серверу, профиль сети сам
        // переподключил с новым режимом, автоподбор zapret сам перезапустил службу
        // с новой стратегией — второй раз из окна не нужно.
        if (connectedWith) connectedWith = { server: snap.choice.server, mode, zapret: zapretKey() };
      });
    }),
  );

  async function reloadGroups() {
    const snap = await snapshot();
    groups = snap.groups;
    // Выбранный сервер исчез (подписку удалили или провайдер убрал сервер). Если были
    // подключены к нему, Rust уже отключил VPN и сообщил об этом, — к первому
    // серверу другой подписки не переподключаемся.
    if (!groups.some((g) => g.servers.some((s) => s.key === selected))) {
      connectedWith = null;
      status = await serviceStatus().catch(() => null);
      selected = firstKey();
    }
  }

  // Подписка добавлена, обновилась в фоне или удалена.
  $effect(() => onSubscriptionsChanged(() => void reloadGroups()));

  let notice = $state<string | null>(null);
  /** Сеть просит войти: вместо «Понятно» — кнопка отключить VPN. */
  let captive = $state(false);
  /** Сообщения, которые появились до открытия окна (например, о повреждённых настройках). */
  let startupNotices = $state<string[]>([]);
  $effect(() => {
    void takeNotices().then((n) => (startupNotices = [...startupNotices, ...n]));
  });

  /** Идут ли данные через туннель: null — ещё не проверяли. */
  let tunnelOk = $state<boolean | null>(null);
  $effect(() => {
    void tunnelState().then((t) => (tunnelOk = t));
    return onTunnelState((t) => (tunnelOk = t));
  });

  function watchdogText(e: WatchdogEvent): string {
    switch (e.kind) {
      case "captive_portal":
        return "Сеть просит войти (как Wi-Fi в гостинице или кафе), а VPN не даёт открыть страницу входа. Отключите VPN, войдите в сеть и подключитесь снова.";
      case "server_removed":
        return `Сервер «${e.server}» больше не в подписках — VPN отключён. Выберите другой сервер и подключитесь.`;
      case "switched":
        return `Через «${e.from}» перестали идти данные — KVT переключился на «${e.to}».`;
      case "no_network":
        return "Пропала сеть. VPN снова заработает, когда она появится.";
      case "no_alternative":
        return `Через «${e.server}» перестали идти данные, а рабочей замены в подписках нет.`;
      case "gave_up":
        return "Серверы слишком часто перестают работать — автопереключение приостановлено на полчаса.";
    }
  }

  $effect(() =>
    onWatchdog((e) => {
      notice = watchdogText(e);
      captive = e.kind === "captive_portal";
    }),
  );

  // Автопроверка zapret: сама подобрала стратегию или просит внимания.
  $effect(() =>
    onZapretAuto((e) => {
      notice =
        e.kind === "picked"
          ? `zapret перестал справляться — KVT подобрал стратегию ${e.title} (${e.passed} из ${e.max}).`
          : `zapret справляется хуже: ${e.passed} из ${e.max} проверок. Откройте вкладку Zapret → «Почему не работает?».`;
    }),
  );

  // «Почему не работает?» с главной: открыть раздел «Проверка» и сразу запустить.
  let autoDiagnose = $state(false);
  function askWhy() {
    autoDiagnose = true;
    page = "diagnostics";
  }

  async function onfix(fix: Fix) {
    switch (fix.kind) {
      case "connect":
        page = "home";
        await onconnect();
        break;
      case "disconnect":
        await ondisconnect();
        break;
      case "switch_server":
        selected = fix.key;
        page = "home";
        await onconnect();
        break;
      case "refresh_subscription": {
        // На главной видно и вращение «Обновить», и ошибку, если провайдер не ответил.
        page = "home";
        const group = groups.find((g) => g.servers.some((s) => s.key === selected));
        if (group?.byUrl) await refresh(group.id);
        break;
      }
      case "add_subscription":
        page = "home";
        adding = true;
        break;
      case "zapret_autoselect":
        page = "zapret";
        void startAutoselect();
        break;
      case "open_dns_check":
        break;
    }
  }

  // Выбор сервера, режима и kill switch нужен Rust-части: по нему подключается трей.
  $effect(() => {
    const choice = currentChoice();
    if (restored) void setChoice(choice);
  });

  const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

  function failed(e: unknown, why = false) {
    error = { text: message(e), why };
  }

  async function check(group: string) {
    checking = group;
    try {
      results = { ...results, ...(await quickCheck(group)) };
    } catch (e) {
      failed(e);
    } finally {
      checking = null;
    }
  }

  async function runFullCheck(group: string) {
    fullChecking = group;
    error = null;
    const keys = new Set(groups.find((g) => g.id === group)?.servers.map((s) => s.key));
    outcomes = Object.fromEntries(Object.entries(outcomes).filter(([k]) => !keys.has(k)));
    try {
      await fullCheck(group, (key, o) => {
        outcomes[key] = o;
      });
    } catch (e) {
      failed(e);
    } finally {
      fullChecking = null;
    }
  }

  async function refresh(group: string) {
    refreshing = group;
    error = null;
    try {
      await refreshSubscription(group);
      await reloadGroups();
    } catch (e) {
      failed(e);
    } finally {
      refreshing = null;
    }
  }

  function closeAdd() {
    if (busy) return;
    adding = false;
    addError = null;
  }

  async function add(body: string) {
    busy = true;
    addError = null;
    try {
      const result = await addSubscription(body);
      if (result.servers === 0) {
        addError = "В подписке не нашлось ни одного сервера.";
        return;
      }
      await reloadGroups();
      if (result.first) selected = result.first;
      adding = false;
      page = "home";
      void check(result.group);
    } catch (e) {
      addError = message(e);
    } finally {
      busy = false;
    }
  }

  let status = $state<ServiceStatus | null>(null);
  /** Работает VPN или только zapret. */
  const active = $derived(status?.state === "connected" || status?.state === "zapret");
  /** Настройки zapret, с которыми запущена служба (стратегия, фильтр). */
  const zapretKey = () => JSON.stringify($state.snapshot(zapret));
  /** С каким сервером, режимом и настройками zapret сейчас подключены. */
  let connectedWith = $state<{ server: string | null; mode: Mode; zapret: string } | null>(null);

  async function onconnect() {
    busy = true;
    error = null;
    const target = { server: selected, mode, zapret: zapretKey() };
    try {
      await setChoice(currentChoice());
      status = await connect();
    } catch (e) {
      failed(e, true);
      status = await serviceStatus().catch(() => null);
    } finally {
      // Даже при ошибке запоминаем попытку: иначе переподключение пошло бы по кругу.
      connectedWith = status?.state === "connected" || status?.state === "zapret" ? target : null;
      busy = false;
    }
  }

  async function ondisconnect() {
    busy = true;
    try {
      status = await disconnect();
      connectedWith = null;
    } catch (e) {
      failed(e, true);
    } finally {
      busy = false;
    }
  }

  // Другой сервер, режим или стратегия zapret при подключении — переподключаемся сразу, как в Happ.
  $effect(() => {
    if (!restored || busy || !active || !connectedWith) return;
    const zapretChanged = mode !== "vpn" && zapretKey() !== connectedWith.zapret;
    const serverChanged = mode !== "zapret" && selected !== connectedWith.server;
    if (!serverChanged && !zapretChanged && mode === connectedWith.mode) return;
    if (selected === null && mode !== "zapret") return;
    void onconnect();
  });

  // Локальный pipe — дешёвый запрос; так видно, если ядро упало само.
  $effect(() => {
    const refreshStatus = async () => {
      if (busy) return;
      const next = await serviceStatus().catch(() => null);
      if (next?.state === "failed" && status?.state === "connected") {
        error = { text: `Соединение прервано: ${next.reason}`, why: true };
      }
      const nextActive = next?.state === "connected" || next?.state === "zapret";
      if (!nextActive) connectedWith = null;
      // Подключились из трея или профиля сети — считаем, что с текущим выбором.
      else if (!connectedWith && restored) connectedWith = { server: selected, mode, zapret: zapretKey() };
      status = next;
    };
    void refreshStatus();
    const timer = setInterval(refreshStatus, 3000);
    return () => clearInterval(timer);
  });
</script>

<div class="shell">
  <NavRail bind:current={page} />

  <main bind:this={mainEl}>
    <!-- Новая вкладка проявляется с лёгким подъёмом; старая уходит сразу, без задержки. -->
    {#key page}
    <div class="page">
    {#if page === "home"}
      <h1>Главная</h1>

      <StatusCard {server} bind:mode {busy} {status} {tunnelOk} {onconnect} {ondisconnect} onwhy={askWhy} />

      {#each startupNotices as text, i (i)}
        <Banner>
          {text}
          {#snippet action()}
            <button class="btn" onclick={() => (startupNotices = startupNotices.filter((_, j) => j !== i))}>Понятно</button>
          {/snippet}
        </Banner>
      {/each}

      {#if mode !== "vpn"}
        <ZapretCard bind:zapret vpnConnected={status?.state === "connected"} onopen={() => (page = "zapret")} />
      {/if}

      {#if error}
        <Banner>
          {error.text}
          {#snippet action()}
            {#if error?.why}
              <button class="btn" onclick={askWhy}>Почему не работает?</button>
            {/if}
            <button class="btn" onclick={() => (error = null)}>{error?.why ? "Скрыть" : "Понятно"}</button>
          {/snippet}
        </Banner>
      {/if}
      {#if notice}
        <Banner tone={captive ? "warn" : "info"}>
          {notice}
          {#snippet action()}
            {#if captive && active}
              <button
                class="btn btn-primary"
                onclick={async () => {
                  notice = null;
                  captive = false;
                  await ondisconnect();
                }}>Отключить VPN</button
              >
            {/if}
            <button
              class="btn"
              onclick={() => {
                notice = null;
                captive = false;
              }}>Понятно</button
            >
          {/snippet}
        </Banner>
      {/if}

      {#if allServers.length > 0}
        <ServerList
          {groups}
          bind:selected
          {results}
          {checking}
          oncheck={check}
          {outcomes}
          {fullChecking}
          fullCheckBlocked={status?.state === "connected"
            ? "Отключите VPN: полная проверка идёт напрямую, иначе туннель исказит результат"
            : null}
          onfullcheck={runFullCheck}
          {refreshing}
          onrefresh={refresh}
          onadd={() => (adding = true)}
        />
      {:else}
        <AddSubscription onadd={add} {busy} />
        {#if addError && !adding}
          <Banner>{addError}</Banner>
        {/if}
      {/if}
    {:else if page === "subscriptions"}
      <h1>Подписки</h1>
      <Subscriptions onadd={() => (adding = true)} />
    {:else if page === "routing"}
      <h1>Маршрутизация</h1>
      <Routing bind:routing connected={status?.state === "connected"} />
    {:else if page === "zapret"}
      <h1>Zapret</h1>
      <ZapretPage bind:zapret bind:mode {status} {busy} {onconnect} />
    {:else if page === "diagnostics"}
      <h1>Проверка</h1>
      <Diagnostics
        connected={status?.state === "connected"}
        bind:dns
        {onfix}
        autorun={autoDiagnose}
        onautorun={() => (autoDiagnose = false)}
      />
    {:else if page === "settings"}
      <h1>Настройки</h1>
      <Settings bind:killSwitch bind:autoSwitch bind:dns bind:networks />
    {:else}
      <h1>Журнал</h1>
      <NetJournal />
    {/if}
    </div>
    {/key}
  </main>
</div>

{#if adding}
  <!-- Панель добавления поверх текущего экрана: список остаётся на месте. -->
  <div
    class="overlay"
    role="dialog"
    aria-modal="true"
    aria-labelledby="add-title"
    tabindex="-1"
    transition:fade={{ duration: 150 }}
    onclick={(e) => {
      if (e.target === e.currentTarget) closeAdd();
    }}
    onkeydown={(e) => {
      if (e.key === "Escape") closeAdd();
    }}
  >
    <AddSubscription onadd={add} {busy} oncancel={closeAdd} />
    {#if addError}
      <div class="overlay-error"><Banner>{addError}</Banner></div>
    {/if}
  </div>
{/if}

<style>
  .shell {
    display: flex;
    height: 100%;
  }

  main {
    /* Закреплённые панели (список серверов) прилипают к самому верху окна. */
    --page-pad-top: var(--space-6);
    flex: 1;
    min-width: 0;
    padding: var(--page-pad-top) var(--space-8) var(--space-6);
    overflow-y: auto;
    scrollbar-gutter: stable;
  }

  .page {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
    max-width: 880px;
    /* backwards: после анимации на странице не остаётся transform — закреплённая
       панель списка серверов работает как обычно. */
    animation: kvt-rise var(--dur) var(--ease) backwards;
  }

  /* Карточки не сжимаются под высоту окна — страница прокручивается целиком. */
  .page > :global(*) {
    flex-shrink: 0;
  }

  .overlay {
    position: fixed;
    inset: 0;
    z-index: 10;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: var(--space-3);
    padding: var(--space-4);
    background: rgb(0 0 0 / 0.45);
  }

  .overlay-error {
    width: min(560px, calc(100vw - 32px));
  }
  @media (max-width: 720px) {
    main {
      --page-pad-top: var(--space-4);
      padding: var(--space-4);
    }
  }
</style>
