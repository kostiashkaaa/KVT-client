<script lang="ts">
  import NavRail, { type Page } from "./lib/NavRail.svelte";
  import StatusCard from "./lib/StatusCard.svelte";
  import ServerList from "./lib/ServerList.svelte";
  import AddSubscription from "./lib/AddSubscription.svelte";
  import Settings from "./lib/Settings.svelte";
  import Routing from "./lib/Routing.svelte";
  import Subscriptions from "./lib/Subscriptions.svelte";
  import {
    addSubscription,
    connect,
    disconnect,
    quickCheck,
    fullCheck,
    type Outcome,
    serviceStatus,
    setChoice,
    snapshot,
    onSubscriptionsChanged,
    defaultRouting,
    type RoutingSettings,
    type ServiceStatus,
    type Mode,
    type ParsedSubscription,
    type QuickResult,
  } from "./lib/api";

  let page = $state<Page>("home");
  let mode = $state<Mode>("vpn");
  let parsed = $state<ParsedSubscription | null>(null);
  let selected = $state<number | null>(null);
  let busy = $state(false);
  let error = $state<string | null>(null);
  let results = $state<QuickResult[] | null>(null);
  let checking = $state(false);
  let outcomes = $state<(Outcome | null)[] | null>(null);
  let fullChecking = $state(false);

  async function runFullCheck() {
    if (!parsed) return;
    fullChecking = true;
    error = null;
    outcomes = parsed.servers.map(() => null);
    try {
      await fullCheck(parsed.servers.length, (i, o) => {
        if (outcomes) outcomes[i] = o;
      });
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      fullChecking = false;
    }
  }
  let killSwitch = $state(false);
  let routing = $state<RoutingSettings>(defaultRouting());
  let restored = $state(false);

  // Окно могло быть закрыто (WebView выгружен) — восстанавливаем состояние из Rust.
  $effect(() => {
    void snapshot()
      .then((snap) => {
        if (snap?.subscription) parsed = snap.subscription;
        if (snap?.choice) {
          selected = snap.choice.serverIndex ?? (snap.subscription ? 0 : null);
          mode = snap.choice.mode ?? "vpn";
          killSwitch = snap.choice.killSwitch;
          routing = { ...defaultRouting(), ...snap.choice.routing };
        }
      })
      .finally(() => (restored = true));
  });

  // Подписка обновилась в фоне, сменилась основная или удалена — берём актуальную из Rust.
  $effect(() =>
    onSubscriptionsChanged(() => {
      void snapshot().then((snap) => {
        const previous = parsed?.id;
        parsed = snap?.subscription ?? null;
        if (parsed?.id !== previous) {
          selected = parsed && parsed.servers.length > 0 ? 0 : null;
          results = null;
          outcomes = null;
        }
      });
    }),
  );

  // Выбор сервера, режима и kill switch нужен Rust-части: по нему подключается трей.
  $effect(() => {
    const choice = { serverIndex: selected, mode, killSwitch, routing: $state.snapshot(routing) };
    if (restored) void setChoice(choice);
  });

  async function check() {
    if (!parsed) return;
    checking = true;
    try {
      results = await quickCheck(parsed.servers.length);
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      checking = false;
    }
  }

  const server = $derived(selected !== null ? (parsed?.servers[selected] ?? null) : null);

  async function add(body: string) {
    busy = true;
    error = null;
    try {
      const result = await addSubscription(body);
      if (result.servers.length === 0) {
        error = "В подписке не нашлось ни одного сервера.";
        return;
      }
      parsed = result;
      selected = 0;
      results = null;
      outcomes = null;
      void check();
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  let status = $state<ServiceStatus | null>(null);

  async function onconnect() {
    busy = true;
    error = null;
    try {
      await setChoice({ serverIndex: selected, mode, killSwitch, routing: $state.snapshot(routing) });
      status = await connect();
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
      status = await serviceStatus().catch(() => null);
    } finally {
      busy = false;
    }
  }

  async function ondisconnect() {
    busy = true;
    try {
      status = await disconnect();
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  // Локальный pipe — дешёвый запрос; так видно, если ядро упало само.
  $effect(() => {
    const refresh = async () => {
      if (busy) return;
      const next = await serviceStatus().catch(() => null);
      if (next?.state === "failed" && status?.state === "connected") error = `Соединение прервано: ${next.reason}`;
      status = next;
    };
    void refresh();
    const timer = setInterval(refresh, 3000);
    return () => clearInterval(timer);
  });
</script>

<div class="shell">
  <NavRail bind:current={page} />

  <main>
    {#if page === "home"}
      <h1>Главная</h1>

      <StatusCard {server} bind:mode {busy} {status} {onconnect} {ondisconnect} />

      {#if error}
        <div class="banner" role="alert">{error}</div>
      {/if}

      {#if parsed && parsed.servers.length > 0}
        <ServerList
          title={parsed.meta?.title ?? "Подписка"}
          meta={parsed.meta}
          servers={parsed.servers}
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
        />
        {#if parsed.meta?.announce}
          <p class="announce">{parsed.meta.announce}</p>
        {/if}
        {#if parsed.info.length > 0}
          <ul class="info">
            {#each parsed.info as line, i (i)}
              <li class="caption">{line}</li>
            {/each}
          </ul>
        {/if}
        {#if parsed.errors.length > 0}
          <p class="caption">Пропущено строк с ошибками: {parsed.errors.length}</p>
        {/if}
      {:else}
        <AddSubscription onadd={add} {busy} />
      {/if}
    {:else if page === "subscriptions"}
      <h1>Подписки</h1>
      <Subscriptions onadd={add} {busy} />
    {:else if page === "routing"}
      <h1>Маршрутизация</h1>
      <Routing bind:routing connected={status?.state === "connected"} />
    {:else if page === "settings"}
      <h1>Настройки</h1>
      <Settings bind:killSwitch connected={status?.state === "connected"} />
    {:else}
      <h1>
        Журнал
      </h1>
      <p class="muted">Раздел появится на следующих этапах.</p>
    {/if}
  </main>
</div>

<style>
  .shell {
    display: flex;
    height: 100%;
  }

  main {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
    max-width: 880px;
    padding: var(--space-6) var(--space-8);
    overflow-y: auto;
  }

  /* Карточки не сжимаются под высоту окна — страница прокручивается целиком. */
  main > :global(*) {
    flex-shrink: 0;
  }

  .banner {
    padding: var(--space-3) var(--space-4);
    border: 1px solid var(--stroke);
    border-left: 3px solid var(--warn);
    border-radius: var(--radius-s);
    background: var(--warn-subtle);
  }

  .info {
    margin: 0;
    padding: 0 var(--space-5);
  }

  /* Текст провайдера выводится только как текст, без разметки. */
  .announce {
    margin: 0;
    padding: var(--space-3) var(--space-4);
    border-radius: var(--radius-s);
    background: var(--accent-subtle);
    white-space: pre-line;
  }

  @media (max-width: 720px) {
    main {
      padding: var(--space-4);
    }
  }
</style>
