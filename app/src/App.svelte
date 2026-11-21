<script lang="ts">
  import { t } from "./lib/i18n";
  import { fade } from "svelte/transition";
  import Banner from "./lib/Banner.svelte";
  import NoticeStack from "./lib/NoticeStack.svelte";
  import { push as pushNotice } from "./lib/notices.svelte";
  import { update, skipUpdate, watchUpdates } from "./lib/update.svelte";
  import NavRail, { type Page } from "./lib/NavRail.svelte";
  import StatusCard from "./lib/StatusCard.svelte";
  import Onboarding from "./lib/Onboarding.svelte";
  import ServerList from "./lib/ServerList.svelte";
  import AddSubscription from "./lib/AddSubscription.svelte";
  import Settings from "./lib/Settings.svelte";
  import Routing from "./lib/Routing.svelte";
  import Subscriptions from "./lib/Subscriptions.svelte";
  import Diagnostics from "./lib/Diagnostics.svelte";
  import NetJournal from "./lib/NetJournal.svelte";
  import ZapretCard from "./lib/ZapretCard.svelte";
  import ZapretPage from "./lib/ZapretPage.svelte";
  import PickmeSky from "./lib/PickmeSky.svelte";
  import { theme } from "./lib/theme.svelte";
  import { startAutoselect } from "./lib/zapretStore.svelte";
  import AddOverlay from "./lib/AddOverlay.svelte";
  import { watchEventNotices, watchStartupNotices } from "./lib/appNotices.svelte";
  import { choice, watchChoicePersisted } from "./lib/choiceStore.svelte";
  import {
    conn,
    connect,
    disconnect,
    initConnection,
    isActive,
    watchReconnect,
    watchStatus,
    watchTunnel,
  } from "./lib/connectionStore.svelte";
  import {
    checks,
    hasServers,
    initSubscriptions,
    loadSnapshot,
    reloadGroups,
    subs,
    watchExternalChoice,
    watchSubscriptions,
  } from "./lib/subscriptionsStore.svelte";
  import {
    addSubscription,
    openLink,
    onNavigate,
    takePage,
    type Fix,
    type TrayPage,
  } from "./lib/api";

  let page = $state<Page>(restoredPage());

  /** Страница до перезагрузки окна при смене языка (одноразово). */
  function restoredPage(): Page {
    try {
      const saved = sessionStorage.getItem("kvt.page");
      sessionStorage.removeItem("kvt.page");
      if (saved === "settings") return "settings";
    } catch {
      // Хранилище недоступно — главная.
    }
    return "home";
  }

  let mainEl = $state<HTMLElement | null>(null);

  // У каждой вкладки своя прокрутка: новая открывается сверху.
  $effect(() => {
    void page;
    mainEl?.scrollTo({ top: 0 });
  });

  /** Открыта панель добавления (кнопка «+»). */
  let adding = $state(false);
  /** Ошибка добавления подписки — показывается рядом с формой, а не на главной. */
  let addError = $state<string | null>(null);

  const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

  /** Ошибка действия: одна на окно (новая заменяет прежнюю), висит до «Понятно». */
  function failed(e: unknown, why = false) {
    showError(message(e), why);
  }

  function showError(text: string, why: boolean) {
    pushNotice({
      key: "error",
      text,
      actions: why ? [{ label: t("Почему не работает?", "Why isn't it working?"), run: askWhy }] : [],
      closeLabel: why ? t("Скрыть", "Hide") : t("Понятно", "Got it"),
    });
  }

  // Сторы: выбор — choiceStore, подключение — connectionStore, подписки — subscriptionsStore.
  // Ошибки и «Почему не работает?» показывает окно: сторам передаются обработчики.
  initConnection({ failed, showError });
  initSubscriptions({ failed });

  // Окно могло быть закрыто (WebView выгружен) — восстанавливаем состояние из Rust.
  void loadSnapshot();

  // Выбор хранится в Rust, опрос службы и переподключение — connectionStore; подписки и
  // выбор, изменённый не из окна, — subscriptionsStore. Эффекты ставятся здесь: им нужен
  // контекст окна.
  watchChoicePersisted();
  watchStatus();
  watchTunnel();
  watchReconnect();
  watchExternalChoice();
  watchSubscriptions();

  // Сообщения, которые появились до открытия окна (например, о повреждённых
  // настройках) или пришли из трея, когда уведомления Windows выключены.
  watchStartupNotices();

  // Новая версия KVT: плашка на главной и точка у «Настроек» (update.svelte.ts).
  $effect(() => watchUpdates());

  const active = $derived(isActive(conn.status));

  // События службы (замена сервера, пропавшая сеть, вход в сеть) и автопроверка zapret.
  watchEventNotices({ active: () => active, ondisconnect: () => disconnect(), openZapret: () => void (page = "zapret") });

  // «Почему не работает?» с главной: открыть раздел «Проверка» и сразу запустить.
  let autoDiagnose = $state(false);
  function askWhy() {
    autoDiagnose = true;
    page = "diagnostics";
  }

  // Пункты трея «Почему не работает?», «Журнал», «Подобрать заново…» и т. п.
  function openFromTray(target: TrayPage) {
    if (target === "why") askWhy();
    else if (target === "add") {
      page = "home";
      adding = true;
    } else page = target;
  }
  $effect(() => {
    void takePage().then((p) => p && openFromTray(p));
    return onNavigate((p) => {
      // Открытое окно получает событие сразу — отложенная страница больше не нужна.
      void takePage();
      openFromTray(p);
    });
  });

  async function onfix(fix: Fix) {
    switch (fix.kind) {
      case "connect":
        page = "home";
        await connect();
        break;
      case "disconnect":
        await disconnect();
        break;
      case "switch_server":
        choice.selected = fix.key;
        page = "home";
        await connect();
        break;
      case "refresh_subscription": {
        // На главной видно и вращение «Обновить», и ошибку, если провайдер не ответил.
        page = "home";
        const group = subs.groups.find((g) => g.servers.some((s) => s.key === choice.selected));
        if (group?.byUrl) await checks.refresh(group.id);
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

  function closeAdd() {
    if (conn.busy) return;
    adding = false;
    addError = null;
  }

  async function add(body: string) {
    // Общий флаг «окно выполняет действие», как у подключения: пока добавляется
    // подписка, опрос и переподключение не мешают.
    conn.busy = true;
    addError = null;
    try {
      const result = await addSubscription(body);
      if (result.servers === 0 || result.group === null) {
        addError = result.failed[0] ?? t("В подписке не нашлось ни одного сервера.", "No servers found in the subscription.");
        return;
      }
      // Добавилась только часть вставки — сказать, что именно не вышло.
      if (result.failed.length > 0) {
        pushNotice({
          text: t(`Добавлено не всё. ${result.failed.join(" ")}`, `Not everything was added. ${result.failed.join(" ")}`),
          tone: "warn",
          key: "add-partial",
        });
      }
      await reloadGroups();
      // При работающем VPN выбор не трогаем: иначе KVT сразу переподключился бы
      // к первому серверу новой подписки.
      if (result.first && (!active || choice.selected === null)) choice.selected = result.first;
      adding = false;
      page = "home";
      void checks.check(result.group);
    } catch (e) {
      addError = message(e);
    } finally {
      conn.busy = false;
    }
  }
</script>

{#if theme.pickme}
  <PickmeSky />
{/if}

<div class="shell">
  <NavRail bind:current={page} />

  <main bind:this={mainEl}>
    <NoticeStack />
    <!-- Новая вкладка проявляется с лёгким подъёмом; старая уходит сразу, без задержки. -->
    {#key page}
    <div class="page" class:home={page === "home"}>
    {#if page === "home"}
      <h1>{t("Главная", "Home")}</h1>

      {#if choice.restored && !choice.onboarded}
        <Onboarding
          onadd={() => (adding = true)}
          onmigrate={() => (page = "subscriptions")}
        />
      {/if}

      {#if update.banner}
        <div transition:fade={{ duration: 150 }}>
          <Banner tone="info">
            {t(`Вышла KVT ${update.version}. Скачайте её на странице загрузки — настройки и подписки сохранятся.`, `KVT ${update.version} is out. Download it from the download page — your settings and subscriptions will be kept.`)}
            {#snippet action()}
              <button class="btn btn-primary" onclick={() => void openLink("latest")}>{t("Скачать", "Download")}</button>
              <button class="btn" onclick={skipUpdate}>{t("Позже", "Later")}</button>
            {/snippet}
          </Banner>
        </div>
      {/if}

      <!-- Широкое окно: слева управление (прилипает при прокрутке), справа серверы.
           Узкое — всё в одну колонку. -->
      <div class="home-grid">
      <div class="side">
      <StatusCard onwhy={askWhy} />

      {#if choice.mode !== "vpn"}
        <ZapretCard onopen={() => (page = "zapret")} />
      {/if}
      </div>

      <div class="servers">
      {#if hasServers()}
        <ServerList onadd={() => (adding = true)} />
      {:else}
        <AddSubscription onadd={add} busy={conn.busy} />
        {#if addError && !adding}
          <Banner>{addError}</Banner>
        {/if}
      {/if}
      </div>
      </div>
    {:else if page === "subscriptions"}
      <h1>{t("Подписки", "Subscriptions")}</h1>
      <Subscriptions onadd={() => (adding = true)} />
    {:else if page === "routing"}
      <h1>{t("Маршрутизация", "Routing")}</h1>
      <Routing />
    {:else if page === "zapret"}
      <h1>Zapret</h1>
      <ZapretPage />
    {:else if page === "diagnostics"}
      <h1>{t("Проверка", "Check")}</h1>
      <Diagnostics
        onfix={onfix}
        autorun={autoDiagnose}
        onautorun={() => (autoDiagnose = false)}
      />
    {:else if page === "settings"}
      <h1>{t("Настройки", "Settings")}</h1>
      <Settings
        onrestartonboarding={() => {
          choice.onboarded = false;
          page = "home";
        }}
      />
    {:else}
      <h1>{t("Журнал", "Log")}</h1>
      <NetJournal />
    {/if}
    </div>
    {/key}
  </main>
</div>

{#if adding}
  <!-- Панель добавления поверх текущего экрана: список остаётся на месте. -->
  <AddOverlay busy={conn.busy} {addError} onadd={add} onclose={closeAdd} />
{/if}

<style>
  .shell {
    display: flex;
    height: 100%;
  }

  main {
    /* Закреплённые панели (список серверов) прилипают к самому верху окна. */
    --page-pad-top: var(--space-6);
    /* Карточки подстраиваются под ширину своей колонки (@container), а не окна. */
    container: main / inline-size;
    flex: 1;
    min-width: 0;
    padding: var(--page-pad-top) var(--space-8) var(--space-6);
    overflow-y: auto;
    scrollbar-gutter: stable;
  }

  /* Страница не растягивается бесконечно: на большом экране стоит по центру. */
  .page {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
    max-width: 1040px;
    margin-inline: auto;
    /* backwards: после анимации на странице не остаётся transform — закреплённая
       панель списка серверов работает как обычно. */
    animation: kvt-rise var(--dur) var(--ease) backwards;
  }

  /* Главная шире: серверы встают до трёх столбцов. */
  .page.home {
    max-width: 1240px;
  }

  /* Карточки не сжимаются под высоту окна — страница прокручивается целиком. */
  .page > :global(*),
  .side > :global(*),
  .servers > :global(*) {
    flex-shrink: 0;
  }

  .home-grid,
  .side,
  .servers {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
    min-width: 0;
  }

  .side,
  .servers {
    container-type: inline-size;
  }

  /* Две колонки одной высоты — по содержимому, но не выше окна: короткий список
     не растягивается в пустую панель, длинный прокручивается внутри карточки.
     Страница при этом сама не прокручивается. */
  @container main (min-width: 900px) {
    .page.home {
      height: 100%;
      min-height: 480px;
    }

    .page > .home-grid {
      display: grid;
      grid-template-columns: minmax(320px, 360px) minmax(0, 1fr);
      flex: 0 1 auto;
      min-height: 0;
    }

    .home-grid > .side,
    .home-grid > .servers {
      min-height: 0;
    }

    /* Низкое окно, подбор zapret, предупреждения — колонка прокручивается сама. */
    .side {
      overflow-y: auto;
      scrollbar-width: thin;
    }

    /* Список выше карточки статуса — она тянется до его высоты, кнопка по центру. */
    .side > :global(.status) {
      flex: 1 0 auto;
    }

    .servers > :global(.list) {
      flex: 0 1 auto;
      min-height: 0;
    }
  }

  @media (max-width: 900px) {
    main {
      --page-pad-top: var(--space-4);
      padding: var(--space-4);
    }
  }
</style>
