<script lang="ts">
  import { fade } from "svelte/transition";
  import { inApp, panelClose, panelReady } from "../lib/api";
  import Alerts from "./Alerts.svelte";
  import Footer from "./Footer.svelte";
  import ModeTiles from "./ModeTiles.svelte";
  import QuickChips from "./QuickChips.svelte";
  import ServerPick from "./ServerPick.svelte";
  import ServicesRow from "./ServicesRow.svelte";
  import StatusHeader from "./StatusHeader.svelte";
  import { panel, start, status } from "./store.svelte";

  $effect(() => start());

  const sv = $derived(status());
  const view = $derived(panel.view);
  /** Службы нет: настраивать нечего, остаётся «Запустить службу». */
  const down = $derived(panel.polled && panel.status === null);
  /** Режимы, сервер, сервисы и переключатели — пока есть что настраивать. */
  const settings = $derived(!down && !sv.blocked);

  // Высота зависит от состояния (плашка, список серверов, режим «Zapret»): сообщаем её
  // Rust при каждом изменении, он заново ставит окно у значка. Первое сообщение — и повод
  // показать окно, поэтому каркас рисуется сразу, ещё до данных: окно открывается, не
  // дожидаясь ответов, а данные проявляются на месте.
  let root = $state<HTMLElement | null>(null);
  let reported = 0;
  $effect(() => {
    const el = root;
    if (!el) return;
    const report = () => {
      const height = Math.ceil(el.getBoundingClientRect().height);
      if (height === reported) return;
      reported = height;
      void panelReady(height);
    };
    report();
    const observer = new ResizeObserver(report);
    observer.observe(el);
    return () => observer.disconnect();
  });

  // Появление панели: играем, когда окно показывает Rust — при первом открытии и каждом
  // повторном (окно живёт минуту после закрытия, страница не монтируется заново). В
  // превью окно «видно» сразу — всплываем на месте.
  function reveal() {
    const el = root;
    if (!el) return;
    el.classList.remove("revealed");
    void el.offsetWidth; // перезапуск анимации при повторном показе
    el.classList.add("revealed");
  }
  const onVisibility = () => {
    if (!document.hidden) reveal();
  };
  $effect(() => {
    if (document.visibilityState === "visible") reveal();
    document.addEventListener("visibilitychange", onVisibility);
    return () => document.removeEventListener("visibilitychange", onVisibility);
  });
</script>

<svelte:window onkeydown={(e) => e.key === "Escape" && void panelClose()} />

<div class="panel" class:framed={!inApp} bind:this={root} role="dialog" aria-label="KVT">
  {#if panel.polled && view}
    <div class="content" in:fade={{ duration: 150 }}>
      <StatusHeader {sv} {down} />
      <Alerts {sv} {down} />
      {#if settings}
        <ModeTiles />
        {#if view.mode !== "zapret"}<ServerPick />{/if}
        <ServicesRow />
        <QuickChips />
      {/if}
      <Footer />
    </div>
  {:else}
    <!-- Каркас, пока страница читает выбор и статус: по очертаниям — как готовая панель. -->
    <div class="skeleton" aria-hidden="true">
      <span class="sk status"></span>
      <span class="sk tiles"></span>
      <span class="sk server"></span>
      <span class="sk chips"></span>
    </div>
  {/if}
</div>

<style>
  /* Окно панели без рамки: подложку и скругление даёт система, страница заполняет окно.
     Плотная подложка --surface; Mica и Acrylic — позже, как у главного окна. */
  :global(html),
  :global(body) {
    overflow: hidden;
    background: var(--surface);
  }

  .panel {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    padding: var(--space-4) var(--space-4) var(--space-2);
    background: var(--surface);
    /* Всплытие при показе окна: до него страница ждёт в скрытом окне. */
    opacity: 0;
    transform: translateY(10px);
  }

  /* Класс вешает `reveal()` при показе окна — Svelte его в шаблоне не видит. */
  .panel:global(.revealed) {
    opacity: 1;
    transform: none;
    transition:
      opacity 180ms var(--ease),
      transform 180ms var(--ease);
  }

  .content {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }

  .skeleton {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }

  /* Очертания готовой панели: строка статуса, плитки режимов, сервер, быстрые
     переключатели. Пульс — как индикатор «ждём», по очереди. */
  .sk {
    display: block;
    border-radius: var(--radius-m);
    background: var(--stroke);
    animation: kvt-pulse 1.2s ease-in-out infinite;
  }

  .sk:nth-child(2) {
    animation-delay: 150ms;
  }

  .sk:nth-child(3) {
    animation-delay: 300ms;
  }

  .sk:nth-child(4) {
    animation-delay: 450ms;
  }

  .sk.status {
    height: 48px;
  }

  .sk.tiles {
    height: 76px;
  }

  .sk.server {
    height: 48px;
  }

  .sk.chips {
    height: 32px;
  }

  /* В браузерном превью окна нет: панель рисуется карточкой, как в окошке Windows 11. */
  .panel.framed {
    width: 360px;
    margin: var(--space-6) auto;
    border: 1px solid var(--stroke);
    border-radius: 8px;
    box-shadow: 0 8px 32px rgb(0 0 0 / 0.32);
  }

  :global(html:has(.panel.framed)),
  :global(body:has(.panel.framed)) {
    overflow: auto;
    background: var(--bg);
  }
</style>
