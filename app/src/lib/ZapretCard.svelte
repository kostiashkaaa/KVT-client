<script lang="ts">
  import Icon from "./Icon.svelte";
  import {
    currentNetwork,
    onNetworkChanged,
    strategyFor,
    strategyTitle,
    zapretAutoselectCancel,
    zapretConflicts,
    zapretStopConflicts,
    zapretStrategies,
    type ZapretChoice,
    type ZapretConflict,
    type ZapretStrategy,
  } from "./api";
  import { check, listenChecks, pick, startAutoselect } from "./zapretStore.svelte";

  let {
    zapret = $bindable(),
    vpnConnected,
    onopen,
  }: { zapret: ZapretChoice; vpnConnected: boolean; onopen: () => void } = $props();

  listenChecks();

  let strategies = $state<ZapretStrategy[]>([]);
  let loadError = $state<string | null>(null);
  $effect(() => {
    zapretStrategies()
      .then((s) => (strategies = s))
      .catch((e) => (loadError = e instanceof Error ? e.message : String(e)));
  });

  let networkKey = $state<string | null>(null);
  $effect(() => {
    void currentNetwork().then((v) => (networkKey = v.network?.key ?? null));
    return onNetworkChanged((v) => (networkKey = v.network?.key ?? null));
  });

  const current = $derived(strategyFor(zapret, networkKey));
  const currentInfo = $derived(strategies.find((s) => s.id === current) ?? null);
  const pickedForNetwork = $derived(networkKey !== null && zapret.byNetwork[networkKey] !== undefined);

  /** Ручной выбор действует и в этой сети: подобранная для неё стратегия забывается. */
  function choose(id: string) {
    const byNetwork = { ...zapret.byNetwork };
    if (networkKey) delete byNetwork[networkKey];
    zapret = { ...zapret, strategy: id, byNetwork };
  }

  let conflicts = $state<ZapretConflict[]>([]);
  let stopping = $state(false);
  $effect(() => {
    zapretConflicts()
      .then((c) => (conflicts = c))
      .catch(() => (conflicts = []));
  });

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

  const share = $derived(
    pick.progress && pick.progress.total > 0 ? Math.min(1, pick.progress.index / pick.progress.total) : 0,
  );
</script>

<section class="card zapret">
  <!-- Короткая строка: что сейчас работает и одна кнопка. Описание режима — в карточке
       статуса выше, подробности и обслуживание — на вкладке Zapret. -->
  <div class="head">
    <div class="title">
      <h2>Zapret</h2>
      <p class="caption">
        {#if pick.running}
          Подбор стратегии…
        {:else}
          {pickedForNetwork ? "Подобрана для этой сети" : "Выбрана вручную"}{#if check.last}
            · проверка: {check.last.check.passed} из {check.last.check.max}{/if}
        {/if}
      </p>
    </div>
    <div class="controls">
      <select
        id="zapret-strategy"
        aria-label="Стратегия zapret"
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
      {#if pick.running}
        <button class="btn" onclick={() => void zapretAutoselectCancel()}>Остановить</button>
      {:else}
        <button
          class="btn"
          disabled={vpnConnected}
          title={vpnConnected
            ? "Отключите VPN: подбор проверяет сайты напрямую"
            : "Перебирает стратегии и проверяет Discord и YouTube (TLS 1.2, TLS 1.3, загрузка больше 32 КБ). До трёх минут"}
          onclick={startAutoselect}
        >
          Подобрать
        </button>
      {/if}
      <button class="btn ghost square" title="Все настройки zapret" aria-label="Все настройки zapret" onclick={onopen}>
        <Icon name="chevron" size={16} />
      </button>
    </div>
  </div>

  {#if pick.running}
    <div class="progress appear">
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
  {/if}

  {#if currentInfo?.needsTimestamps && !zapret.tcpTimestamps}
    <p class="note">
      Этой стратегии нужны TCP timestamps, а включать их запрещено в настройках — она может не сработать.
    </p>
  {/if}
  {#if loadError}
    <p class="note">{loadError}</p>
  {/if}

  {#if conflicts.length > 0}
    <div class="conflict appear" role="alert">
      <Icon name="warning" size={16} />
      <div>
        <strong>Работает другой обход блокировок</strong>
        <p>
          {conflicts.map((c) => c.name).join(", ")} — вместе с zapret KVT пакеты обрабатываются дважды и ничего не
          открывается. KVT может остановить их; удалять ничего не будет.
        </p>
      </div>
      <button class="btn" class:busy={stopping} disabled={stopping} onclick={stopConflicts}>Остановить</button>
    </div>
  {/if}

  {#if pick.error}
    <p class="note">{pick.error}</p>
  {:else if pick.result && !pick.running}
    {@const r = pick.result}
    <p class="result appear" class:good={r.best !== null || r.baseline === r.max}>
      {#if r.cancelled && !r.best}
        Подбор остановлен.
      {:else if r.best}
        Лучше всего работает {r.bestTitle}: {r.score} из {r.max} проверок (без zapret — {r.baseline}). Стратегия
        выбрана для этой сети.
      {:else if r.baseline === r.max}
        YouTube и Discord открываются и без zapret — в этой сети он не нужен.
      {:else}
        Ни одна стратегия не помогла ({r.baseline} из {r.max} без zapret). Попробуйте режим «Гибрид» или VPN.
      {/if}
    </p>
  {/if}
</section>

<style>
  .zapret {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    padding: var(--space-4) var(--space-5);
  }

  .head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-4);
  }

  .title {
    min-width: 0;
  }

  .title p {
    margin: 2px 0 0;
  }

  .controls {
    display: flex;
    flex: none;
    align-items: center;
    gap: var(--space-2);
  }

  .controls select {
    width: 200px;
    height: 32px;
  }

  .btn.ghost {
    border-color: transparent;
    background: transparent;
    color: var(--text-2);
  }

  .btn.ghost:hover:not(:disabled) {
    background: var(--surface-hover);
    color: var(--text);
  }

  /* Стрелка «в раздел»: шеврон списка повёрнут вправо. */
  .btn.square {
    width: 32px;
    padding: 0;
  }

  .btn.square :global(svg) {
    transform: rotate(-90deg);
  }

  .caption,
  .note,
  .result {
    margin: 0;
  }

  .note {
    padding: var(--space-2) var(--space-3);
    border-left: 3px solid var(--warn);
    border-radius: var(--radius-s);
    background: var(--warn-subtle);
  }

  .conflict {
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
    padding: var(--space-3);
    border-left: 3px solid var(--warn);
    border-radius: var(--radius-s);
    background: var(--warn-subtle);
    color: var(--text);
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

  .progress {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .bar {
    height: 4px;
    border-radius: 2px;
    background: var(--stroke);
    overflow: hidden;
  }

  .bar span {
    display: block;
    height: 100%;
    background: var(--accent);
    transition: width 200ms var(--ease);
  }

  .result {
    padding: var(--space-2) var(--space-3);
    border-left: 3px solid var(--warn);
    border-radius: var(--radius-s);
    background: var(--warn-subtle);
  }

  .result.good {
    border-left-color: var(--ok);
    background: var(--ok-subtle);
  }

  /* Узкая колонка: выбор стратегии и кнопки — отдельной строкой под заголовком. */
  @container (max-width: 560px) {
    .head {
      flex-direction: column;
      align-items: stretch;
    }

    .controls select {
      flex: 1;
      width: auto;
    }

    /* Кнопка «Остановить» — под текстом, а не сбоку: текст не сжимается в столбик. */
    .conflict {
      display: grid;
      grid-template-columns: auto minmax(0, 1fr);
    }

    .conflict .btn {
      grid-column: 2;
      justify-self: start;
      margin-left: 0;
    }
  }
</style>
