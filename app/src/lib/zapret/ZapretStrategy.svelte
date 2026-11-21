<script lang="ts">
  // Стратегия и автопроверка: выбор стратегии Flowseal, автоподбор с ходом и итогом,
  // переключатели «проверять» и «подбирать новую». Подбор — в zapretStore.
  import { t } from "../i18n";
  import {
    strategyFor,
    strategyTitle,
    zapretAutoselectCancel,
    type ZapretChoice,
    type ZapretStrategy,
  } from "../api";
  import { pick, startAutoselect } from "../zapretStore.svelte";

  let {
    zapret = $bindable(),
    strategies,
    networkKey,
    networkLabel,
    vpnConnected,
    running,
    busy,
    onenable,
  }: {
    zapret: ZapretChoice;
    strategies: ZapretStrategy[];
    networkKey: string | null;
    networkLabel: string | null;
    vpnConnected: boolean;
    running: { mode: string; strategy: string } | null;
    busy: boolean;
    /** Включить zapret («Гибрид», если VPN уже работает). */
    onenable: () => Promise<void>;
  } = $props();

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
</script>

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
        <button class="btn btn-primary" class:busy disabled={busy} onclick={onenable}>{t("Включить zapret", "Turn on zapret")}</button>
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

  .row > select {
    flex: none;
  }

  .row > select {
    min-width: 220px;
  }

  h2 {
    margin: 0;
  }

  .divider {
    height: 1px;
    margin: var(--space-1) 0;
    background: var(--stroke);
  }

  .row.disabled {
    opacity: 0.55;
  }

  .muted,
  .caption {
    margin: 0;
  }

  .note {
    margin: 0;
    padding: var(--space-2) var(--space-3);
    border-left: 3px solid var(--warn);
    border-radius: var(--radius-s);
    background: var(--warn-subtle);
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

  @container (max-width: 620px) {
    /* Переключатель остаётся справа от текста, поле и кнопка уходят под него. */
    .row:has(> select),
    .pick,
    .result {
      flex-direction: column;
      align-items: stretch;
    }

    .tried li {
      grid-template-columns: 1fr 64px;
    }

    .tried .meter {
      display: none;
    }
  }
</style>
