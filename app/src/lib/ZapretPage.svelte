<script lang="ts">
  import { t } from "./i18n";
  import ZapretMaintenance from "./zapret/ZapretMaintenance.svelte";
  import ZapretOptions from "./zapret/ZapretOptions.svelte";
  import ZapretStatus from "./zapret/ZapretStatus.svelte";
  import ZapretStrategy from "./zapret/ZapretStrategy.svelte";
  import ZapretTelegram from "./zapret/ZapretTelegram.svelte";
  import {
    currentNetwork,
    onNetworkChanged,
    strategyFor,
    zapretConflicts,
    zapretStopConflicts,
    zapretStrategies,
    type ZapretConflict,
    type ZapretStrategy as Strategy,
  } from "./api";
  import { listenChecks } from "./zapretStore.svelte";
  import { choice } from "./choiceStore.svelte";
  import { conn, connect } from "./connectionStore.svelte";

  // Настройки zapret и режим читаются и пишутся прямо в стор выбора; статус —
  // `connectionStore`. Пропсов нет.
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
    conn.status?.state === "zapret"
      ? { mode: "Zapret", strategy: conn.status.strategy }
      : conn.status?.state === "connected" && choice.mode === "hybrid"
        ? { mode: t("Гибрид", "Hybrid"), strategy: strategyFor(choice.zapret, networkKey) }
        : null,
  );
  const vpnConnected = $derived(conn.status?.state === "connected");
  const busy = $derived(conn.busy);

  /** При работающем VPN zapret добавляется «Гибридом» — VPN не отключается. */
  async function enable() {
    choice.mode = vpnConnected ? "hybrid" : "zapret";
    await connect();
  }

  // ── Стратегии ──
  let strategies = $state<Strategy[]>([]);
  async function loadStrategies() {
    strategies = await zapretStrategies().catch(() => []);
  }
  $effect(() => void loadStrategies());

  // ── Чужие обходы блокировок ──
  let conflicts = $state<ZapretConflict[]>([]);
  let stopping = $state(false);
  let conflictError = $state<string | null>(null);

  async function loadConflicts() {
    conflicts = await zapretConflicts().catch(() => []);
  }
  $effect(() => void loadConflicts());

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

  // ── Обслуживание ──
  /** Подтверждение переустановки открыто (его показывает ZapretMaintenance). */
  let confirmRepair = $state(false);

  /** «Переустановить» из вердикта: открыть подтверждение и показать, где оно. */
  function askRepair() {
    confirmRepair = true;
    document.getElementById("zapret-maintenance")?.scrollIntoView({ behavior: "smooth" });
  }

  /** После обновления или переустановки набор стратегий и чужие обходы могли измениться. */
  async function reloadAfterMaintenance() {
    await Promise.all([loadConflicts(), loadStrategies()]);
  }
</script>

<div class="page">
  <!-- Состояние и проверка -->
  <ZapretStatus
    bind:zapret={choice.zapret}
    {running}
    {vpnConnected}
    {networkLabel}
    {busy}
    {conflicts}
    {stopping}
    {conflictError}
    onenable={enable}
    onstop={stopConflicts}
    onrepair={askRepair}
  />

  <!-- Стратегия и автопроверка -->
  <ZapretStrategy bind:zapret={choice.zapret} {strategies} {networkKey} {networkLabel} {vpnConnected} {running} {busy} onenable={enable} />

  <!-- Telegram -->
  <ZapretTelegram bind:zapret={choice.zapret} status={conn.status} />

  <!-- Параметры -->
  <ZapretOptions bind:zapret={choice.zapret} {running} />

  <!-- Версия и обслуживание -->
  <ZapretMaintenance bind:confirmRepair onrefresh={reloadAfterMaintenance} />
</div>

<style>
  .page {
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
    container-type: inline-size;
  }
</style>
