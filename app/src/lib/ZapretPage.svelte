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
    type Mode,
    type ServiceStatus,
    type ZapretChoice,
    type ZapretConflict,
    type ZapretStrategy as Strategy,
  } from "./api";
  import { listenChecks } from "./zapretStore.svelte";

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
        ? { mode: t("Гибрид", "Hybrid"), strategy: strategyFor(zapret, networkKey) }
        : null,
  );
  const vpnConnected = $derived(status?.state === "connected");

  /** При работающем VPN zapret добавляется «Гибридом» — VPN не отключается. */
  async function enable() {
    mode = vpnConnected ? "hybrid" : "zapret";
    await onconnect();
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
    bind:zapret
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
  <ZapretStrategy bind:zapret {strategies} {networkKey} {networkLabel} {vpnConnected} {running} {busy} onenable={enable} />

  <!-- Telegram -->
  <ZapretTelegram bind:zapret {status} />

  <!-- Параметры -->
  <ZapretOptions bind:zapret {running} />

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
