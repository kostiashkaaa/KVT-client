<script lang="ts">
  // Параметры zapret: игровой фильтр, обход по IP-списку, TCP timestamps.
  import { t } from "../i18n";
  import type { GameFilter, ZapretChoice } from "../api";

  let {
    zapret = $bindable(),
    running,
  }: { zapret: ZapretChoice; running: { mode: string; strategy: string } | null } = $props();

  const gameFilters: { id: GameFilter; label: string }[] = [
    { id: "off", label: t("Выключен", "Off") },
    { id: "tcp", label: "TCP" },
    { id: "udp", label: "UDP" },
    { id: "all", label: t("TCP и UDP", "TCP and UDP") },
  ];
  /** Подпись про перезапуск: в «Гибриде» вместе с zapret переподключается VPN. */
  const restartNote = $derived(
    running && running.mode !== "Zapret"
      ? t("Изменения применяются сразу: VPN и zapret переподключатся на пару секунд.", "Changes apply immediately: the VPN and zapret will reconnect for a couple of seconds.")
      : running
        ? t("Изменения применяются сразу: zapret перезапустится на пару секунд.", "Changes apply immediately: zapret will restart for a couple of seconds.")
        : null,
  );
</script>

<section class="card block">
  <h2>{t("Параметры", "Options")}</h2>
  <div class="row">
    <div>
      <span>{t("Игровой фильтр", "Game filter")}</span>
      <p class="caption">{t("Обход на всех портах выше 1024 — для игр и голоса. Без нужды не включайте.", "Bypass on all ports above 1024 — for games and voice. Don't turn on unless needed.")}</p>
    </div>
    <select
      aria-label={t("Игровой фильтр", "Game filter")}
      value={zapret.gameFilter}
      onchange={(e) => (zapret = { ...zapret, gameFilter: e.currentTarget.value as GameFilter })}
    >
      {#each gameFilters as g (g.id)}
        <option value={g.id}>{g.label}</option>
      {/each}
    </select>
  </div>
  <div class="row">
    <div>
      <span>{t("Обход по IP-списку Flowseal", "Bypass by Flowseal's IP list")}</span>
      <p class="caption">
        {t("Не только по доменам, а по всем адресам из ipset-all. Помогает, когда сервис ходит по IP (игры, голос), но может замедлить другие сайты.", "Not just by domain but by every address in ipset-all. Helps when a service connects by IP (games, voice), but may slow down other sites.")}
      </p>
    </div>
    <label class="switch">
      <input type="checkbox" role="switch" checked={zapret.ipset} onchange={(e) => (zapret = { ...zapret, ipset: e.currentTarget.checked })} />
      <span aria-hidden="true"></span><span class="sr">{t("Обход по IP-списку", "Bypass by IP list")}</span>
    </label>
  </div>
  <div class="row">
    <div>
      <span>{t("Разрешить включать TCP timestamps", "Allow turning on TCP timestamps")}</span>
      <p class="caption">
        {t("Они нужны части стратегий. Flowseal включает их при каждом запуске, KVT — только с разрешения. Это обычная настройка TCP, она остаётся включённой.", "Some strategies need them. Flowseal turns them on at every start, KVT only with your permission. It's a regular TCP setting and stays on.")}
      </p>
    </div>
    <label class="switch">
      <input
        type="checkbox"
        role="switch"
        checked={zapret.tcpTimestamps}
        onchange={(e) => (zapret = { ...zapret, tcpTimestamps: e.currentTarget.checked })}
      />
      <span aria-hidden="true"></span><span class="sr">{t("Разрешить включать TCP timestamps", "Allow turning on TCP timestamps")}</span>
    </label>
  </div>
  {#if restartNote}<p class="caption">{restartNote}</p>{/if}
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

  .caption {
    margin: 0;
  }

  @container (max-width: 620px) {
    /* Переключатель остаётся справа от текста, поле и кнопка уходят под него. */
    .row:has(> select) {
      flex-direction: column;
      align-items: stretch;
    }
  }
</style>
