<script lang="ts">
  import { t } from "../i18n";
  import Flag from "../Flag.svelte";
  import { vpnCheck, type SitePath, type SiteRunning, type VpnReport, type VpnSide } from "../api";

  // «Проверить VPN»: адрес и страна выхода и замер скорости — через VPN и
  // напрямую. Данные приходят из Rust (`kvt_core::vpncheck`, запросы — `vpncheck`
  // в kvt-app); здесь только показ. Пути и подписи — как у проверки одного сайта.

  let running = $state(false);
  let report = $state<VpnReport | null>(null);

  async function run() {
    if (running) return;
    running = true;
    report = null;
    try {
      report = await vpnCheck();
    } finally {
      running = false;
    }
  }

  /** Метка пути: «напрямую» при работающем zapret — это перехват winws, «через zapret». */
  function pathLabel(path: SitePath, r: SiteRunning): string {
    if (path === "tunnel") return t("через VPN", "via VPN");
    return r === "hybrid" || r === "zapret"
      ? t("через zapret", "via zapret")
      : t("напрямую", "direct");
  }

  /** 6144 → «6 МБ/с»; 640 → «640 КБ/с». */
  function speedText(kbps: number): string {
    return kbps >= 1024
      ? t(`${(kbps / 1024).toFixed(1).replace(".", ",")} МБ/с`, `${(kbps / 1024).toFixed(1)} MB/s`)
      : t(`${kbps} КБ/с`, `${kbps} KB/s`);
  }

  function sideText(side: VpnSide): { text: string; tone: string } {
    if (side.kind === "failed") {
      return { text: t("не удалось — путь не отвечает", "couldn't check — the path doesn't respond"), tone: "muted" };
    }
    if (side.kind === "deferred") {
      return {
        text: t("отложено — соединения недавно заморожены, попробуйте позже", "postponed — connections were frozen recently, try again later"),
        tone: "muted",
      };
    }
    // Основной источник не показываем: он и так подразумевается; запасной виден,
    // чтобы было ясно, чей ответ перед нами.
    const via = (name: string | null): string => (name && name !== "cloudflare" ? ` · ${name}` : "");
    const parts = [
      (side.country ?? t("страна неизвестна", "unknown country")) + via(side.traceVia),
      (side.kbps != null ? speedText(side.kbps) : t("скорость не измерилась", "speed couldn't be measured")) + via(side.speedVia),
    ];
    return { text: parts.join(" · "), tone: "" };
  }
</script>

<section class="card block" id="vpn-check">
  <div class="row">
    <div>
      <h2>{t("Проверить VPN", "Check the VPN")}</h2>
      <p class="muted">
        {t(
          "С какого адреса и из какой страны видят сайты, и какая скорость — через VPN и напрямую.",
          "Which address and country websites see you from, and how fast it is — via VPN and direct.",
        )}
      </p>
    </div>
    <button class="btn btn-primary" disabled={running} onclick={() => void run()}>
      {#if running}<span class="spinner" aria-hidden="true"></span>{/if}
      {running ? t("Проверяем…", "Checking…") : t("Проверить", "Check")}
    </button>
  </div>

  {#if report}
    <ul class="sides">
      {#each report.sides as s}
        {@const v = sideText(s.side)}
        <li>
          <span class="name">{pathLabel(s.path, report.running)}</span>
          {#if s.side.kind === "ok"}
            <span class="out">
              {#if s.side.country}<Flag code={s.side.country} width={24} />{/if}
              <span class="caption ip">{s.side.ip ?? t("адрес неизвестен", "unknown address")}</span>
              <span class="caption {v.tone ? '' : 'ok'}">{v.text}</span>
            </span>
          {:else}
            <span class="caption {v.tone}">{v.text}</span>
          {/if}
        </li>
      {/each}
      {#each report.skipped as s}
        <li>
          <span class="name">{pathLabel(s.path, report.running)}</span>
          <span class="caption muted">
            {t("не проверяли — kill switch держит трафик в туннеле", "not checked — the kill switch keeps traffic in the tunnel")}
          </span>
        </li>
      {/each}
    </ul>
  {/if}
</section>

<style>
  /* Карточка на «Проверке»: свои `block`/`row`, как у соседних карточек — общие
     стили страницы scoped, из компонента их не видно. */
  .block {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    padding: var(--space-5);
  }

  #vpn-check {
    scroll-margin-top: var(--space-5);
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

  .row .btn {
    flex: none;
  }

  .sides {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    margin: 0;
    padding: 0;
    list-style: none;
  }

  .sides li {
    display: flex;
    align-items: center;
    gap: var(--space-3);
  }

  .name {
    flex: none;
    min-width: 96px;
    color: var(--text-2);
  }

  .out {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    min-width: 0;
  }

  .ip {
    font-variant-numeric: tabular-nums;
    user-select: text;
  }

  .muted {
    color: var(--text-3);
  }

  .ok {
    color: var(--ok);
  }
</style>
