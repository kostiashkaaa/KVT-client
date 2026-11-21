<script lang="ts">
  import { t } from "../i18n";
  import {
    siteCheck,
    type SitePath,
    type SiteReport,
    type SiteRunning,
    type SiteVerdict,
  } from "../api";

  // «Почему не работает?» для одного сайта. Вердикты и совет приходят из Rust
  // (`kvt_core::sitecheck`, пробы — `sitecheck` в kvt-app); здесь только показ.

  let host = $state("");
  let running = $state(false);
  let report = $state<SiteReport | null>(null);
  let error = $state<string | null>(null);

  async function run() {
    if (running || !host.trim()) return;
    running = true;
    error = null;
    report = null;
    try {
      report = await siteCheck(host);
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
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

  function verdictView(v: SiteVerdict): { text: string; tone: string } {
    switch (v) {
      case "works":
        return { text: t("открывается", "opens"), tone: "good" };
      case "slow":
        return { text: t("медленно, но открывается", "slow, but opens"), tone: "warn" };
      case "tls_cut":
        return { text: t("оборвали соединение — режут по имени сайта", "the connection was cut — blocked by site name"), tone: "bad" };
      case "tls_frozen":
        return { text: t("рукопожатие заморожено", "the handshake was frozen"), tone: "bad" };
      case "data_frozen":
        return { text: t("соединение есть, данные не идут", "the connection is up, but no data flows"), tone: "bad" };
      case "refused":
        return { text: t("сайт сам не пускает (403)", "the site itself refuses (403)"), tone: "warn" };
      case "unreachable":
        return { text: t("адрес недоступен", "unreachable"), tone: "bad" };
      case "no_address":
        return { text: t("имя не находится", "the name doesn't resolve"), tone: "bad" };
    }
  }

  function adviceView(a: SiteReport["advice"]): { text: string; tone: string } {
    switch (a) {
      case "works":
        return { text: t("Сайт открывается — каким путём, видно выше.", "The site opens — the path is shown above."), tone: "good" };
      case "try_vpn":
        return {
          text: t(
            "Похоже, сайт блокируют. Подключите VPN и проверьте снова — строка «через VPN» покажет, открывает ли он.",
            "Looks like the site is blocked. Connect the VPN and check again — the “via VPN” row will show whether it opens.",
          ),
          tone: "warn",
        };
      case "still_cut":
        return {
          text: t(
            "Не открывается ни одним путём. Попробуйте другой сервер: этот адрес могли внести в чёрный список.",
            "No path opens it. Try another server: this address may be blacklisted.",
          ),
          tone: "bad",
        };
      case "change_server":
        return {
          text: t(
            "Сайт не пускает с адреса VPN-сервера (403). Смените сервер — у другого адрес другой.",
            "The site refuses the VPN server's address (403). Switch servers — another one has a different address.",
          ),
          tone: "warn",
        };
      case "check_dns":
        return {
          text: t(
            "Имя не находится. «Проверка DNS» ниже покажет, кто отвечает за адреса в этой сети и не подменяют ли их.",
            "The name doesn't resolve. The “DNS check” below will show who answers for addresses on this network, and whether they're being spoofed.",
          ),
          tone: "warn",
        };
    }
  }
</script>

<section class="card block" id="site-check">
  <div class="row">
    <div>
      <h2>{t("Один сайт не открывается?", "One site won't open?")}</h2>
      <p class="muted">
        {t(
          "Проверит сайт по стадиям — имя, соединение, рукопожатие, ответ — каждым доступным путём и скажет, как именно его режут.",
          "Checks the site in stages — name, connection, handshake, response — along every available path, and tells you exactly how it's being cut.",
        )}
      </p>
    </div>
    <form class="ask" onsubmit={(e) => { e.preventDefault(); void run(); }}>
      <input
        type="text"
        placeholder="example.com"
        aria-label={t("Адрес сайта", "Site address")}
        autocomplete="off"
        spellcheck="false"
        bind:value={host}
      />
      <button class="btn btn-primary" type="submit" disabled={running || !host.trim()}>
        {#if running}<span class="spinner" aria-hidden="true"></span>{/if}
        {running ? t("Проверяем…", "Checking…") : t("Проверить", "Check")}
      </button>
    </form>
  </div>

  {#if error}
    <p class="caption error-text">{error}</p>
  {/if}

  {#if report}
    <ul class="paths">
      {#each report.paths as p}
        <li>
          <span class="name">{pathLabel(p.path, report.running)}</span>
          {#if p.verdict}
            {@const v = verdictView(p.verdict)}
            <span class="verdict {v.tone}">{v.text}</span>
            {#if p.ms != null}<span class="caption ms">{p.ms} {t("мс", "ms")}</span>{/if}
          {:else}
            <span class="verdict muted">
              {t("отложено — соединения с этим сайтом недавно заморожены, попробуйте позже", "postponed — connections to this site were frozen recently, try again later")}
            </span>
          {/if}
        </li>
      {/each}
      {#each report.skipped as s}
        <li>
          <span class="name">{pathLabel(s.path, report.running)}</span>
          <span class="verdict muted">
            {t("не проверяли — kill switch держит трафик в туннеле", "not checked — the kill switch keeps traffic in the tunnel")}
          </span>
        </li>
      {/each}
    </ul>
    {@const a = adviceView(report.advice)}
    <p class="advice {a.tone}">{a.text}</p>
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

  /* К карточке прокручивают по ссылке — не прижимаем к краю окна. */
  #site-check {
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

  .error-text {
    margin: 0;
    color: var(--danger);
  }

  .ask {
    display: flex;
    flex: none;
    gap: var(--space-2);
  }

  .ask input {
    width: 220px;
    height: 32px;
    padding: 0 var(--space-3);
    border: 1px solid var(--stroke);
    border-bottom-color: var(--text-3);
    border-radius: var(--radius-s);
    background: var(--surface);
    user-select: text;
  }

  .ask input:focus {
    outline: none;
    border-bottom-color: var(--accent);
    box-shadow: inset 0 -1px 0 var(--accent);
  }

  .paths {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    margin: 0;
    padding: 0;
    list-style: none;
  }

  .paths li {
    display: flex;
    align-items: baseline;
    gap: var(--space-3);
  }

  .name {
    flex: none;
    min-width: 96px;
    color: var(--text-2);
  }

  .verdict {
    min-width: 0;
  }

  .ms {
    flex: none;
    font-variant-numeric: tabular-nums;
  }

  .good {
    color: var(--ok);
  }

  .warn {
    color: var(--warn);
  }

  .bad {
    color: var(--danger);
  }

  .muted {
    color: var(--text-3);
  }

  .advice {
    margin: 0;
  }

  @container (max-width: 620px) {
    .ask {
      width: 100%;
      flex-direction: column;
    }

    .ask input {
      width: 100%;
    }
  }
</style>
