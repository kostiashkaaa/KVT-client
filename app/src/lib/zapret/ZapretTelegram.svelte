<script lang="ts">
  // Прокси для Telegram: переключатель, состояние прокси, «Подключить Telegram» и ссылка,
  // путь в «Гибриде». Состояние прокси перечитывается, пока переключатель включён.
  import { t } from "../i18n";
  import {
    tgProxyLink,
    tgProxyOpen,
    tgProxyStatus,
    type ServiceStatus,
    type TelegramRoute,
    type TgProxyStatus,
    type ZapretChoice,
  } from "../api";

  let {
    zapret = $bindable(),
    status,
  }: { zapret: ZapretChoice; status: ServiceStatus | null } = $props();

  const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

  // ── Telegram ──
  let tg = $state<TgProxyStatus | null>(null);
  let tgMessage = $state<string | null>(null);
  // Прокси запускается вместе с подключением — состояние перечитывается, пока открыта вкладка.
  $effect(() => {
    if (!zapret.telegram) return;
    const load = () => void tgProxyStatus().then((s) => (tg = s)).catch(() => {});
    load();
    const timer = setInterval(load, 3000);
    return () => clearInterval(timer);
  });

  async function connectTelegram() {
    tgMessage = null;
    try {
      await tgProxyOpen();
      tgMessage = t("В Telegram откроется окно «Подключить прокси» — нажмите «Подключиться».", "Telegram will open a “Connect proxy” window — press “Connect”.");
    } catch (e) {
      tgMessage = message(e);
    }
  }

  async function copyTelegramLink() {
    tgMessage = null;
    try {
      await navigator.clipboard.writeText(await tgProxyLink());
      tgMessage = t("Ссылка скопирована. Отправьте её себе в «Избранное» в Telegram и нажмите на неё.", "Link copied. Send it to your “Saved Messages” in Telegram and tap it.");
    } catch (e) {
      tgMessage = message(e);
    }
  }
</script>

<section class="card block">
  <div class="row">
    <div>
      <h2>Telegram</h2>
      <p class="muted">
        {t("Telegram Desktop ходит через прокси KVT в любом режиме — подключите его один раз. Работают сообщения, фото и видео; звонки через прокси не идут.", "Telegram Desktop goes through KVT's proxy in any mode — connect it once. Messages, photos and videos work; calls don't go through the proxy.")}
      </p>
    </div>
    <label class="switch">
      <input type="checkbox" role="switch" checked={zapret.telegram} onchange={(e) => (zapret = { ...zapret, telegram: e.currentTarget.checked })} />
      <span aria-hidden="true"></span><span class="sr">{t("Прокси для Telegram", "Telegram proxy")}</span>
    </label>
  </div>
  {#if zapret.telegram}
    <div class="tg">
      <div class="state">
        <span class="dot" class:on={tg?.running} aria-hidden="true"></span>
        <div>
          {#if tg?.running}
            <strong>{t("Прокси работает", "Proxy is running")}</strong>
          {:else if tg?.error}
            <strong>{t("Прокси не запустился", "The proxy didn't start")}</strong>
            <p class="caption">{tg.error}</p>
          {:else if status?.state === "connected" || status?.state === "zapret"}
            <strong>{t("Прокси запускается…", "The proxy is starting…")}</strong>
          {:else}
            <strong>{t("Прокси выключен", "Proxy is off")}</strong>
            <p class="caption">{t("Запустится, когда KVT подключится.", "It starts when KVT connects.")}</p>
          {/if}
        </div>
      </div>
      <div class="actions">
        <button class="btn btn-primary" disabled={!tg?.running} onclick={connectTelegram}>{t("Подключить Telegram", "Connect Telegram")}</button>
        <button class="btn" onclick={copyTelegramLink}>{t("Скопировать ссылку", "Copy link")}</button>
      </div>
    </div>
    {#if tgMessage}<p class="caption">{tgMessage}</p>{/if}
    <div class="row">
      <div>
        <span>{t("Путь Telegram в «Гибриде»", "Telegram's route in Hybrid")}</span>
        <p class="caption">
          {zapret.telegramRoute === "direct"
            ? t("Мимо VPN, как в «Zapret»: сервер не нагружается. Если прямой путь закрыт — запасной через Cloudflare.", "Around the VPN, as in Zapret mode: the server isn't loaded. If the direct route is blocked, a fallback goes through Cloudflare.")
            : t("Через VPN; если сервер не отвечает, прокси сам уйдёт на запасной путь через Cloudflare, без переподключения.", "Via the VPN; if the server doesn't respond, the proxy switches to the Cloudflare fallback itself, without reconnecting.")}
        </p>
      </div>
      <select
        aria-label={t("Путь Telegram в «Гибриде»", "Telegram's route in Hybrid")}
        value={zapret.telegramRoute}
        onchange={(e) => (zapret = { ...zapret, telegramRoute: e.currentTarget.value as TelegramRoute })}
      >
        <option value="direct">{t("Мимо VPN", "Around the VPN")}</option>
        <option value="vpn_first">{t("Сначала VPN", "VPN first")}</option>
      </select>
    </div>
    <p class="caption">
      {t("Прокси работает, пока запущен KVT (и в трее). Если закрыть KVT или выключить прокси здесь, уберите прокси и в настройках Telegram — иначе он не подключится.", "The proxy runs while KVT is running (including in the tray). If you quit KVT or turn off the proxy here, remove the proxy in Telegram's settings too — otherwise it won't connect.")}
    </p>
  {/if}
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

  .tg {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-4);
    padding: var(--space-3) var(--space-4);
    border-radius: var(--radius-s);
    background: var(--surface-hover);
  }

  .tg .state {
    align-items: center;
  }

  .tg .dot {
    margin-top: 0;
  }

  .muted,
  .caption {
    margin: 0;
  }

  /* Точка — по центру строки заголовка, а не между строками. */
  .state {
    display: flex;
    align-items: flex-start;
    gap: var(--space-3);
  }

  .state p {
    margin: 2px 0 0;
  }

  .dot {
    flex: none;
    width: 10px;
    height: 10px;
    margin-top: 6px;
    border-radius: 50%;
    background: var(--text-3);
    transition:
      background-color var(--dur) var(--ease),
      box-shadow var(--dur) var(--ease);
  }

  .dot.on {
    background: var(--ok);
    box-shadow: 0 0 0 4px var(--ok-subtle);
  }

  .actions {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
  }

  @container (max-width: 620px) {
    /* Переключатель остаётся справа от текста, поле и кнопка уходят под него. */
    .row:has(> select),
    .tg {
      flex-direction: column;
      align-items: stretch;
    }
  }
</style>
