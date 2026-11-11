<script lang="ts">
  import { t } from "./i18n";
  import type { Mode } from "./api";

  // Первый запуск — три коротких шага поверх главной: подписка → режим → подключение.
  // Пропускается одной кнопкой, повторяется из «Настроек».
  let {
    hasServers,
    mode = $bindable(),
    active,
    busy,
    onadd,
    onmigrate,
    onconnect,
    ondone,
  }: {
    hasServers: boolean;
    mode: Mode;
    /** Работает VPN или zapret. */
    active: boolean;
    busy: boolean;
    /** Открыть добавление подписки. */
    onadd: () => void;
    /** Перенос из другого клиента («Подписки»). */
    onmigrate: () => void;
    onconnect: () => void;
    /** Пройдено или пропущено — больше не показывать. */
    ondone: () => void;
  } = $props();

  // Режим Zapret работает без сервера, поэтому шаг 1 для него не нужен.
  let step = $state(1);
  $effect(() => {
    if (step === 1 && hasServers) step = 2;
  });
  const finished = $derived(step === 3 && active);

  const modes: { id: Mode; title: string; text: string }[] = [
    { id: "vpn", title: "VPN", text: t("Заблокированное — через VPN-сервер, российские сайты — напрямую.", "Blocked sites go through the VPN server, Russian sites go direct.") },
    { id: "hybrid", title: t("Гибрид", "Hybrid"), text: t("YouTube и Discord — через zapret без VPN, Telegram Desktop — через прокси, остальное заблокированное — через VPN.", "YouTube and Discord go through zapret without the VPN, Telegram Desktop through the proxy, other blocked sites through the VPN.") },
    { id: "zapret", title: "Zapret", text: t("Без VPN-сервера: обход замедления YouTube и Discord, Telegram Desktop — через прокси.", "No VPN server: bypasses YouTube and Discord throttling, Telegram Desktop goes through the proxy.") },
  ];
</script>

<section class="card onboarding appear" aria-labelledby="onboarding-title">
  <div class="head">
    <p class="caption steps" aria-label={t(`Шаг ${step} из 3`, `Step ${step} of 3`)}>
      {#each [1, 2, 3] as n (n)}
        <span class="dot" class:done={n < step || finished} class:current={n === step && !finished}></span>
      {/each}
      {t(`Шаг ${step} из 3`, `Step ${step} of 3`)}
    </p>
    {#if !finished}
      <button class="skip" onclick={ondone}>{t("Пропустить", "Skip")}</button>
    {/if}
  </div>

  {#if step === 1}
    <h2 id="onboarding-title">{t("Добавьте подписку или ключ", "Add a subscription or key")}</h2>
    <p class="muted">
      {t("Ссылку на подписку (https://…) или ключ (vless://, vmess://, trojan://, hy2://…) даёт ваш VPN-провайдер. Пользуетесь v2rayN, Hiddify или NekoRay — KVT перенесёт подписки из них.", "Your VPN provider gives you a subscription link (https://…) or a key (vless://, vmess://, trojan://, hy2://…). Using v2rayN, Hiddify or NekoRay? KVT will import subscriptions from them.")}
    </p>
    <div class="actions">
      <button class="btn btn-primary" onclick={onadd}>{t("Вставить ссылку", "Paste link")}</button>
      <button class="btn" onclick={onmigrate}>{t("Перенести из другого клиента", "Import from another client")}</button>
      <button class="btn link" onclick={() => ((mode = "zapret"), (step = 2))}>{t("У меня нет VPN — только zapret", "I have no VPN — just zapret")}</button>
    </div>
  {:else if step === 2}
    <h2 id="onboarding-title">{t("Выберите режим", "Choose a mode")}</h2>
    <div class="modes" role="radiogroup" aria-label={t("Режим работы", "Mode")}>
      {#each modes as m (m.id)}
        <button
          class="mode"
          role="radio"
          aria-checked={mode === m.id}
          class:selected={mode === m.id}
          disabled={m.id !== "zapret" && !hasServers}
          onclick={() => (mode = m.id)}
        >
          <strong>{m.title}</strong>
          <span class="caption">{m.text}</span>
        </button>
      {/each}
    </div>
    <p class="caption">{t("Режим можно сменить в любой момент — на главной и в меню трея.", "You can change the mode any time — on the home page and in the tray menu.")}</p>
    <div class="actions">
      <button class="btn btn-primary" onclick={() => (step = 3)}>{t("Дальше", "Next")}</button>
    </div>
  {:else if !finished}
    <h2 id="onboarding-title">{t("Подключитесь", "Connect")}</h2>
    <p class="muted">
      {t("KVT поднимет защищённое соединение и проверит, что сайты открываются. Закрытое окно не выключает VPN: KVT остаётся в трее, оттуда же можно сменить сервер и режим.", "KVT will set up a secure connection and check that sites open. Closing the window doesn't turn off the VPN: KVT stays in the tray, where you can also change the server and mode.")}
    </p>
    <div class="actions">
      <button class="btn btn-primary" disabled={busy} onclick={onconnect}>
        {#if busy}<span class="spinner" aria-hidden="true"></span>{/if}
        {busy ? t("Подключение…", "Connecting…") : t("Подключить", "Connect")}
      </button>
      <button class="btn" onclick={() => (step = 2)}>{t("Назад", "Back")}</button>
    </div>
  {:else}
    <h2 id="onboarding-title">{t("Готово", "Done")}</h2>
    <p class="muted">
      {t("KVT подключён. Если что-то не открывается — «Почему не работает?» на главной найдёт причину. Подсказки можно показать снова в «Настройках».", "KVT is connected. If something doesn't open, “Why isn't it working?” on the home page will find the cause. You can show these tips again in Settings.")}
    </p>
    <div class="actions">
      <button class="btn btn-primary" onclick={ondone}>{t("Понятно", "Got it")}</button>
    </div>
  {/if}
</section>

<style>
  .onboarding {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    padding: var(--space-5);
    border-color: var(--accent);
  }

  .head {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .steps {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    margin: 0;
  }

  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--stroke);
    transition: background-color var(--dur) var(--ease);
  }

  .dot.current {
    background: var(--accent);
  }

  .dot.done {
    background: var(--ok);
  }

  .skip {
    padding: 0;
    border: 0;
    background: none;
    color: var(--text-2);
    font-size: 12px;
    cursor: pointer;
  }

  .skip:hover {
    color: var(--text);
    text-decoration: underline;
    text-underline-offset: 2px;
  }

  h2,
  p {
    margin: 0;
  }

  .actions {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
  }

  .link {
    border-color: transparent;
    background: none;
    color: var(--accent);
  }

  .modes {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: var(--space-2);
  }

  .mode {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    padding: var(--space-3);
    border: 1px solid var(--stroke);
    border-radius: var(--radius-s);
    background: var(--bg);
    color: inherit;
    text-align: left;
    cursor: pointer;
    transition:
      border-color var(--dur-fast) var(--ease),
      background-color var(--dur-fast) var(--ease);
  }

  .mode:hover:not(:disabled) {
    background: var(--surface-hover);
  }

  .mode.selected {
    border-color: var(--accent);
    background: var(--accent-subtle);
  }

  .mode:disabled {
    opacity: 0.5;
    cursor: default;
  }

  @media (max-width: 720px) {
    .modes {
      grid-template-columns: 1fr;
    }
  }
</style>
