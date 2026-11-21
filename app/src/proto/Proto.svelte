<script lang="ts">
  import { t } from "../lib/i18n";
  import Icon from "../lib/Icon.svelte";
  import MiniPanel from "./MiniPanel.svelte";
  import { setTheme, theme, type ThemeChoice } from "../lib/theme.svelte";
  import type { Mode } from "../lib/api";

  let connected = $state(true);
  let mode = $state<Mode>("hybrid");
  /** Панель открыта: клик по значку в трее, закрывается кликом мимо и по Esc. */
  let open = $state(true);

  function outside(e: PointerEvent) {
    if (e.target instanceof Element && !e.target.closest(".slot, .kvt")) open = false;
  }

  const choices: { id: ThemeChoice; label: string }[] = [
    { id: "auto", label: t("Как в Windows", "System") },
    { id: "light", label: t("Светлая", "Light") },
    { id: "dark", label: t("Тёмная", "Dark") },
  ];

  const hhmm = new Date(2026, 10, 14, 21, 40).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" });

  /** Состояния для галереи: что видно в каждом случае. */
  const gallery: {
    label: string;
    props: {
      connected: boolean;
      mode: Mode;
      noData?: boolean;
      connecting?: boolean;
      serviceDown?: boolean;
      blocked?: boolean;
      notice?: "update" | "expiring" | null;
    };
  }[] = [
    { label: t("Подключено, VPN", "Connected, VPN"), props: { connected: true, mode: "vpn" } },
    { label: t("Подключение", "Connecting"), props: { connected: true, mode: "vpn", connecting: true } },
    { label: t("Отключено", "Disconnected"), props: { connected: false, mode: "hybrid" } },
    { label: t("Данные не идут: два выхода сразу", "No data: two ways out"), props: { connected: true, mode: "vpn", noData: true } },
    { label: t("Только Zapret, без сервера", "Zapret only, no server"), props: { connected: true, mode: "zapret" } },
    { label: t("Служба не запущена", "Service not running"), props: { connected: false, mode: "vpn", serviceDown: true } },
    { label: t("Интернет закрыт kill switch", "Internet blocked by kill switch"), props: { connected: true, mode: "vpn", blocked: true } },
    { label: t("Напоминание: вышла новая версия", "Reminder: a new version is out"), props: { connected: true, mode: "vpn", notice: "update" } },
    { label: t("Напоминание: подписка кончается", "Reminder: subscription is ending"), props: { connected: true, mode: "hybrid", notice: "expiring" } },
  ];
</script>

<svelte:window onkeydown={(e) => e.key === "Escape" && (open = false)} />

<div class="proto">
  <header class="top">
    <div>
      <h1>{t("Мини-панель из трея", "Tray mini-panel")}</h1>
      <p class="muted">{t("Прототип: кнопки живые, но со службой не связаны.", "Mock-up: the buttons work, but nothing is connected to the service.")}</p>
    </div>
    <div class="seg" role="radiogroup" aria-label={t("Тема", "Theme")}>
      {#each choices as c (c.id)}
        <button role="radio" aria-checked={theme.choice === c.id} class:on={theme.choice === c.id} onclick={() => setTheme(c.id)}>{c.label}</button>
      {/each}
    </div>
  </header>

  <section class="block">
    <p class="muted">
      {t("Клик по значку K в трее выдвигает окошко над панелью задач; закрывается кликом мимо или по Esc. Режим, сервер, статус сервисов и быстрые настройки — без большого окна.", "Clicking the K tray icon slides the flyout up above the taskbar; it closes on a click outside or Esc. Mode, server, service status and quick settings without the big window.")}
    </p>
    <div class="desk" role="presentation" onpointerdown={outside}>
      <div class="wall" aria-hidden="true"></div>
      <!-- Панель остаётся в странице, только прячется: выбор сервера и переключатели не теряются. -->
      <div class="slot" class:closed={!open} inert={!open}><MiniPanel bind:connected bind:mode notice="update" /></div>
      <div class="taskbar">
        <div class="center" aria-hidden="true">
          {#each [0, 1, 2, 3, 4] as n (n)}<span class="tb-icon" class:active={n === 1}></span>{/each}
        </div>
        <div class="tray">
          <button
            class="kvt"
            class:on={connected}
            class:open
            aria-expanded={open}
            aria-label={t("KVT: открыть мини-панель", "KVT: open the mini-panel")}
            title="KVT"
            onclick={() => (open = !open)}>K</button
          >
          <Icon name="wifi" size={16} />
          <span class="time">{hhmm}<br />14.11.2026</span>
        </div>
      </div>
    </div>
  </section>

  <section class="block">
    <h2>{t("Состояния", "States")}</h2>
    <div class="gallery">
      {#each gallery as g (g.label)}
        <figure>
          <figcaption class="cap">{g.label}</figcaption>
          <div class="frame"><MiniPanel {...g.props} /></div>
        </figure>
      {/each}
    </div>
  </section>
</div>

<style>
  .proto {
    height: 100%;
    padding: var(--space-6) var(--space-8) var(--space-8);
    overflow-y: auto;
  }

  .proto > :global(*) {
    max-width: 980px;
    margin-inline: auto;
  }

  .top {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: var(--space-4);
    margin-bottom: var(--space-4);
  }

  .top p {
    margin: 4px 0 0;
  }

  .seg {
    display: inline-flex;
    flex: none;
    padding: 2px;
    border: 1px solid var(--stroke);
    border-radius: var(--radius-s);
    background: var(--surface);
  }

  .seg button {
    height: 28px;
    padding: 0 var(--space-3);
    border: 0;
    border-radius: 3px;
    background: transparent;
    cursor: pointer;
  }

  .seg button.on {
    background: var(--accent-subtle);
    box-shadow: inset 0 0 0 1px var(--accent);
    color: var(--accent);
    font-weight: 600;
  }

  .block {
    margin-bottom: var(--space-8);
  }

  .block > p {
    max-width: var(--measure);
    margin: 0 0 var(--space-4);
  }

  .block > h2 {
    margin-bottom: var(--space-3);
  }

  /* Рабочий стол: обои, окошко над панелью задач и сама панель. */
  .desk {
    position: relative;
    height: 700px;
    border: 1px solid var(--stroke);
    border-radius: var(--radius-l);
    overflow: hidden;
  }

  .wall,
  .frame {
    background:
      radial-gradient(60% 70% at 25% 30%, #3a7bd5 0%, transparent 60%),
      radial-gradient(50% 60% at 75% 25%, #8e44ad 0%, transparent 60%),
      radial-gradient(60% 60% at 60% 85%, #1abc9c 0%, transparent 55%), #0f1d3a;
  }

  .wall {
    position: absolute;
    inset: 0;
  }

  /* Выезжает снизу, как окошки быстрых настроек Windows 11. */
  .slot {
    position: absolute;
    right: 12px;
    bottom: 56px;
    transition:
      opacity 180ms var(--ease),
      transform 220ms var(--ease),
      visibility 0s linear 0s;
  }

  .slot.closed {
    visibility: hidden;
    opacity: 0;
    transform: translateY(24px);
    transition:
      opacity 140ms var(--ease),
      transform 160ms var(--ease),
      visibility 0s linear 160ms;
  }

  .taskbar {
    position: absolute;
    inset: auto 0 0;
    display: flex;
    align-items: center;
    justify-content: space-between;
    height: 48px;
    padding: 0 var(--space-3);
    background: color-mix(in srgb, var(--sidebar) 82%, transparent);
    backdrop-filter: blur(20px);
    border-top: 1px solid rgb(255 255 255 / 0.08);
  }

  .center {
    position: absolute;
    left: 50%;
    display: flex;
    gap: 6px;
    transform: translateX(-50%);
  }

  .tb-icon {
    width: 32px;
    height: 32px;
    border-radius: 6px;
    background: color-mix(in srgb, var(--text) 14%, transparent);
  }

  .tb-icon.active {
    box-shadow: inset 0 -3px 0 var(--accent);
  }

  .tray {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    margin-left: auto;
    color: var(--text);
  }

  /* Значок KVT в трее: цвет плитки — состояние, как у настоящего значка. */
  .kvt {
    display: grid;
    place-items: center;
    width: 18px;
    height: 18px;
    border-radius: 4px;
    background: var(--text-3);
    color: #fff;
    border: 0;
    padding: 0;
    font-size: 11px;
    font-weight: 700;
    cursor: pointer;
    /* Кнопка в трее: подсвечена, пока панель открыта. */
    outline: 2px solid transparent;
    outline-offset: 3px;
    transition: outline-color var(--dur-fast) var(--ease);
  }

  .kvt.open {
    outline-color: color-mix(in srgb, var(--accent) 70%, transparent);
  }

  .kvt.on {
    background: #1a8a3a;
  }

  .time {
    font-size: 11px;
    line-height: 14px;
    text-align: right;
  }

  .gallery {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(376px, 1fr));
    gap: var(--space-3);
    align-items: start;
  }

  @media (max-width: 900px) {
    .proto {
      padding-inline: var(--space-4);
    }
  }

  figure {
    margin: 0;
  }

  .cap {
    margin-bottom: var(--space-2);
    color: var(--text-3);
    font-size: 12px;
  }

  .frame {
    display: flex;
    justify-content: center;
    padding: var(--space-2);
    border-radius: var(--radius-l);
  }
</style>
