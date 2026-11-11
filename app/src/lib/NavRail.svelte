<script lang="ts" module>
  export type Page = "home" | "subscriptions" | "routing" | "zapret" | "diagnostics" | "journal" | "settings";
</script>

<script lang="ts">
  import { t } from "./i18n";
  import Icon, { type IconName } from "./Icon.svelte";
  import { update } from "./update.svelte";
  import { tapSettings } from "./theme.svelte";

  let { current = $bindable() }: { current: Page } = $props();

  const items: { id: Page; label: string; icon: IconName }[] = [
    { id: "home", label: t("Главная", "Home"), icon: "home" },
    { id: "subscriptions", label: t("Подписки", "Subscriptions"), icon: "list" },
    { id: "routing", label: t("Маршрутизация", "Routing"), icon: "route" },
    { id: "zapret", label: "Zapret", icon: "bolt" },
    { id: "diagnostics", label: t("Проверка", "Check"), icon: "pulse" },
    { id: "journal", label: t("Журнал", "Log"), icon: "log" },
  ];
</script>

<nav aria-label={t("Разделы", "Sections")}>
  <div class="brand">
    <!-- Тот же знак, что и app-icon.svg. -->
    <svg viewBox="0 0 1024 1024" width="28" height="28" role="img" aria-label="KVT">
      <rect width="1024" height="1024" rx="224" fill="#005fb8" />
      <path d="M348 276v472" fill="none" stroke="#fff" stroke-width="104" stroke-linecap="round" />
      <path
        d="M706 276 472 512l234 236"
        fill="none"
        stroke="#60cdff"
        stroke-width="104"
        stroke-linecap="round"
        stroke-linejoin="round"
      />
    </svg>
  </div>
  <ul>
    {#each items as item (item.id)}
      <li>
        <button
          class:active={current === item.id}
          aria-current={current === item.id ? "page" : undefined}
          title={item.label}
          onclick={() => (current = item.id)}
        >
          <Icon name={item.icon} />
          <span>{item.label}</span>
        </button>
      </li>
    {/each}
  </ul>
  <button
    class="settings"
    class:active={current === "settings"}
    aria-current={current === "settings" ? "page" : undefined}
    title={update.version ? t(`Настройки · вышла KVT ${update.version}`, `Settings · KVT ${update.version} is out`) : t("Настройки", "Settings")}
    onclick={() => {
      current = "settings";
      tapSettings();
    }}
  >
    <span class="icon">
      <Icon name="settings" />
      {#if update.version}<i class="badge" aria-hidden="true"></i>{/if}
    </span>
    <span>{t("Настройки", "Settings")}{#if update.version}<b class="sr"> {t("— вышла новая версия", "— a new version is out")}</b>{/if}</span>
  </button>
</nav>

<style>
  nav {
    display: flex;
    flex-direction: column;
    width: 220px;
    padding: var(--space-3) var(--space-2);
    background: var(--sidebar);
  }

  /* Центр знака совпадает с центром иконок разделов. */
  .brand {
    display: flex;
    padding: var(--space-1) var(--space-2) var(--space-4);
  }

  ul {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    margin: 0;
    padding: 0;
    list-style: none;
  }

  button {
    position: relative;
    display: flex;
    align-items: center;
    gap: var(--space-3);
    width: 100%;
    height: 36px;
    padding: 0 var(--space-3);
    border: 0;
    border-radius: var(--radius-s);
    background: transparent;
    text-align: left;
    cursor: pointer;
    transition: background-color var(--dur-fast) var(--ease);
  }

  button :global(svg) {
    flex: none;
  }

  button:hover {
    background: var(--surface-hover);
  }

  button:active {
    background: var(--surface-pressed);
  }

  button.active {
    background: var(--surface);
  }

  /* Индикатор выбранного раздела, как в навигации Windows 11: вытягивается из центра. */
  button::before {
    content: "";
    position: absolute;
    left: 0;
    top: 10px;
    bottom: 10px;
    width: 3px;
    border-radius: 2px;
    background: var(--accent);
    opacity: 0;
    transform: scaleY(0);
    transition:
      transform var(--dur) var(--ease),
      opacity var(--dur-fast) var(--ease);
  }

  button.active::before {
    opacity: 1;
    transform: scaleY(1);
  }

  .settings {
    margin-top: auto;
  }

  /* Новая версия: красная точка на иконке «Настроек», видна и в узкой панели. */
  .icon {
    position: relative;
    display: flex;
  }

  .badge {
    position: absolute;
    top: -3px;
    right: -4px;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #e5484d;
    box-shadow: 0 0 0 2px var(--sidebar);
    animation: pop var(--dur) var(--ease);
  }

  @keyframes pop {
    from {
      transform: scale(0);
    }
  }

  .sr {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip: rect(0 0 0 0);
  }

  /* Узкое окно (в том числе у края экрана при разработке): только значки. */
  @media (max-width: 900px) {
    nav {
      width: 56px;
    }
    .brand {
      justify-content: center;
      padding-inline: 0;
    }
    /* Подпись скрыта визуально, но остаётся именем кнопки для экранного диктора. */
    button span:not(.icon) {
      position: absolute;
      width: 1px;
      height: 1px;
      overflow: hidden;
      clip: rect(0 0 0 0);
    }
    button {
      justify-content: center;
      padding: 0;
    }
  }
</style>
