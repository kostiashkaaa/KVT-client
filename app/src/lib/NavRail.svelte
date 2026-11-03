<script lang="ts" module>
  export type Page = "home" | "subscriptions" | "routing" | "zapret" | "diagnostics" | "journal" | "settings";
</script>

<script lang="ts">
  import Icon, { type IconName } from "./Icon.svelte";

  let { current = $bindable() }: { current: Page } = $props();

  const items: { id: Page; label: string; icon: IconName }[] = [
    { id: "home", label: "Главная", icon: "home" },
    { id: "subscriptions", label: "Подписки", icon: "list" },
    { id: "routing", label: "Маршрутизация", icon: "route" },
    { id: "zapret", label: "Zapret", icon: "bolt" },
    { id: "diagnostics", label: "Проверка", icon: "pulse" },
    { id: "journal", label: "Журнал", icon: "log" },
  ];
</script>

<nav aria-label="Разделы">
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
    onclick={() => (current = "settings")}
  >
    <Icon name="sliders" />
    <span>Настройки</span>
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
  }

  button:hover {
    background: var(--surface-hover);
  }

  button.active {
    background: var(--surface);
  }

  /* Индикатор выбранного раздела, как в навигации Windows 11. */
  button.active::before {
    content: "";
    position: absolute;
    left: 0;
    top: 10px;
    bottom: 10px;
    width: 3px;
    border-radius: 2px;
    background: var(--accent);
  }

  .settings {
    margin-top: auto;
  }

  @media (max-width: 720px) {
    nav {
      width: 56px;
    }
    .brand {
      justify-content: center;
      padding-inline: 0;
    }
    button span {
      display: none;
    }
    button {
      justify-content: center;
      padding: 0;
    }
  }
</style>
