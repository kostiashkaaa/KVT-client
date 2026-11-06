<script lang="ts">
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
    { id: "vpn", title: "VPN", text: "Заблокированное — через VPN-сервер, российские сайты — напрямую." },
    { id: "hybrid", title: "Гибрид", text: "YouTube и Discord — через zapret без VPN, Telegram Desktop — через прокси, остальное заблокированное — через VPN." },
    { id: "zapret", title: "Zapret", text: "Без VPN-сервера: обход замедления YouTube и Discord, Telegram Desktop — через прокси." },
  ];
</script>

<section class="card onboarding appear" aria-labelledby="onboarding-title">
  <div class="head">
    <p class="caption steps" aria-label="Шаг {step} из 3">
      {#each [1, 2, 3] as n (n)}
        <span class="dot" class:done={n < step || finished} class:current={n === step && !finished}></span>
      {/each}
      Шаг {step} из 3
    </p>
    {#if !finished}
      <button class="skip" onclick={ondone}>Пропустить</button>
    {/if}
  </div>

  {#if step === 1}
    <h2 id="onboarding-title">Добавьте подписку или ключ</h2>
    <p class="muted">
      Ссылку на подписку (https://…) или ключ (vless://, vmess://, trojan://, hy2://…) даёт ваш VPN-провайдер. Пользуетесь
      v2rayN, Hiddify или NekoRay — KVT перенесёт подписки из них.
    </p>
    <div class="actions">
      <button class="btn btn-primary" onclick={onadd}>Вставить ссылку</button>
      <button class="btn" onclick={onmigrate}>Перенести из другого клиента</button>
      <button class="btn link" onclick={() => ((mode = "zapret"), (step = 2))}>У меня нет VPN — только zapret</button>
    </div>
  {:else if step === 2}
    <h2 id="onboarding-title">Выберите режим</h2>
    <div class="modes" role="radiogroup" aria-label="Режим работы">
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
    <p class="caption">Режим можно сменить в любой момент — на главной и в меню трея.</p>
    <div class="actions">
      <button class="btn btn-primary" onclick={() => (step = 3)}>Дальше</button>
    </div>
  {:else if !finished}
    <h2 id="onboarding-title">Подключитесь</h2>
    <p class="muted">
      KVT поднимет защищённое соединение и проверит, что сайты открываются. Закрытое окно не выключает VPN: KVT
      остаётся в трее, оттуда же можно сменить сервер и режим.
    </p>
    <div class="actions">
      <button class="btn btn-primary" disabled={busy} onclick={onconnect}>
        {#if busy}<span class="spinner" aria-hidden="true"></span>{/if}
        {busy ? "Подключение…" : "Подключить"}
      </button>
      <button class="btn" onclick={() => (step = 2)}>Назад</button>
    </div>
  {:else}
    <h2 id="onboarding-title">Готово</h2>
    <p class="muted">
      KVT подключён. Если что-то не открывается — «Почему не работает?» на главной найдёт причину. Подсказки можно
      показать снова в «Настройках».
    </p>
    <div class="actions">
      <button class="btn btn-primary" onclick={ondone}>Понятно</button>
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
