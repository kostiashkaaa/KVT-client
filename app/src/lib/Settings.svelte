<script lang="ts">
  import Icon from "./Icon.svelte";
  import { leakTest, type CheckResult, type LeakReport } from "./api";

  let { killSwitch = $bindable(), connected }: { killSwitch: boolean; connected: boolean } = $props();

  let report = $state<LeakReport | null>(null);
  let running = $state(false);

  async function run() {
    running = true;
    try {
      report = await leakTest(connected);
    } finally {
      running = false;
    }
  }

  const rows = $derived<[string, CheckResult][]>(
    report
      ? [
          ["Маршрут IPv4", report.ipv4Route],
          ["Маршрут IPv6", report.ipv6Route],
          ["DNS", report.dns],
        ]
      : [],
  );
</script>

<section class="card block">
  <div class="row">
    <div>
      <h2>Kill switch</h2>
      <p class="muted">
        Если VPN оборвётся, интернет будет закрыт, пока вы не нажмёте «Отключить». Ни один запрос не уйдёт мимо
        туннеля. Если сама служба KVT остановится, Windows снимет блокировку автоматически.
      </p>
    </div>
    <label class="switch">
      <input type="checkbox" role="switch" bind:checked={killSwitch} />
      <span aria-hidden="true"></span>
      <span class="sr">Kill switch</span>
    </label>
  </div>
  <p class="caption">Изменение применится при следующем подключении.</p>
</section>

<section class="card block">
  <div class="row">
    <div>
      <h2>Проверка утечек</h2>
      <p class="muted">
        Ищет на компьютере открытые прокси других VPN-клиентов, проверяет маршруты IPv4/IPv6 и DNS. Почти всё
        проверяется локально — в интернет уходит один DNS-запрос.
      </p>
    </div>
    <button class="btn" disabled={running} onclick={run}>
      <Icon name="shield" size={16} />{running ? "Проверка…" : "Проверить"}
    </button>
  </div>

  {#if report}
    <ul class="results">
      {#if report.openProxies.length === 0}
        <li class="ok">
          <strong>Открытые прокси</strong>
          <span>Не найдено. Программы на компьютере не смогут узнать адрес VPN-сервера через локальный порт.</span>
        </li>
      {:else}
        {#each report.openProxies as p (p.port)}
          <li class="warning">
            <strong>Открытый SOCKS5 на порту {p.port}</strong>
            <span>
              {p.process ?? "Неизвестная программа"} принимает подключения без пароля: любое приложение может узнать
              через него IP вашего VPN-сервера.{#if p.knownScanPort}
                Этот порт из списка, по которому ищут прокси.{/if}
              Включите в той программе пароль для локального прокси или используйте режим TUN.
            </span>
          </li>
        {/each}
      {/if}
      {#each rows as [label, r] (label)}
        <li class={r.verdict}>
          <strong>{label}</strong>
          <span>{r.detail}</span>
        </li>
      {/each}
    </ul>
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
    max-width: 560px;
  }

  .caption {
    margin: 0;
  }

  /* Переключатель в стиле Windows 11. */
  .switch {
    position: relative;
    flex: none;
    width: 40px;
    height: 20px;
    margin-top: var(--space-1);
    cursor: pointer;
  }

  .switch input {
    position: absolute;
    inset: 0;
    opacity: 0;
    margin: 0;
    cursor: pointer;
  }

  .switch span[aria-hidden] {
    position: absolute;
    inset: 0;
    border: 1px solid var(--text-2);
    border-radius: 10px;
    transition: background 120ms var(--ease);
  }

  .switch span[aria-hidden]::after {
    content: "";
    position: absolute;
    top: 4px;
    left: 4px;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: var(--text-2);
    transition: transform 120ms var(--ease);
  }

  .switch input:checked + span {
    border-color: var(--accent);
    background: var(--accent);
  }

  .switch input:checked + span::after {
    background: var(--accent-text);
    transform: translateX(20px);
  }

  .switch input:focus-visible + span {
    box-shadow: var(--focus);
  }

  .sr {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip: rect(0 0 0 0);
  }

  .results {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    margin: 0;
    padding: 0;
    list-style: none;
  }

  .results li {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: var(--space-2) var(--space-3);
    border-left: 3px solid var(--stroke-strong);
    border-radius: var(--radius-s);
    background: var(--bg);
  }

  .results li.ok {
    border-left-color: var(--ok);
  }

  .results li.warning {
    border-left-color: var(--warn);
    background: var(--warn-subtle);
  }
</style>
