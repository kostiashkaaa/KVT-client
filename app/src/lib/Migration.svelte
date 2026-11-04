<script lang="ts">
  import Icon from "./Icon.svelte";
  import {
    migrateImport,
    migratePickFolder,
    migrateScan,
    type MigrationPreview,
    type MigrationReport,
  } from "./api";

  let found = $state<MigrationPreview[] | null>(null);
  let scanning = $state(false);
  let importing = $state(false);
  let error = $state<string | null>(null);
  let report = $state<MigrationReport | null>(null);
  /** Выбранные клиенты (по папке с данными). */
  let chosen = $state<string[]>([]);
  let withServers = $state(true);

  const importable = (p: MigrationPreview) => p.subscriptions.length > 0 || p.servers.length > 0;

  function choose(list: MigrationPreview[]) {
    found = list;
    chosen = list.filter(importable).map((p) => p.location);
  }

  async function scan() {
    scanning = true;
    error = null;
    report = null;
    try {
      choose(await migrateScan());
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      scanning = false;
    }
  }

  async function pick() {
    error = null;
    report = null;
    try {
      const list = await migratePickFolder();
      if (list) choose(list);
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  async function run() {
    importing = true;
    error = null;
    try {
      report = await migrateImport(chosen, withServers);
      found = null;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      importing = false;
    }
  }

  function toggle(location: string, on: boolean) {
    chosen = on ? [...chosen, location] : chosen.filter((l) => l !== location);
  }

  const selected = $derived(found?.filter((p) => chosen.includes(p.location)) ?? []);
  const serversCount = $derived(selected.reduce((n, p) => n + p.servers.length, 0));

  function plural(n: number, one: string, few: string, many: string): string {
    const d = n % 10;
    const dd = n % 100;
    if (d === 1 && dd !== 11) return one;
    if (d >= 2 && d <= 4 && (dd < 12 || dd > 14)) return few;
    return many;
  }

  const subs = (n: number) => `${n} ${plural(n, "подписка", "подписки", "подписок")}`;
  const servers = (n: number) => `${n} ${plural(n, "сервер", "сервера", "серверов")}`;
</script>

<section class="card block" aria-labelledby="migrate-title">
  <div class="row">
    <div>
      <h2 id="migrate-title">Перенести из другого клиента</h2>
      <p class="muted">
        Найдёт на компьютере v2rayN, Throne, NekoRay и Hiddify и перенесёт подписки и серверы, добавленные вручную.
        Данные этих программ только читаются — в них ничего не меняется.
      </p>
    </div>
    <div class="actions">
      <button class="btn" class:busy={scanning} disabled={scanning || importing} onclick={scan}>
        <Icon name="refresh" size={16} />Найти
      </button>
      <button class="btn" disabled={scanning || importing} onclick={pick}>Указать папку</button>
    </div>
  </div>

  {#if error}
    <p class="error-text appear">{error}</p>
  {/if}

  {#if report}
    <div class="verdict appear" role="status">
      <strong>Перенос завершён</strong>
      <ul>
        {#if report.loaded > 0}<li>Загружено подписок: {report.loaded}</li>{/if}
        {#if report.pending > 0}
          <li>
            Сохранено, но пока не загрузилось: {report.pending}. Сайт провайдера может быть недоступен без VPN —
            подключитесь и нажмите «Обновить» у подписки.
          </li>
        {/if}
        {#if report.existing > 0}<li>Уже были в KVT: {report.existing}</li>{/if}
        {#if report.servers > 0}<li>Серверов в группе «Добавлено вручную»: {report.servers}</li>{/if}
        {#if report.loaded + report.pending + report.servers === 0 && report.existing === 0}
          <li>Переносить оказалось нечего.</li>
        {/if}
      </ul>
    </div>
  {/if}

  {#if found}
    {#if found.length === 0}
      <p class="caption appear">
        Ничего не нашлось. Если программа лежит в другом месте, нажмите «Указать папку» и выберите её папку.
      </p>
    {:else}
      <ul class="clients appear">
        {#each found as p (p.location)}
          {@const can = importable(p)}
          <li class:off={!can}>
            <label class="head">
              <input
                type="checkbox"
                disabled={!can || importing}
                checked={chosen.includes(p.location)}
                onchange={(e) => toggle(p.location, e.currentTarget.checked)}
              />
              <span class="name">{p.title}</span>
              <span class="caption path" title={p.location}>{p.location}</span>
            </label>
            {#if p.note}
              <p class="caption">{p.note}</p>
            {/if}
            {#if p.subscriptions.length > 0}
              <p class="caption">
                {subs(p.subscriptions.length)}: {p.subscriptions.map((s) => `${s.name} (${s.host})`).join(", ")}
              </p>
            {/if}
            {#if p.servers.length > 0}
              <p class="caption">
                {servers(p.servers.length)} вручную: {p.servers.map((s) => `${s.name} — ${s.protocol}`).join(", ")}
              </p>
            {/if}
            {#if p.skipped.length > 0}
              <p class="caption">
                Не перенесётся: {p.skipped.map((s) => `${s.count} — ${s.reason}`).join("; ")}
              </p>
            {/if}
            {#if can === false && !p.note}
              <p class="caption">Подписок и серверов не найдено.</p>
            {/if}
          </li>
        {/each}
      </ul>

      {#if found.some(importable)}
        <div class="go">
          {#if serversCount > 0}
            <label class="check">
              <input type="checkbox" bind:checked={withServers} disabled={importing} />
              Перенести и серверы, добавленные вручную ({serversCount})
            </label>
          {/if}
          <button
            class="btn btn-primary"
            class:busy={importing}
            disabled={importing || selected.length === 0}
            onclick={run}
          >
            Перенести
          </button>
        </div>
        <p class="caption">
          Серверы из подписок переносятся вместе с подпиской: KVT загрузит их сам и будет обновлять.
        </p>
      {/if}
    {/if}
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

  .actions {
    display: flex;
    flex: none;
    gap: var(--space-2);
  }

  .caption {
    margin: 0;
  }

  .error-text {
    margin: 0;
    color: var(--danger);
  }

  .verdict {
    padding: var(--space-3) var(--space-4);
    border-left: 3px solid var(--ok);
    border-radius: var(--radius-s);
    background: var(--ok-subtle);
  }

  .verdict ul {
    margin: var(--space-1) 0 0;
    padding-left: var(--space-5);
  }

  .clients {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    margin: 0;
    padding: 0;
    list-style: none;
  }

  .clients li {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    padding: var(--space-3);
    border: 1px solid var(--stroke);
    border-radius: var(--radius-s);
  }

  .clients li.off .name {
    color: var(--text-2);
  }

  .head {
    display: flex;
    align-items: baseline;
    gap: var(--space-2);
    min-width: 0;
    cursor: pointer;
  }

  .head input {
    flex: none;
    align-self: center;
  }

  .name {
    flex: none;
    font-weight: 600;
  }

  .path {
    overflow: hidden;
    white-space: nowrap;
    text-overflow: ellipsis;
  }

  .go {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: var(--space-4);
  }

  .check {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    cursor: pointer;
  }

  @media (max-width: 720px) {
    .row,
    .go {
      flex-direction: column;
      align-items: stretch;
    }
  }
</style>
