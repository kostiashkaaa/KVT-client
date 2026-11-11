<script lang="ts">
  import { count, t } from "./i18n";
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

  const subs = (n: number) => count(n, ["подписка", "подписки", "подписок"], ["subscription", "subscriptions"]);
  const servers = (n: number) => count(n, ["сервер", "сервера", "серверов"], ["server", "servers"]);
</script>

<section class="card block" aria-labelledby="migrate-title">
  <div class="row">
    <div>
      <h2 id="migrate-title">{t("Перенести из другого клиента", "Import from another client")}</h2>
      <p class="muted">
        {t("Найдёт на компьютере v2rayN, Throne, NekoRay и Hiddify и перенесёт подписки и серверы, добавленные вручную. Данные этих программ только читаются — в них ничего не меняется.", "Finds v2rayN, Throne, NekoRay and Hiddify on this computer and imports subscriptions and manually added servers. Those apps' data is only read — nothing in them changes.")}
      </p>
    </div>
    <div class="actions">
      <button class="btn" class:busy={scanning} disabled={scanning || importing} onclick={scan}>
        <Icon name="refresh" size={16} />{t("Найти", "Find")}
      </button>
      <button class="btn" disabled={scanning || importing} onclick={pick}>{t("Указать папку", "Choose folder")}</button>
    </div>
  </div>

  {#if error}
    <p class="error-text appear">{error}</p>
  {/if}

  {#if report}
    <div class="verdict appear" role="status">
      <strong>{t("Перенос завершён", "Import complete")}</strong>
      <ul>
        {#if report.loaded > 0}<li>{t(`Загружено подписок: ${report.loaded}`, `Subscriptions loaded: ${report.loaded}`)}</li>{/if}
        {#if report.pending > 0}
          <li>
            {t(`Сохранено, но пока не загрузилось: ${report.pending}. Сайт провайдера может быть недоступен без VPN — подключитесь и нажмите «Обновить» у подписки.`, `Saved but not loaded yet: ${report.pending}. The provider's site may be unreachable without the VPN — connect and press “Update” on the subscription.`)}
          </li>
        {/if}
        {#if report.existing > 0}<li>{t(`Уже были в KVT: ${report.existing}`, `Already in KVT: ${report.existing}`)}</li>{/if}
        {#if report.servers > 0}<li>{t(`Серверов в группе «Добавлено вручную»: ${report.servers}`, `Servers in the “Added manually” group: ${report.servers}`)}</li>{/if}
        {#if report.loaded + report.pending + report.servers === 0 && report.existing === 0}
          <li>{t("Переносить оказалось нечего.", "There was nothing to import.")}</li>
        {/if}
      </ul>
    </div>
  {/if}

  {#if found}
    {#if found.length === 0}
      <p class="caption appear">
        {t("Ничего не нашлось. Если программа лежит в другом месте, нажмите «Указать папку» и выберите её папку.", "Nothing found. If the app is somewhere else, press “Choose folder” and select its folder.")}
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
                {t(`${servers(p.servers.length)} вручную: ${p.servers.map((s) => `${s.name} — ${s.protocol}`).join(", ")}`, `${servers(p.servers.length)} added manually: ${p.servers.map((s) => `${s.name} — ${s.protocol}`).join(", ")}`)}
              </p>
            {/if}
            {#if p.skipped.length > 0}
              <p class="caption">
                {t(`Не перенесётся: ${p.skipped.map((s) => `${s.count} — ${s.reason}`).join("; ")}`, `Won't be imported: ${p.skipped.map((s) => `${s.count} — ${s.reason}`).join("; ")}`)}
              </p>
            {/if}
            {#if can === false && !p.note}
              <p class="caption">{t("Подписок и серверов не найдено.", "No subscriptions or servers found.")}</p>
            {/if}
          </li>
        {/each}
      </ul>

      {#if found.some(importable)}
        <div class="go">
          {#if serversCount > 0}
            <label class="check">
              <input type="checkbox" bind:checked={withServers} disabled={importing} />
              {t(`Перенести и серверы, добавленные вручную (${serversCount})`, `Also import manually added servers (${serversCount})`)}
            </label>
          {/if}
          <button
            class="btn btn-primary"
            class:busy={importing}
            disabled={importing || selected.length === 0}
            onclick={run}
          >
            {t("Перенести", "Import")}
          </button>
        </div>
        <p class="caption">
          {t("Серверы из подписок переносятся вместе с подпиской: KVT загрузит их сам и будет обновлять.", "Servers from subscriptions come with the subscription: KVT loads and updates them itself.")}
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
