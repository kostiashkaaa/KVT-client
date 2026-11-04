<script lang="ts">
  import { fade } from "svelte/transition";
  import Icon from "./Icon.svelte";
  import { diagPreview, diagSave, type DiagFile } from "./api";

  /** Кнопка «Сохранить диагностику» и окно с тем, что войдёт в архив. */
  let open = $state(false);
  let loading = $state(false);
  let saving = $state(false);
  let files = $state<DiagFile[]>([]);
  let shown = $state<string | null>(null);
  let error = $state<string | null>(null);
  let saved = $state(false);

  const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

  function size(text: string): string {
    const bytes = new TextEncoder().encode(text).length;
    if (bytes === 0) return "пусто";
    if (bytes < 1024) return `${bytes} Б`;
    return `${Math.round(bytes / 102.4) / 10} КБ`;
  }

  async function start() {
    open = true;
    loading = true;
    error = null;
    saved = false;
    shown = null;
    try {
      files = await diagPreview();
    } catch (e) {
      error = message(e);
    } finally {
      loading = false;
    }
  }

  async function save() {
    saving = true;
    error = null;
    try {
      if (await diagSave()) {
        saved = true;
      }
    } catch (e) {
      error = message(e);
    } finally {
      saving = false;
    }
  }

  function close() {
    if (saving) return;
    open = false;
  }
</script>

<button class="btn" onclick={start}><Icon name="log" size={16} />Сохранить диагностику</button>

{#if open}
  <div
    class="overlay"
    role="dialog"
    aria-modal="true"
    aria-labelledby="diag-title"
    tabindex="-1"
    transition:fade={{ duration: 150 }}
    onclick={(e) => {
      if (e.target === e.currentTarget) close();
    }}
    onkeydown={(e) => {
      if (e.key === "Escape") close();
    }}
  >
    <section class="card dialog">
      <h2 id="diag-title">Что войдёт в диагностику</h2>
      <p class="muted">
        Архив для разбора проблемы: журналы, итоги проверок и конфиг ядра. Ключи, пароли, UUID, ссылки подписок и адреса
        серверов уже скрыты — нажмите на файл, чтобы увидеть его целиком.
      </p>

      {#if loading}
        <p class="caption"><span class="spinner" aria-hidden="true"></span> Собираем…</p>
      {:else if files.length > 0}
        <ul class="files">
          {#each files as f (f.name)}
            <li>
              <button
                class="file"
                aria-expanded={shown === f.name}
                onclick={() => (shown = shown === f.name ? null : f.name)}
              >
                <span class="chev" class:open={shown === f.name}><Icon name="chevron" size={14} /></span>
                <span class="name">{f.name}</span>
                <span class="caption">{size(f.text)}</span>
              </button>
              {#if shown === f.name}
                <pre class="appear">{f.text || "(пусто)"}</pre>
              {/if}
            </li>
          {/each}
        </ul>
      {/if}

      {#if error}
        <p class="error-text appear">{error}</p>
      {/if}
      {#if saved}
        <p class="caption appear">Архив сохранён. Приложите его к сообщению об ошибке на GitHub.</p>
      {/if}

      <div class="actions">
        <button class="btn" onclick={close} disabled={saving}>{saved ? "Готово" : "Отмена"}</button>
        <button
          class="btn btn-primary"
          class:busy={saving}
          disabled={loading || saving || files.length === 0}
          onclick={save}
        >
          Сохранить…
        </button>
      </div>
    </section>
  </div>
{/if}

<style>
  .overlay {
    position: fixed;
    inset: 0;
    z-index: 10;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: var(--space-4);
    background: rgb(0 0 0 / 0.45);
  }

  .dialog {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    width: min(640px, calc(100vw - 32px));
    max-height: calc(100vh - 48px);
    padding: var(--space-6);
    box-shadow: 0 8px 32px rgb(0 0 0 / 0.28);
    animation: kvt-rise var(--dur) var(--ease) backwards;
  }

  h2,
  p {
    margin: 0;
  }

  .files {
    display: flex;
    flex-direction: column;
    min-height: 0;
    margin: 0;
    padding: 0;
    overflow-y: auto;
    border: 1px solid var(--stroke);
    border-radius: var(--radius-s);
    list-style: none;
  }

  .files li + li {
    border-top: 1px solid var(--stroke);
  }

  .file {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    width: 100%;
    padding: var(--space-2) var(--space-3);
    border: 0;
    background: transparent;
    text-align: left;
    cursor: pointer;
    transition: background-color var(--dur-fast) var(--ease);
  }

  .file:hover {
    background: var(--surface-hover);
  }

  .name {
    flex: 1;
    font-family: var(--mono);
    font-size: 12px;
  }

  .chev {
    display: inline-flex;
    color: var(--text-3);
    transform: rotate(-90deg);
    transition: transform var(--dur-fast) var(--ease);
  }

  .chev.open {
    transform: none;
  }

  pre {
    max-height: 240px;
    margin: 0;
    padding: var(--space-3);
    overflow: auto;
    border-top: 1px solid var(--stroke);
    background: var(--bg);
    font: 12px/18px var(--mono);
    white-space: pre-wrap;
    word-break: break-word;
  }

  .actions {
    display: flex;
    justify-content: flex-end;
    gap: var(--space-2);
  }
</style>
