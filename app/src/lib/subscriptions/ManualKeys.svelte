<script lang="ts">
  // Ключи, добавленные вручную: каждый правится и удаляется отдельно. Какой ключ
  // сейчас правится или ждёт подтверждения — в `ui` (общее для всех карточек).
  import { slide } from "svelte/transition";
  import { t } from "../i18n";
  import Flag from "../Flag.svelte";
  import ServerName from "../ServerName.svelte";
  import { editServer, removeServer, type ManualKey } from "../api";
  import { protocolTitle } from "./format";
  import type { ListUi } from "./ui.svelte";

  let {
    keys,
    ui,
    act,
    reload,
  }: {
    keys: ManualKey[];
    ui: ListUi;
    act: (fn: () => Promise<unknown>) => Promise<void>;
    reload: () => Promise<void>;
  } = $props();

  const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

  let editName = $state("");
  let editLink = $state("");
  let saving = $state(false);
  let editError = $state<string | null>(null);

  function startEdit(k: ManualKey) {
    ui.editing = k.key;
    editName = k.name;
    editLink = "";
    editError = null;
    ui.confirmKey = null;
  }

  async function saveEdit(key: string) {
    saving = true;
    editError = null;
    try {
      await editServer(key, editName, editLink.trim() || null);
      ui.editing = null;
      await reload();
    } catch (e) {
      // Ошибка — у формы, а не над всей страницей: форма остаётся открытой.
      editError = message(e);
    } finally {
      saving = false;
    }
  }
</script>

<ul class="keys">
  {#each keys as k (k.key)}
    <li class="key">
      <div class="key-row">
        <Flag code={k.flag} />
        <div class="key-text">
          <span class="key-name"><ServerName name={k.title} /></span>
          <span class="caption">{protocolTitle(k.protocol)}{k.transport !== "tcp" ? ` · ${k.transport.toUpperCase()}` : ""}</span>
        </div>
        <div class="actions">
          {#if ui.confirmKey === k.key}
            <span class="caption appear">{t("Удалить ключ?", "Delete the key?")}</span>
            <button
              class="btn danger"
              onclick={() => act(() => removeServer(k.key)).then(() => (ui.confirmKey = null))}
            >
              {t("Удалить", "Delete")}
            </button>
            <button class="btn" onclick={() => (ui.confirmKey = null)}>{t("Отмена", "Cancel")}</button>
          {:else if ui.editing !== k.key}
            <button class="btn" onclick={() => startEdit(k)} aria-label={t(`Изменить ${k.name}`, `Edit ${k.name}`)}>{t("Изменить", "Edit")}</button>
            <button
              class="btn subtle"
              onclick={() => ((ui.confirmKey = k.key), (ui.editing = null))}
              aria-label={t(`Удалить ${k.name}`, `Delete ${k.name}`)}
            >
              {t("Удалить", "Delete")}
            </button>
          {/if}
        </div>
      </div>

      {#if ui.editing === k.key}
        <form
          class="editor"
          transition:slide={{ duration: 150 }}
          onsubmit={(e) => {
            e.preventDefault();
            void saveEdit(k.key);
          }}
        >
          <label for="name-{k.key}">{t("Название", "Name")}</label>
          <input id="name-{k.key}" bind:value={editName} maxlength="120" autocomplete="off" />
          <label for="link-{k.key}">{t("Новая ссылка", "New link")}</label>
          <textarea
            id="link-{k.key}"
            bind:value={editLink}
            rows="2"
            spellcheck="false"
            placeholder={t("vless://… — оставьте пустым, чтобы ключ остался прежним", "vless://… — leave empty to keep the current key")}
          ></textarea>
          <p class="caption">
            {t("Текущая ссылка не показывается: в ней пароль или UUID сервера. Если название пустое, возьмётся из новой ссылки.", "The current link isn't shown: it contains the server's password or UUID. If the name is empty, it's taken from the new link.")}
          </p>
          {#if editError}
            <p class="error-text appear">{editError}</p>
          {/if}
          <div class="editor-actions">
            <button type="submit" class="btn btn-primary" class:busy={saving} disabled={saving}>
              {t("Сохранить", "Save")}
            </button>
            <button type="button" class="btn" disabled={saving} onclick={() => (ui.editing = null)}>
              {t("Отмена", "Cancel")}
            </button>
          </div>
        </form>
      {/if}
    </li>
  {/each}
</ul>

<style>
  .editor input,
  .editor textarea {
    width: 100%;
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--stroke);
    border-bottom-color: var(--text-3);
    border-radius: var(--radius-s);
    background: var(--surface);
    user-select: text;
    transition: border-color var(--dur-fast) var(--ease);
  }

  .editor input {
    height: 32px;
    font-family: var(--font), "Segoe UI Emoji";
  }

  /* Как в Windows 11: снизу акцентная линия, высота поля не меняется. */
  .editor input:focus,
  .editor textarea:focus {
    outline: none;
    border-bottom-color: var(--accent);
    box-shadow: inset 0 -1px 0 var(--accent);
  }

  .caption {
    margin: 0;
  }

  /* Ключи ручной группы — строками под заголовком карточки. */
  .keys {
    display: flex;
    flex-direction: column;
    margin: 0 calc(-1 * var(--space-2));
    padding: 0;
    list-style: none;
  }

  .key {
    padding: var(--space-2);
    border-top: 1px solid var(--stroke);
  }

  .key-row {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    min-height: 32px;
  }

  .key-text {
    display: flex;
    flex: 1;
    flex-direction: column;
    min-width: 0;
  }

  .key-name {
    overflow: hidden;
    font-family: var(--font), "Segoe UI Emoji";
    white-space: nowrap;
    text-overflow: ellipsis;
  }

  .key-text .caption {
    overflow: hidden;
    white-space: nowrap;
    text-overflow: ellipsis;
  }

  .editor {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    max-width: 560px;
    padding: var(--space-3) 0 var(--space-2) calc(20px + var(--space-3));
  }

  .editor label {
    font-size: 12px;
    color: var(--text-2);
  }

  .editor textarea {
    font: 12px/18px var(--mono);
    resize: vertical;
  }

  .editor-actions {
    display: flex;
    gap: var(--space-2);
    margin-top: var(--space-1);
  }

  .error-text {
    margin: 0;
    color: var(--danger);
  }

  .actions {
    display: flex;
    flex: none;
    align-items: center;
    gap: var(--space-2);
  }

  .btn.subtle {
    border-color: transparent;
    background: transparent;
    color: var(--text-2);
  }

  .btn.subtle:hover {
    background: var(--surface-hover);
    color: var(--danger);
  }

  .btn.danger {
    border-color: transparent;
    background: var(--danger);
    color: var(--accent-text);
  }

  .btn.danger:hover {
    background: var(--danger);
    opacity: 0.9;
  }

  @container main (max-width: 620px) {
    .actions {
      flex-wrap: wrap;
    }
  }
</style>
