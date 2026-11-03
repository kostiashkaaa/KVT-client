<script lang="ts">
  import Icon from "./Icon.svelte";

  let { onadd, busy }: { onadd: (body: string) => void; busy: boolean } = $props();
  let value = $state("");

  // Буфер обмена читается только по нажатию — никакого фонового чтения.
  async function paste() {
    try {
      value = await navigator.clipboard.readText();
    } catch {
      /* доступ к буферу запрещён — пользователь вставит вручную */
    }
  }
</script>

<section class="card empty">
  <div class="icon" aria-hidden="true"><Icon name="shield" size={32} /></div>
  <h2>Добавьте подписку</h2>
  <p class="muted">
    Вставьте ссылку на подписку (https://…), ссылки на серверы (vless://, trojan://, ss://, hy2://) или
    содержимое подписки.
  </p>

  <textarea
    bind:value
    rows="3"
    spellcheck="false"
    autocomplete="off"
    placeholder="https://… или vless://…"
    aria-label="Ссылки или подписка"
  ></textarea>

  <div class="actions">
    <button class="btn" onclick={paste}><Icon name="paste" size={16} />Вставить из буфера</button>
    <button class="btn btn-primary" disabled={!value.trim() || busy} onclick={() => onadd(value)}>
      <Icon name="plus" size={16} />Добавить
    </button>
  </div>
</section>

<style>
  .empty {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-8) var(--space-6);
    text-align: center;
  }

  .icon {
    color: var(--accent);
  }

  p {
    max-width: 420px;
    margin: 0;
  }

  textarea {
    width: 100%;
    max-width: 520px;
    padding: var(--space-2) var(--space-3);
    border: 1px solid var(--stroke);
    border-bottom-color: var(--text-3);
    border-radius: var(--radius-s);
    background: var(--surface);
    font: 12px/18px var(--mono);
    resize: vertical;
    user-select: text;
  }

  textarea:focus {
    outline: none;
    border-bottom: 2px solid var(--accent);
  }

  .actions {
    display: flex;
    gap: var(--space-2);
  }
</style>
