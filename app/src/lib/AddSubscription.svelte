<script lang="ts">
  import Icon from "./Icon.svelte";

  let {
    onadd,
    busy,
    oncancel,
  }: {
    onadd: (body: string) => void;
    busy: boolean;
    /** Есть — форма открыта поверх списка (кнопка «+»), её можно закрыть. */
    oncancel?: () => void;
  } = $props();
  let value = $state("");

  function focus(node: HTMLTextAreaElement) {
    if (oncancel) node.focus();
  }

  // Буфер обмена читается только по нажатию — никакого фонового чтения.
  async function paste() {
    try {
      value = await navigator.clipboard.readText();
    } catch {
      /* доступ к буферу запрещён — пользователь вставит вручную */
    }
  }
</script>

<section class="card empty" class:dialog={!!oncancel}>
  <div class="icon" aria-hidden="true"><Icon name="shield" size={32} /></div>
  <h2 id="add-title">{oncancel ? "Добавить подписку или ключ" : "Добавьте подписку"}</h2>
  <p class="muted">
    Вставьте ссылку на подписку (https://…), ссылки на серверы (vless://, vmess://, trojan://, ss://, hy2://, tuic://, anytls://) или
    содержимое подписки.
  </p>

  <textarea
    bind:value
    rows="3"
    spellcheck="false"
    autocomplete="off"
    placeholder="https://… или vless://…"
    aria-label="Ссылки или подписка"
    use:focus
    onkeydown={(e) => {
      if (e.key === "Escape" && oncancel) oncancel();
      if (e.key === "Enter" && e.ctrlKey && value.trim() && !busy) onadd(value);
    }}
  ></textarea>

  <div class="actions">
    {#if oncancel}
      <button class="btn" disabled={busy} onclick={oncancel}>Отмена</button>
    {/if}
    <button class="btn" disabled={busy} onclick={paste}><Icon name="paste" size={16} />Вставить из буфера</button>
    <button
      class="btn btn-primary"
      class:busy
      disabled={!value.trim() || busy}
      title="Ctrl+Enter"
      onclick={() => onadd(value)}
    >
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

  .dialog {
    width: min(560px, calc(100vw - 32px));
    padding: var(--space-6);
    box-shadow: 0 8px 32px rgb(0 0 0 / 0.28);
    animation: pop var(--dur) var(--ease) backwards;
  }

  @keyframes pop {
    from {
      opacity: 0;
      transform: translateY(8px) scale(0.98);
    }
  }

  p {
    max-width: 440px;
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
    transition: border-color var(--dur-fast) var(--ease);
  }

  /* Как в Windows 11: снизу акцентная линия, высота поля не меняется. */
  textarea:focus {
    outline: none;
    border-bottom-color: var(--accent);
    box-shadow: inset 0 -1px 0 var(--accent);
  }

  .actions {
    display: flex;
    flex-wrap: wrap;
    justify-content: center;
    gap: var(--space-2);
  }
</style>
