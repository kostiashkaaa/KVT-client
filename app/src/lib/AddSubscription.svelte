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

  // Подсказка «что найдено» — грубый подсчёт для глаз, разбирает вставку Rust.
  const APP = /^(happ|incy|v2raytun|hiddify|v2rayng|v2box|streisand|clash|sing-box):\/\//i;
  const KEY = /^(vless|vmess|trojan|ss|hy2|hysteria2|tuic|anytls|socks5?|socks5h):\/\//i;
  /** HTTP-прокси: логин в адресе и пустой путь (у подписки путь с токеном есть всегда). */
  const HTTP_PROXY = /^https?:\/\/[^\s/@]+@[^\s/?#]+\/?([?#]|$)/i;
  const found = $derived.by(() => {
    const text = value.trim();
    if (!text) return { urls: 0, text: "" };
    if (/^[[{]/.test(text)) return { urls: 0, text: "Похоже на конфиг в JSON" };
    if (!text.includes("://")) return { urls: 0, text: "Похоже на подписку в base64" };
    let urls = 0;
    let keys = 0;
    for (const line of text.split(/\r?\n/)) {
      const l = line.trim();
      if (KEY.test(l) || HTTP_PROXY.test(l)) keys++;
      else
        for (const t of l.split(/\s+/)) {
          const token = t.replace(/^["'«<(\[]+/, "");
          if (/^https?:\/\/\S/i.test(token) || APP.test(token)) urls++;
        }
    }
    const parts = [];
    if (urls) parts.push(plural(urls, "ссылка на подписку", "ссылки на подписки", "ссылок на подписки"));
    if (keys) parts.push(plural(keys, "ключ", "ключа", "ключей"));
    return { urls, text: parts.length ? `Найдено: ${parts.join(", ")}` : "Не вижу ни ссылки на подписку, ни ключей" };
  });

  function plural(n: number, one: string, few: string, many: string): string {
    const d = n % 10;
    const dd = n % 100;
    const word = d === 1 && dd !== 11 ? one : d >= 2 && d <= 4 && (dd < 12 || dd > 14) ? few : many;
    return `${n} ${word}`;
  }
</script>

<section class="card empty" class:dialog={!!oncancel}>
  <div class="icon" aria-hidden="true"><Icon name="shield" size={32} /></div>
  <h2 id="add-title">{oncancel ? "Добавить подписку или ключ" : "Добавьте подписку"}</h2>
  <p class="muted">
    Ссылка на подписку (https://…), ключи серверов или конфиг Xray / sing-box. Можно несколько сразу и вместе с
    текстом из письма провайдера — KVT найдёт нужное.
  </p>

  <textarea
    bind:value
    rows="3"
    spellcheck="false"
    autocomplete="off"
    placeholder="https://… или vless://…"
    disabled={busy}
    aria-label="Ссылки или подписка"
    use:focus
    onkeydown={(e) => {
      if (e.key === "Escape" && oncancel) oncancel();
      if (e.key === "Enter" && e.ctrlKey && value.trim() && !busy) onadd(value);
    }}
  ></textarea>

  <p class="caption found" aria-live="polite">
    {#if busy && found.urls > 1}
      Загружаю подписки по очереди — к одному провайдеру KVT ходит с паузой, это может занять минуту.
    {:else if found.text}
      {found.text}
    {:else}
      VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS, SOCKS5, HTTP-прокси
    {/if}
  </p>

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

  .found {
    max-width: 520px;
    min-height: 18px;
    margin-top: calc(-1 * var(--space-1));
  }

  .actions {
    display: flex;
    flex-wrap: wrap;
    justify-content: center;
    gap: var(--space-2);
  }
</style>
