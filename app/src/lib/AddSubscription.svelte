<script lang="ts">
  import { count, t } from "./i18n";
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
    if (/^[[{]/.test(text)) return { urls: 0, text: t("Похоже на конфиг в JSON", "Looks like a JSON config") };
    if (!text.includes("://")) return { urls: 0, text: t("Похоже на подписку в base64", "Looks like a base64 subscription") };
    let urls = 0;
    let keys = 0;
    for (const line of text.split(/\r?\n/)) {
      const l = line.trim();
      if (KEY.test(l) || HTTP_PROXY.test(l)) keys++;
      else
        for (const word of l.split(/\s+/)) {
          const token = word.replace(/^["'«<(\[]+/, "");
          if (/^https?:\/\/\S/i.test(token) || APP.test(token)) urls++;
        }
    }
    const parts = [];
    if (urls)
      parts.push(
        count(urls, ["ссылка на подписку", "ссылки на подписки", "ссылок на подписки"], ["subscription link", "subscription links"]),
      );
    if (keys) parts.push(count(keys, ["ключ", "ключа", "ключей"], ["key", "keys"]));
    return {
      urls,
      text: parts.length
        ? `${t("Найдено", "Found")}: ${parts.join(", ")}`
        : t("Не вижу ни ссылки на подписку, ни ключей", "No subscription link or keys found"),
    };
  });
</script>

<section class="card empty" class:dialog={!!oncancel}>
  <div class="icon" aria-hidden="true"><Icon name="shield" size={32} /></div>
  <h2 id="add-title">{oncancel ? t("Добавить подписку или ключ", "Add a subscription or key") : t("Добавьте подписку", "Add a subscription")}</h2>
  <p class="muted">
    {t("Ссылка на подписку (https://…), ключи серверов или конфиг Xray / sing-box. Можно несколько сразу и вместе с текстом из письма провайдера — KVT найдёт нужное.", "A subscription link (https://…), server keys or an Xray / sing-box config. You can paste several at once, even with the text of your provider's email — KVT will find what it needs.")}
  </p>

  <textarea
    bind:value
    rows="3"
    spellcheck="false"
    autocomplete="off"
    placeholder={t("https://… или vless://…", "https://… or vless://…")}
    disabled={busy}
    aria-label={t("Ссылки или подписка", "Links or subscription")}
    use:focus
    onkeydown={(e) => {
      if (e.key === "Escape" && oncancel) oncancel();
      if (e.key === "Enter" && e.ctrlKey && value.trim() && !busy) onadd(value);
    }}
  ></textarea>

  <p class="caption found" aria-live="polite">
    {#if busy && found.urls > 1}
      {t("Загружаю подписки по очереди — к одному провайдеру KVT ходит с паузой, это может занять минуту.", "Loading subscriptions one by one — KVT pauses between requests to the same provider, this may take a minute.")}
    {:else if found.text}
      {found.text}
    {:else}
      {t("VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS, SOCKS5, HTTP-прокси", "VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS, SOCKS5, HTTP proxy")}
    {/if}
  </p>

  <div class="actions">
    {#if oncancel}
      <button class="btn" disabled={busy} onclick={oncancel}>{t("Отмена", "Cancel")}</button>
    {/if}
    <button class="btn" disabled={busy} onclick={paste}><Icon name="paste" size={16} />{t("Вставить из буфера", "Paste from clipboard")}</button>
    <button
      class="btn btn-primary"
      class:busy
      disabled={!value.trim() || busy}
      title="Ctrl+Enter"
      onclick={() => onadd(value)}
    >
      <Icon name="plus" size={16} />{t("Добавить", "Add")}
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
