<script lang="ts">
  import { count, t } from "./i18n";
  import Icon from "./Icon.svelte";
  import { qrScreenClip, type ScreenClip } from "./api";
  import { addLines, imageFromPaste, readClipboard, scanImage, waitForFocus, type ScanError } from "./qr/scan";

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
  /** Идёт поиск QR-кода на картинке. */
  let scanning = $state(false);
  /** Что не вышло с картинкой (или «ищу»); пусто — подсказка про найденное. */
  let note = $state("");
  let fileInput = $state<HTMLInputElement>();

  function focus(node: HTMLTextAreaElement) {
    if (oncancel) node.focus();
  }

  // Буфер обмена читается только по нажатию — никакого фонового чтения. В нём может
  // лежать и картинка с QR-кодом (снимок экрана): её читаем так же, как файл.
  async function paste() {
    try {
      const clip = await readClipboard();
      if (clip.image) {
        await scan(clip.image);
      } else {
        value = clip.text;
        note = "";
      }
    } catch {
      /* доступ к буферу запрещён — пользователь вставит вручную */
    }
  }

  /** QR-код с картинки — в поле, как вставка: проверить глазами и нажать «Добавить». */
  async function scan(image: Blob) {
    if (scanning) return;
    scanning = true;
    try {
      await decode(image);
    } finally {
      scanning = false;
    }
  }

  /** То же без флага `scanning`: его держит вызывающий. */
  async function decode(image: Blob) {
    note = t("Ищу QR-код…", "Looking for a QR code…");
    const result = await scanImage(image);
    if ("texts" in result) {
      value = addLines(value, result.texts);
      note = "";
    } else {
      note = errorText(result.error);
    }
  }

  /**
   * «С экрана»: окно сворачивается, область выделяет системный инструмент снимков
   * (как Win+Shift+S), снимок приходит в буфер обмена — дальше как «Вставить из буфера».
   */
  async function fromScreen() {
    if (scanning) return;
    scanning = true;
    note = t("Выделите область с QR-кодом на экране.", "Select the area with the QR code on the screen.");
    try {
      const result = await qrScreenClip();
      if (result !== "captured") {
        note = screenText(result);
        return;
      }
      // Окно только что вернулось: без фокуса WebView не отдаст буфер обмена.
      const hint = t(
        "Снимок в буфере обмена. Нажмите «Вставить из буфера».",
        "The snip is on the clipboard. Click “Paste from clipboard”.",
      );
      if (!(await waitForFocus())) {
        note = hint;
        return;
      }
      const clip = await readClipboard().catch(() => null);
      if (clip?.image) await decode(clip.image);
      else note = hint;
    } finally {
      scanning = false;
    }
  }

  function screenText(result: ScreenClip): string {
    switch (result) {
      case "cancelled":
        return t("Выделение отменено.", "Selection cancelled.");
      case "timed_out":
        return t("Область не выделили — время вышло.", "No area was selected — timed out.");
      case "unsupported":
        return t(
          "Выделение области здесь недоступно. Нажмите Win+Shift+S, выделите код и «Вставить из буфера».",
          "Area selection isn't available here. Press Win+Shift+S, select the code, then “Paste from clipboard”.",
        );
      case "busy":
        return t("Выделение уже идёт.", "Selection is already in progress.");
      default:
        return "";
    }
  }

  function errorText(error: ScanError): string {
    switch (error) {
      case "not_found":
        return t("На картинке нет QR-кода. Нужна картинка, где код виден целиком.", "No QR code in the image. The whole code must be visible.");
      case "unreadable":
        return t("QR-код нашёл, но не прочитал: картинка мелкая или размытая. Попробуйте крупнее.", "Found a QR code but couldn't read it: the image is small or blurry. Try a larger one.");
      case "too_big":
        return t("Файл больше 20 МБ — это не похоже на снимок QR-кода.", "The file is over 20 MB — that doesn't look like a QR code snapshot.");
      default:
        return t("Не удалось открыть картинку.", "Couldn't open the image.");
    }
  }

  function pickFile(e: Event & { currentTarget: HTMLInputElement }) {
    const file = e.currentTarget.files?.[0];
    // Тот же файл можно выбрать ещё раз: без сброса событие не повторится.
    e.currentTarget.value = "";
    if (file) void scan(file);
  }

  // Ctrl+V с картинкой в буфере: текст вставляется как обычно, картинку читаем сами.
  function onpaste(e: ClipboardEvent) {
    const image = imageFromPaste(e.clipboardData);
    if (!image) return;
    e.preventDefault();
    void scan(image);
  }

  // Подсказка «что найдено» — грубый подсчёт для глаз, разбирает вставку Rust.
  const APP = /^(happ|incy|v2raytun|hiddify|v2rayng|v2box|streisand|clash|sing-box):\/\//i;
  const KEY = /^(vless|vmess|trojan|ss|hy2|hysteria2|tuic|anytls|socks5?|socks5h):\/\//i;
  /** HTTP-прокси: логин в адресе и пустой путь (у подписки путь с токеном есть всегда). */
  const HTTP_PROXY = /^https?:\/\/[^\s/@]+@[^\s/?#]+\/?([?#]|$)/i;
  const found = $derived.by(() => {
    const text = value.trim();
    if (!text) return { urls: 0, text: "" };
    // `.conf` WireGuard / AmneziaWG начинается с «[Interface]» — это не JSON.
    const confs = (text.match(/^\s*\[interface\]\s*$/gim) ?? []).length;
    if (confs)
      return {
        urls: 0,
        text: `${t("Найдено", "Found")}: ${count(
          confs,
          ["конфиг WireGuard / AmneziaWG", "конфига WireGuard / AmneziaWG", "конфигов WireGuard / AmneziaWG"],
          ["WireGuard / AmneziaWG config", "WireGuard / AmneziaWG configs"],
        )}`,
      };
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

<section class="card empty" class:dialog={!!oncancel} {onpaste}>
  <div class="icon" aria-hidden="true"><Icon name="shield" size={32} /></div>
  <h2 id="add-title">{oncancel ? t("Добавить подписку или ключ", "Add a subscription or key") : t("Добавьте подписку", "Add a subscription")}</h2>
  <p class="muted">
    {t("Ссылка на подписку (https://…), ключи серверов, конфиг Xray / sing-box или .conf WireGuard / AmneziaWG. Можно несколько сразу и вместе с текстом из письма провайдера — KVT найдёт нужное. QR-код — из файла, из буфера обмена или прямо с экрана.", "A subscription link (https://…), server keys, an Xray / sing-box config or a WireGuard / AmneziaWG .conf. You can paste several at once, even with the text of your provider's email — KVT will find what it needs. A QR code works too — from a file, the clipboard or right from the screen.")}
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
    oninput={() => (note = "")}
    onkeydown={(e) => {
      if (e.key === "Escape" && oncancel) oncancel();
      if (e.key === "Enter" && e.ctrlKey && value.trim() && !busy) onadd(value);
    }}
  ></textarea>

  <p class="caption found" aria-live="polite">
    {#if busy && found.urls > 1}
      {t("Загружаю подписки по очереди — к одному провайдеру KVT ходит с паузой, это может занять минуту.", "Loading subscriptions one by one — KVT pauses between requests to the same provider, this may take a minute.")}
    {:else if note}
      {note}
    {:else if found.text}
      {found.text}
    {:else}
      {t("VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS, WireGuard, AmneziaWG, SOCKS5, HTTP-прокси", "VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS, WireGuard, AmneziaWG, SOCKS5, HTTP proxy")}
    {/if}
  </p>

  <div class="actions">
    {#if oncancel}
      <button class="btn" disabled={busy} onclick={oncancel}>{t("Отмена", "Cancel")}</button>
    {/if}
    <input bind:this={fileInput} class="file" type="file" accept="image/*" tabindex="-1" aria-hidden="true" onchange={pickFile} />
    <button
      class="btn"
      disabled={busy || scanning}
      title={t("QR-код из файла с картинкой", "QR code from an image file")}
      onclick={() => fileInput?.click()}
    >
      <Icon name="qr" size={16} />{t("Из картинки", "From an image")}
    </button>
    <button
      class="btn"
      disabled={busy || scanning}
      title={t("Выделить QR-код на экране", "Select a QR code on the screen")}
      onclick={() => void fromScreen()}
    >
      <Icon name="crop" size={16} />{t("С экрана", "From the screen")}
    </button>
    <button class="btn" disabled={busy || scanning} onclick={paste}><Icon name="paste" size={16} />{t("Вставить из буфера", "Paste from clipboard")}</button>
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

  /* Выбор файла открывает кнопка «Из картинки»; сам элемент не показываем. */
  .file {
    display: none;
  }

  .actions {
    display: flex;
    flex-wrap: wrap;
    justify-content: center;
    gap: var(--space-2);
  }
</style>
