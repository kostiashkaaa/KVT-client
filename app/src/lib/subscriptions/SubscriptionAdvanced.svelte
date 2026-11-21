<script lang="ts">
  // Форма «Расширенные» одной подписки: фильтр серверов, клиент, ID устройства. Поля
  // заполняются из настроек подписки при открытии — форма создаётся заново каждый раз.
  import { slide } from "svelte/transition";
  import { t } from "../i18n";
  import { setSubscriptionOptions, type HwidMode, type SubscriptionItem } from "../api";

  let {
    s,
    onclose,
    onchange,
  }: {
    s: SubscriptionItem;
    /** Закрыть форму (после сохранения и по «Отмена»). */
    onclose: () => void;
    /** Перечитать список подписок. */
    onchange: () => Promise<void>;
  } = $props();

  const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

  let keep = $state("");
  let drop = $state("");
  let client = $state<string>("auto");
  let userAgent = $state("");
  let hwid = $state<HwidMode>("auto");
  let ownHwid = $state("");
  /** Убрать ID от провайдера при сохранении. */
  let clearOwnHwid = $state(false);
  let advancedSaving = $state(false);
  let advancedError = $state<string | null>(null);

  const clients: [string, string][] = [
    ["auto", t("Авто — подобрать самому", "Auto — pick automatically")],
    ["v2rayng", "v2rayNG"],
    ["v2rayn", "v2rayN"],
    ["hiddify", "Hiddify"],
    ["happ", "Happ"],
    ["incy", "INCY"],
    ["v2raytun", "v2RayTun"],
    ["kvt", "KVT"],
    ["custom", t("Свой User-Agent", "Custom User-Agent")],
  ];

  /** Поля берутся из настроек подписки один раз, когда форма открывается. */
  function load() {
    keep = s.options.keep.join(", ");
    drop = s.options.drop.join(", ");
    client = s.options.client ?? "auto";
    userAgent = s.options.userAgent ?? "";
    hwid = s.options.hwid;
    ownHwid = "";
    clearOwnHwid = false;
    advancedError = null;
  }
  load();

  async function saveAdvanced(id: string) {
    advancedSaving = true;
    advancedError = null;
    try {
      await setSubscriptionOptions(id, {
        keep,
        drop,
        client: client === "auto" ? null : client,
        userAgent,
        hwid,
        ownHwid: clearOwnHwid ? "" : ownHwid.trim() || null,
      });
      onclose();
    } catch (e) {
      // Настройки могли сохраниться, а загрузка — не пройти: причина видна у формы.
      advancedError = message(e);
    } finally {
      advancedSaving = false;
    }
    await onchange();
  }
</script>

<form
  class="editor advanced"
  transition:slide={{ duration: 150 }}
  onsubmit={(e) => {
    e.preventDefault();
    void saveAdvanced(s.id);
  }}
>
  <fieldset>
    <legend>{t("Серверы", "Servers")}</legend>
    <label for="keep-{s.id}">{t("Оставить только с этими словами в названии", "Keep only names with these words")}</label>
    <input id="keep-{s.id}" bind:value={keep} autocomplete="off" placeholder={t("Пусто — все. Например: NL, Германия", "Empty — all. For example: NL, Germany")} />
    <label for="drop-{s.id}">{t("Убрать с этими словами", "Remove names with these words")}</label>
    <input id="drop-{s.id}" bind:value={drop} autocomplete="off" placeholder={t("Например: резерв, test", "For example: backup, test")} />
    <p class="caption">
      {t("Слова — через запятую, регистр не важен. Код страны (NL, DE) находит сервер и по флагу.", "Separate words with commas, case doesn't matter. A country code (NL, DE) also matches a server by its flag.")}
    </p>
  </fieldset>

  <fieldset>
    <legend>{t("Клиент", "Client")}</legend>
    <label for="client-{s.id}">{t("Как KVT представляется провайдеру", "How KVT introduces itself to the provider")}</label>
    <select id="client-{s.id}" bind:value={client}>
      {#each clients as [value, label] (value)}
        <option {value}>{label}</option>
      {/each}
    </select>
    {#if client === "custom"}
      <input
        bind:value={userAgent}
        maxlength="200"
        autocomplete="off"
        spellcheck="false"
        aria-label={t("Свой User-Agent", "Custom User-Agent")}
        placeholder="Happ/3.6.1"
      />
    {/if}
    <p class="caption">
      {t("Нужен, только если провайдер отдаёт серверы лишь «своему» приложению. «Авто» пробует несколько клиентов по очереди.", "Only needed if the provider gives servers to its “own” app only. “Auto” tries several clients in turn.")}
    </p>
  </fieldset>

  <fieldset>
    <legend>{t("ID устройства", "Device ID")}</legend>
    <label for="hwid-{s.id}">{t("Отправлять провайдеру", "Send to the provider")}</label>
    <select id="hwid-{s.id}" bind:value={hwid}>
      <option value="auto">{t("Когда провайдер просит", "When the provider asks")}</option>
      <option value="always">{t("Всегда", "Always")}</option>
      <option value="never">{t("Никогда", "Never")}</option>
    </select>
    {#if hwid !== "never"}
      <label for="own-{s.id}">{t("ID от провайдера", "ID from the provider")}</label>
      <input
        id="own-{s.id}"
        bind:value={ownHwid}
        maxlength="128"
        autocomplete="off"
        spellcheck="false"
        disabled={clearOwnHwid}
        placeholder={s.options.ownHwid && !clearOwnHwid
          ? t("Задан — вставьте новый, чтобы заменить", "Set — paste a new one to replace it")
          : t("Пусто — свой ID KVT", "Empty — KVT's own ID")}
      />
      {#if s.options.ownHwid}
        <label class="check">
          <input type="checkbox" bind:checked={clearOwnHwid} />
          {t("Убрать ID от провайдера", "Remove the provider's ID")}
        </label>
      {/if}
    {/if}
    <p class="caption">
      {t(`Провайдеры с лимитом устройств отдают серверы только по ID. У KVT он свой для каждого провайдера, без имени компьютера. ${s.options.hwidSent ? "Сейчас ID отправляется." : ""}`, `Providers with a device limit give servers only by ID. KVT has its own for each provider, without the computer's name. ${s.options.hwidSent ? "The ID is being sent now." : ""}`)}
    </p>
  </fieldset>

  {#if advancedError}
    <p class="error-text appear">{advancedError}</p>
  {/if}
  <div class="editor-actions">
    <button type="submit" class="btn btn-primary" class:busy={advancedSaving} disabled={advancedSaving}>
      {t("Сохранить", "Save")}
    </button>
    <button type="button" class="btn" disabled={advancedSaving} onclick={onclose}>
      {t("Отмена", "Cancel")}
    </button>
  </div>
</form>

<style>
  .editor input {
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
  .editor input:focus {
    outline: none;
    border-bottom-color: var(--accent);
    box-shadow: inset 0 -1px 0 var(--accent);
  }

  .caption {
    margin: 0;
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

  .editor.advanced {
    gap: var(--space-4);
    padding-left: 0;
  }

  .advanced fieldset {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    margin: 0;
    padding: 0;
    border: 0;
  }

  .advanced legend {
    margin-bottom: var(--space-1);
    padding: 0;
    font-weight: 600;
  }

  /* Вид — общий из app.css; здесь только высота как у полей ввода. */
  .advanced select {
    height: 32px;
  }

  .advanced .check {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    color: var(--text);
  }

  .advanced input:disabled {
    opacity: 0.5;
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
</style>
