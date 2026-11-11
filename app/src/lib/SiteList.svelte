<script lang="ts" generics="A extends string">
  import { t } from "./i18n";
  // Свои сайты: поле с кнопкой «Добавить» и список с выбором действия у каждого.
  // Общий для «Маршрутизации» и Zapret; адрес проверяет Rust (`check`).
  import Icon from "./Icon.svelte";

  let {
    items,
    actions,
    newAction,
    onnewaction,
    max,
    placeholder,
    label,
    check,
    onchange,
    empty,
  }: {
    items: { target: string; action: A }[];
    /** `tone` — цвет полосы у поля: accent, ok, danger или пусто. */
    actions: { value: A; title: string; tone?: "accent" | "ok" | "danger" }[];
    /** Действие для нового адреса. */
    newAction: A;
    onnewaction: (action: A) => void;
    max: number;
    placeholder: string;
    /** Подпись поля для экранного диктора. */
    label: string;
    check: (input: string) => Promise<string>;
    onchange: (next: { target: string; action: A }[]) => void;
    /** Подсказка, пока список пуст. */
    empty?: string;
  } = $props();

  let draft = $state("");
  let adding = $state(false);
  let error = $state<string | null>(null);
  const errorId = `sites-${Math.random().toString(36).slice(2)}`;

  const toneOf = (a: A) => actions.find((x) => x.value === a)?.tone ?? "";

  async function add(e: SubmitEvent) {
    e.preventDefault();
    const parts = draft.split(/[\s,;]+/).filter(Boolean);
    if (parts.length === 0) return;
    adding = true;
    error = null;
    const next = [...items];
    const failed: string[] = [];
    let firstError: string | null = null;
    for (const part of parts) {
      try {
        const target = await check(part);
        const i = next.findIndex((c) => c.target === target);
        // Уже есть — меняем действие, а не заводим второй.
        if (i >= 0) next.splice(i, 1);
        else if (next.length >= max) {
          firstError ??= t(`Не больше ${max} адресов.`, `No more than ${max} addresses.`);
          failed.push(part);
          continue;
        }
        next.unshift({ target, action: newAction });
      } catch (err) {
        firstError ??= err instanceof Error ? err.message : String(err);
        failed.push(part);
      }
    }
    onchange(next);
    // Неудачные адреса остаются в поле — их видно и можно поправить.
    draft = failed.join(", ");
    error = failed.length > 0 ? firstError : null;
    adding = false;
  }

  const setAction = (target: string, action: A) =>
    onchange(items.map((c) => (c.target === target ? { ...c, action } : c)));
  const remove = (target: string) => onchange(items.filter((c) => c.target !== target));
</script>

<div class="sites">
  <form class="add" onsubmit={add}>
    <input
      bind:value={draft}
      {placeholder}
      aria-label={label}
      autocomplete="off"
      spellcheck="false"
      disabled={adding}
      oninput={() => (error = null)}
      aria-invalid={error !== null}
      aria-describedby={error ? errorId : undefined}
    />
    <select
      aria-label={t("Действие для нового адреса", "Action for the new address")}
      value={newAction}
      class="tone-{toneOf(newAction)}"
      onchange={(e) => onnewaction(e.currentTarget.value as A)}
    >
      {#each actions as a (a.value)}
        <option value={a.value}>{a.title}</option>
      {/each}
    </select>
    <button type="submit" class="btn btn-primary" class:busy={adding} disabled={adding || draft.trim() === ""}>
      <Icon name="plus" size={16} />{t("Добавить", "Add")}
    </button>
  </form>
  {#if error}
    <p id={errorId} class="error" role="alert">{error}</p>
  {/if}

  {#if items.length > 0}
    <ul>
      {#each items as c (c.target)}
        <li class="appear">
          <span class="target" title={c.target}>{c.target}</span>
          <select
            aria-label={t(`Действие: ${c.target}`, `Action: ${c.target}`)}
            value={c.action}
            class="tone-{toneOf(c.action)}"
            onchange={(e) => setAction(c.target, e.currentTarget.value as A)}
          >
            {#each actions as a (a.value)}
              <option value={a.value}>{a.title}</option>
            {/each}
          </select>
          <button class="btn subtle icon" onclick={() => remove(c.target)} aria-label={t(`Удалить ${c.target}`, `Delete ${c.target}`)} title={t("Удалить", "Delete")}>
            <Icon name="trash" size={16} />
          </button>
        </li>
      {/each}
    </ul>
  {:else if empty}
    <p class="caption">{empty}</p>
  {/if}
</div>

<style>
  .sites {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
    container-type: inline-size;
  }

  .add {
    display: flex;
    gap: var(--space-2);
  }

  .add input {
    flex: 1;
    min-width: 0;
    height: 32px;
    padding: 0 var(--space-3);
    border: 1px solid var(--stroke);
    border-bottom-color: var(--text-3);
    border-radius: var(--radius-s);
    background: var(--surface);
    user-select: text;
    transition: border-color var(--dur-fast) var(--ease);
  }

  /* Как в Windows 11: снизу акцентная линия, высота поля не меняется. */
  .add input:focus {
    outline: none;
    border-bottom-color: var(--accent);
    box-shadow: inset 0 -1px 0 var(--accent);
  }

  .add input[aria-invalid="true"] {
    border-bottom-color: var(--danger);
    box-shadow: inset 0 -1px 0 var(--danger);
  }

  .add .btn {
    flex: none;
  }

  select {
    flex: none;
    height: 32px;
    min-width: 132px;
  }

  .error {
    margin: calc(-1 * var(--space-1)) 0 0;
    font-size: 12px;
    line-height: 16px;
    color: var(--danger);
  }

  .caption {
    margin: 0;
  }

  ul {
    margin: 0;
    padding: 0;
    list-style: none;
  }

  li {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    min-height: 44px;
    padding: var(--space-1) 0;
    border-bottom: 1px solid var(--stroke);
  }

  li:last-child {
    border-bottom: 0;
  }

  .target {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-family: var(--mono);
    font-size: 13px;
    user-select: text;
  }

  .icon {
    width: 32px;
    padding: 0;
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

  /* Свой выбор виден сразу: цвет полосы слева у поля по смыслу действия. */
  select.tone-accent {
    border-color: var(--accent);
    box-shadow: inset 3px 0 0 var(--accent);
  }

  select.tone-ok {
    border-color: var(--ok);
    box-shadow: inset 3px 0 0 var(--ok);
  }

  select.tone-danger {
    border-color: var(--danger);
    box-shadow: inset 3px 0 0 var(--danger);
  }

  @container (max-width: 520px) {
    .add {
      flex-wrap: wrap;
    }

    .add input {
      flex-basis: 100%;
    }

    li select {
      min-width: 0;
      max-width: 55%;
    }
  }
</style>
