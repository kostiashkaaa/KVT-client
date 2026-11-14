<script lang="ts" module>
  import { lang } from "./i18n";

  // Флаги flag-icons (MIT), только 4×3: в сборку попадают они, а не весь пакет.
  // Картинки встроены в приложение — никаких запросов в интернет.
  const urls = import.meta.glob("/node_modules/flag-icons/flags/4x3/*.svg", {
    query: "?url",
    import: "default",
    eager: true,
  }) as Record<string, string>;

  const byCode = new Map(
    Object.entries(urls).map(([path, url]) => [path.slice(path.lastIndexOf("/") + 1, -".svg".length), url]),
  );

  /** Картинка флага по коду (`ee`), если она есть в сборке. */
  export function flagUrl(code: string): string | undefined {
    return byCode.get(code);
  }

  // Создаются при первом вызове, а не при загрузке модуля: модуль грузится раньше,
  // чем выставлен язык окна, и названия всегда были бы русскими.
  let names: Intl.DisplayNames | null | undefined;

  function displayNames(): Intl.DisplayNames | null {
    if (names === undefined) {
      try {
        names = new Intl.DisplayNames([lang()], { type: "region" });
      } catch {
        names = null;
      }
    }
    return names;
  }

  /** Название страны на языке окна («Эстония», «Estonia»); если его нет — код. */
  export function country(code: string): string {
    try {
      return displayNames()?.of(code.toUpperCase()) ?? code.toUpperCase();
    } catch {
      return code.toUpperCase();
    }
  }
</script>

<script lang="ts">
  /** width — ширина в пикселях, высота по пропорции флага 4×3. */
  let { code, width = 20 }: { code: string | null; width?: number } = $props();
  const src = $derived(code ? byCode.get(code) : undefined);
  const height = $derived(Math.round((width * 3) / 4));
</script>

{#if code && src}
  <img
    class="flag"
    {src}
    alt={country(code)}
    title={country(code)}
    {width}
    {height}
    style:width="{width}px"
    style:height="{height}px"
    style:border-radius="{width >= 24 ? 4 : 2}px"
    draggable="false"
  />
{:else}
  <span class="flag none" aria-hidden="true" style:width="{width}px" style:height="{height}px"></span>
{/if}

<style>
  .flag {
    display: block;
    flex: none;
    object-fit: cover;
    /* Тонкая рамка: белые полосы флагов не сливаются со светлым фоном. */
    box-shadow: 0 0 0 1px rgb(0 0 0 / 0.12);
  }

  /* Без флага — пустое место той же ширины, чтобы названия стояли ровно. */
  .none {
    box-shadow: none;
  }
</style>
