<script lang="ts" module>
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

  const names = (() => {
    try {
      return new Intl.DisplayNames(["ru"], { type: "region" });
    } catch {
      return null;
    }
  })();

  function country(code: string): string {
    try {
      return names?.of(code.toUpperCase()) ?? code.toUpperCase();
    } catch {
      return code.toUpperCase();
    }
  }
</script>

<script lang="ts">
  let { code }: { code: string | null } = $props();
  const src = $derived(code ? byCode.get(code) : undefined);
</script>

{#if code && src}
  <img class="flag" {src} alt={country(code)} title={country(code)} width="20" height="15" draggable="false" />
{:else}
  <span class="flag none" aria-hidden="true"></span>
{/if}

<style>
  .flag {
    display: block;
    width: 20px;
    height: 15px;
    border-radius: 2px;
    object-fit: cover;
    /* Тонкая рамка: белые полосы флагов не сливаются со светлым фоном. */
    box-shadow: 0 0 0 1px rgb(0 0 0 / 0.12);
  }

  /* Без флага — пустое место той же ширины, чтобы названия стояли ровно. */
  .none {
    box-shadow: none;
  }
</style>
