<script lang="ts" module>
  import { country, flagUrl } from "./Flag.svelte";

  type Part = { text: string } | { code: string; src: string };

  const RI_START = 0x1f1e6;
  // Флаг-эмодзи — пара региональных индикаторов, иногда с селектором U+FE0F.
  const FLAG = /([\u{1F1E6}-\u{1F1FF}]{2})\u{FE0F}?/u;

  /** «→🇪🇪 для wifi» → текст и флаги по порядку. Флаг без картинки — буквами («XX»). */
  export function parts(name: string): Part[] {
    const out: Part[] = [];
    name.split(FLAG).forEach((piece, i) => {
      if (!piece) return;
      if (i % 2 === 0) {
        out.push({ text: piece });
        return;
      }
      const code = Array.from(piece, (c) => String.fromCharCode(97 + c.codePointAt(0)! - RI_START)).join("");
      const src = flagUrl(code);
      out.push(src ? { code, src } : { text: code.toUpperCase() });
    });
    return out;
  }
</script>

<script lang="ts">
  /** Название сервера как в подписке; флаги внутри него — картинками
   *  (WebView в Windows рисует флаги-эмодзи буквами). */
  let { name }: { name: string } = $props();
  const list = $derived(parts(name));
</script>

{#each list as p, i (i)}{#if "src" in p}<img
      class="inline-flag"
      src={p.src}
      alt={country(p.code)}
      title={country(p.code)}
      width="16"
      height="12"
      draggable="false"
    />{:else}{p.text}{/if}{/each}

<style>
  .inline-flag {
    display: inline-block;
    width: 16px;
    height: 12px;
    margin: 0 2px;
    vertical-align: -1px;
    border-radius: 2px;
    object-fit: cover;
    box-shadow: 0 0 0 1px rgb(0 0 0 / 0.12);
  }
</style>
