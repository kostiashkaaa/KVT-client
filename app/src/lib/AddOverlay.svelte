<script lang="ts">
  // Панель добавления подписки поверх текущего экрана: список под ней остаётся на месте.
  // Закрытие — по клику мимо панели и по Esc; сама форма — AddSubscription.
  import { fade } from "svelte/transition";
  import AddSubscription from "./AddSubscription.svelte";
  import Banner from "./Banner.svelte";

  let {
    busy,
    addError,
    onadd,
    onclose,
  }: {
    busy: boolean;
    /** Ошибка добавления — под формой. */
    addError: string | null;
    onadd: (body: string) => void | Promise<void>;
    onclose: () => void;
  } = $props();
</script>

<div
  class="overlay"
  role="dialog"
  aria-modal="true"
  aria-labelledby="add-title"
  tabindex="-1"
  transition:fade={{ duration: 150 }}
  onclick={(e) => {
    if (e.target === e.currentTarget) onclose();
  }}
  onkeydown={(e) => {
    if (e.key === "Escape") onclose();
  }}
>
  <AddSubscription {onadd} {busy} oncancel={onclose} />
  {#if addError}
    <div class="overlay-error"><Banner>{addError}</Banner></div>
  {/if}
</div>

<style>
  .overlay {
    position: fixed;
    inset: 0;
    z-index: 10;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: var(--space-3);
    padding: var(--space-4);
    background: rgb(0 0 0 / 0.45);
  }

  .overlay-error {
    width: min(560px, calc(100vw - 32px));
  }
</style>
