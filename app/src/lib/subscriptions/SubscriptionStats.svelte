<script lang="ts">
  // Расход трафика и срок подписки. Только показ: что считать и как назвать — в format.ts.
  import { t } from "../i18n";
  import type { Expiry, Usage } from "./format";

  let { use, exp }: { use: Usage | null; exp: Expiry | null } = $props();
</script>

<div class="stats">
  {#if use}
    <div class="stat">
      {#if use.share !== null}
        <div class="bar {use.tone}" role="progressbar" aria-label={t("Трафик", "Traffic")} aria-valuenow={Math.round(use.share * 100)} aria-valuemin="0" aria-valuemax="100">
          <span style:width={`${use.share * 100}%`}></span>
        </div>
      {/if}
      <span class="caption {use.tone}">{use.text}</span>
    </div>
  {/if}
  {#if exp}
    <span class="caption {exp.tone}">{exp.text}</span>
  {/if}
</div>

<style>
  .caption.warn {
    color: var(--warn);
  }

  .caption.danger {
    color: var(--danger);
  }

  .stats {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: var(--space-2) var(--space-6);
  }

  .stat {
    display: flex;
    align-items: center;
    gap: var(--space-3);
  }

  .bar {
    width: 160px;
    height: 4px;
    border-radius: 2px;
    background: var(--stroke);
    overflow: hidden;
  }

  .bar span {
    display: block;
    height: 100%;
    border-radius: 2px;
    background: var(--accent);
    transition: width 300ms var(--ease);
  }

  .bar.warn span {
    background: var(--warn);
  }

  .bar.danger span {
    background: var(--danger);
  }
</style>
