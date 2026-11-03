<script lang="ts" module>
  // Контурные иконки 20×20 в стиле Fluent. Позже заменим на Fluent UI System Icons (MIT).
  const paths = {
    home: "M3.5 8.5 10 3l6.5 5.5V16a1 1 0 0 1-1 1h-3.5v-4.5h-4V17H4.5a1 1 0 0 1-1-1z",
    list: "M7 5.5h10M7 10h10M7 14.5h10M3.5 5.5h.01M3.5 10h.01M3.5 14.5h.01",
    route: "M5 4.5a1.5 1.5 0 1 0 0 .01M15 15.5a1.5 1.5 0 1 0 0 .01M5 6v4.5a2 2 0 0 0 2 2h6a2 2 0 0 1 2 2V14",
    log: "M5 3.5h7l3 3V16a.5.5 0 0 1-.5.5h-9.5a.5.5 0 0 1-.5-.5V4a.5.5 0 0 1 .5-.5zM7.5 9.5h5M7.5 12.5h5",
    sliders: "M3.5 6h8M14.5 6h2M3.5 14h2M8.5 14h8M13 4.5v3M7 12.5v3",
    shield: "M10 2.5 4 5v4.5c0 3.6 2.5 6.6 6 8 3.5-1.4 6-4.4 6-8V5z",
    warning: "M10 3 2.5 16.5h15zM10 8v4M10 14.2v.01",
    plus: "M10 4v12M4 10h12",
    paste: "M7.5 3.5h5v2h-5zM7.5 4.5H5.5a1 1 0 0 0-1 1V16a1 1 0 0 0 1 1h9a1 1 0 0 0 1-1V5.5a1 1 0 0 0-1-1h-2",
  } as const;
  export type IconName = keyof typeof paths;
</script>

<script lang="ts">
  let { name, size = 20 }: { name: IconName; size?: number } = $props();
</script>

<svg
  width={size}
  height={size}
  viewBox="0 0 20 20"
  fill="none"
  stroke="currentColor"
  stroke-width="1.25"
  stroke-linecap="round"
  stroke-linejoin="round"
  aria-hidden="true"
>
  <path d={paths[name]} />
</svg>
