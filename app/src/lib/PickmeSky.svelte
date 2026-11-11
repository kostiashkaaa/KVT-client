<script lang="ts">
  // Фон скрытой темы: настоящее небо над Саратовом 17.10.2005 в 00:15 (pickmeSky.ts),
  // нарисованное блёстками, и падающие звёзды. Только украшение: не ловит мышь,
  // скрыто от экранного диктора.
  import { stars, planets } from "./pickmeSky";

  /** Мерцают самые яркие звёзды, каждая в своём такте. */
  const TWINKLE = 30;
  /** У стольких самых ярких — розовое свечение вокруг. */
  const GLOW = 14;
  const colors = ["#ffffff", "#ff8fd4", "#ffd1ec", "#e0c2ff", "#ff6fc4"];

  /** Падающие звёзды: откуда стартуют (% окна), угол, пауза до первой и период. */
  const meteors = [
    { x: 78, y: 6, angle: -32, delay: 1.5, period: 11 },
    { x: 96, y: 34, angle: -24, delay: 6, period: 17 },
    { x: 55, y: 2, angle: -40, delay: 10, period: 14 },
    { x: 88, y: 62, angle: -18, delay: 15, period: 19 },
  ];
  // В эту ночь Луна почти полная (99 %) и высоко на юге, рядом — яркий Марс.
  const moon = planets.find((p) => p.name === "Moon");
  const wanderers = planets.filter((p) => p.name !== "Moon");
  const planetColor: Record<string, string> = { Mars: "#ff8f86" };
  const f = (v: number) => v.toFixed(4);
</script>

<div class="sky" aria-hidden="true">
  <svg viewBox="-1.1 -1.1 2.2 2.2">
    <defs>
      <!-- Четырёхлучевая блёстка, как в остальной теме. -->
      <path id="pickme-star" d="M0-1C.1-.32.32-.1 1 0 .32.1.1.32 0 1-.1.32-.32.1-1 0-.32-.1-.1-.32 0-1Z" />
      <radialGradient id="pickme-glow">
        <stop offset="0" stop-color="#ff8fd4" stop-opacity="0.55" />
        <stop offset="1" stop-color="#ff4fb8" stop-opacity="0" />
      </radialGradient>
      <radialGradient id="pickme-moon-halo">
        <stop offset="0" stop-color="#ffd1ec" stop-opacity="0.5" />
        <stop offset="0.4" stop-color="#ff8fd4" stop-opacity="0.2" />
        <stop offset="1" stop-color="#c45bff" stop-opacity="0" />
      </radialGradient>
      <radialGradient id="pickme-moon" cx="0.42" cy="0.4">
        <stop offset="0" stop-color="#fffafd" />
        <stop offset="0.7" stop-color="#ffe3f3" />
        <stop offset="1" stop-color="#ffb8e0" />
      </radialGradient>
    </defs>

    {#if moon}
      <circle cx={moon.x} cy={moon.y} r="0.2" fill="url(#pickme-moon-halo)" />
      <circle cx={moon.x} cy={moon.y} r="0.038" fill="url(#pickme-moon)" />
    {/if}
    {#each wanderers as p (p.name)}
      <circle cx={p.x} cy={p.y} r="0.045" fill="url(#pickme-glow)" />
      <use
        href="#pickme-star"
        fill={planetColor[p.name] ?? "#ffd98a"}
        transform="translate({p.x} {p.y}) scale(0.026)"
      />
    {/each}

    {#each stars as [x, y, r], i (i)}
      {#if i < GLOW}
        <circle cx={x} cy={y} r={f(r * 4.5)} fill="url(#pickme-glow)" />
      {/if}
      <use
        href="#pickme-star"
        class:tw={i < TWINKLE}
        fill={colors[i % colors.length]}
        transform="translate({x} {y}) scale({f(r * 2.6)})"
        style:animation-delay="{((i * 0.73) % 4).toFixed(2)}s"
      />
    {/each}
  </svg>

  {#each meteors as m, i (i)}
    <i
      class="meteor"
      style:left="{m.x}%"
      style:top="{m.y}%"
      style:--angle="{m.angle}deg"
      style:animation-delay="{m.delay}s"
      style:animation-duration="{m.period}s"
    ></i>
  {/each}
</div>

<style>
  /* Позади интерфейса (но перед блёстками фона): в просветах между карточками
     и сквозь боковую панель. */
  .sky {
    position: fixed;
    inset: 0;
    z-index: -1;
    overflow: hidden;
    pointer-events: none;
    animation: kvt-fade 1.2s var(--ease) backwards;
  }

  svg {
    position: absolute;
    left: 50%;
    top: 50%;
    width: max(100vh, 72vw);
    aspect-ratio: 1;
    translate: -50% -50%;
  }

  .tw {
    animation: sky-twinkle 2.8s ease-in-out infinite alternate;
  }

  @keyframes sky-twinkle {
    from {
      opacity: 1;
    }
    to {
      opacity: 0.3;
    }
  }

  /* Падающая звезда: светлая голова слева, хвост тает вправо. Летит секунду
     в начале своего периода, остальное время невидима. */
  .meteor {
    position: absolute;
    width: 140px;
    height: 2px;
    border-radius: 2px;
    background: linear-gradient(90deg, #fff, rgb(255 143 212 / 0.7) 30%, transparent);
    filter: drop-shadow(0 0 4px rgb(255 120 200 / 0.9));
    opacity: 0;
    transform-origin: left center;
    animation: meteor linear infinite backwards;
  }

  @keyframes meteor {
    0% {
      opacity: 0;
      transform: rotate(var(--angle)) translateX(0) scaleX(0.3);
    }
    1.5% {
      opacity: 1;
    }
    7% {
      opacity: 0;
      transform: rotate(var(--angle)) translateX(-46vmax) scaleX(1);
    }
    100% {
      opacity: 0;
      transform: rotate(var(--angle)) translateX(-46vmax) scaleX(1);
    }
  }
</style>
