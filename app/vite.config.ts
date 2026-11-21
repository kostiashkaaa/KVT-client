import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

// Tauri ожидает фиксированный порт и не должен перезапускать сборку при изменениях в src-tauri.
export default defineConfig({
  plugins: [svelte()],
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
    watch: { ignored: ["**/src-tauri/**"] },
  },
  build: {
    // Две страницы: главное окно и мини-панель из трея (кода окна в ней нет — старт
    // быстрее, а памяти меньше). `proto.html` — только для разработки, в сборку не входит.
    rollupOptions: { input: { main: "index.html", mini: "mini.html" } },
    target: "es2022",
    sourcemap: false,
    // Флаги — отдельными файлами: в коде только адреса, картинка грузится, когда видна.
    assetsInlineLimit: (file) => (file.includes("flag-icons") ? false : undefined),
  },
});
