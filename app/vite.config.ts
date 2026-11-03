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
    target: "es2022",
    sourcemap: false,
    // Флаги — отдельными файлами: в коде только адреса, картинка грузится, когда видна.
    assetsInlineLimit: (file) => (file.includes("flag-icons") ? false : undefined),
  },
});
