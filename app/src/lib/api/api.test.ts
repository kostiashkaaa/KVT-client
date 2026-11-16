// Правила для моста к Rust, которые легко нарушить при новой команде.
//
// Исходники читаются через `import.meta.glob(…?raw)` Vite, а не `node:fs`: типов Node
// в проекте нет (svelte-check в CI их не находит).

import { describe, expect, it } from "vitest";
import barrel from "../api.ts?raw";

const sources = import.meta.glob<string>(["./*.ts", "!./*.test.ts"], {
  query: "?raw",
  import: "default",
  eager: true,
});
const modules = Object.entries(sources).map(([path, text]) => ({
  file: path.replace(/^\.\//, ""),
  text,
}));

/** Экспортированные функции модуля с телами (до следующего объявления верхнего уровня). */
function functions(text: string): { name: string; body: string }[] {
  const re = /^export (?:async )?function (\w+)[\s\S]*?(?=^(?:export |const |let |function |async function |\/\/ ──|\/\*\*)|(?![\s\S]))/gm;
  return [...text.matchAll(re)].map((m) => ({ name: m[1]!, body: m[0] }));
}

describe("api", () => {
  it("исходники разделов прочитаны", () => {
    expect(modules.length).toBeGreaterThan(5);
    expect(modules.some((m) => m.file === "connection.ts")).toBe(true);
  });

  it("каждая команда Rust работает и в превью браузера (`if (!inTauri)`)", () => {
    const missing: string[] = [];
    for (const { file, text } of modules) {
      for (const f of functions(text)) {
        if (/\binvoke\b/.test(f.body) && !/\binTauri\b/.test(f.body)) {
          missing.push(`${file}: ${f.name}`);
        }
      }
    }
    expect(missing).toEqual([]);
  });

  it("каждый раздел доступен через api.ts (данные превью — внутренние)", () => {
    const unused = modules
      .map((m) => m.file.replace(/\.ts$/, ""))
      .filter((name) => name !== "preview" && !barrel.includes(`"./api/${name}"`));
    expect(unused).toEqual([]);
  });

  it("секретов в превью нет: только заглушки, без настоящих ссылок подписок", () => {
    const preview = modules.find((m) => m.file === "preview.ts")?.text ?? "";
    expect(preview).not.toMatch(/(vless|vmess|trojan|ss|hysteria2?):\/\/[^\s"'`]{20,}/);
  });
});
