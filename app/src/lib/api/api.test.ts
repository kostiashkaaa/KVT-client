// Правила для моста к Rust, которые легко нарушить при новой команде.

import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const dir = path.dirname(fileURLToPath(import.meta.url));
const modules = readdirSync(dir)
  .filter((f) => f.endsWith(".ts") && !f.endsWith(".test.ts"))
  .map((f) => ({ file: f, text: readFileSync(path.join(dir, f), "utf8") }));

/** Экспортированные функции модуля с телами (до следующего объявления верхнего уровня). */
function functions(text: string): { name: string; body: string }[] {
  const re = /^export (?:async )?function (\w+)[\s\S]*?(?=^(?:export |const |let |function |async function |\/\/ ──|\/\*\*)|(?![\s\S]))/gm;
  return [...text.matchAll(re)].map((m) => ({ name: m[1]!, body: m[0] }));
}

describe("api", () => {
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
    const barrel = readFileSync(path.join(dir, "..", "api.ts"), "utf8");
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
