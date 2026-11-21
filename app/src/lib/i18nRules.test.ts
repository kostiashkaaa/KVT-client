// Правило из CLAUDE.md: t(), count(), plural() и locale() не вызывают на уровне модуля. Модули
// загружаются раньше, чем main.ts выбирает язык окна, поэтому текст, посчитанный при загрузке,
// всегда русский: в английском окне, превью и на английских скриншотах README. Данные превью и
// справочники — функциями, которые считают текст при вызове.
//
// Исходники читаются через `import.meta.glob(…?raw)` (типов Node в проекте нет), разбирает их
// компилятор TypeScript. Вызов — «на уровне модуля», если выше него нет функции. Обратные вызовы
// `.map(…)` и подобных методов и вызов-выражение (IIFE) выполняются на месте, поэтому функцией
// не считаются. Косвенные вызовы ловятся по именам: функция, внутри которой (прямо или через
// другие) звучит t(), тоже зависит от языка. Имена сравниваются без областей видимости, поэтому
// возможны редкие ложные срабатывания — достаточно вынести вызов в функцию.

import ts from "typescript";
import { describe, expect, it } from "vitest";

const I18N = new Set(["t", "count", "plural", "locale"]);
/** Методы, у которых обратный вызов выполняется на месте. */
const IMMEDIATE = new Set(["map", "filter", "forEach", "reduce", "flatMap", "some", "every", "find", "findIndex", "sort"]);

/** Кусок кода, который выполняется при загрузке модуля; `line` — номер его первой строки в файле. */
type Source = { file: string; text: string; line: number };

const calleeName = (call: ts.CallExpression): string | null =>
  ts.isIdentifier(call.expression) ? call.expression.text : ts.isPropertyAccessExpression(call.expression) ? call.expression.name.text : null;

/** Имя, под которым объявлена функция: `function f`, `const f = () =>`, метод, свойство. */
function declaredName(fn: ts.SignatureDeclaration): string | null {
  const own = (fn as { name?: ts.Node }).name;
  if (own && ts.isIdentifier(own)) return own.text;
  const parent: ts.Node = fn.parent;
  if ((ts.isVariableDeclaration(parent) || ts.isPropertyAssignment(parent) || ts.isPropertyDeclaration(parent)) && ts.isIdentifier(parent.name)) {
    return parent.name.text;
  }
  return null;
}

/** Выполняется ли узел при загрузке модуля (выше него нет функции, которая вызывается позже). */
function atModuleLevel(node: ts.Node): boolean {
  let cur: ts.Node | undefined = node.parent;
  while (cur) {
    if (ts.isSourceFile(cur)) return true;
    if (ts.isFunctionLike(cur)) {
      const fn: ts.Node = cur;
      const call: ts.Node = cur.parent;
      const onTheSpot =
        ts.isCallExpression(call) &&
        (call.expression === fn ||
          (ts.isPropertyAccessExpression(call.expression) && IMMEDIATE.has(call.expression.name.text) && call.arguments.some((a) => a === fn)));
      if (!onTheSpot) return false;
      cur = call.parent;
      continue;
    }
    // Поле класса считается при создании объекта, а не при загрузке модуля.
    if (ts.isPropertyDeclaration(cur) && !(ts.getCombinedModifierFlags(cur) & ts.ModifierFlags.Static)) return false;
    cur = cur.parent;
  }
  return true;
}

/** Вызовы языка на уровне модуля — строками «файл:строка: вызов». */
function scan(sources: Source[]): string[] {
  const parsed = sources.map(({ file, text, line }) => ({
    file,
    line,
    sf: ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS),
  }));

  // 1. Какие имена вызывает каждая функция проекта.
  const calls = new Map<string, Set<string>>();
  for (const { sf } of parsed) {
    const visit = (node: ts.Node): void => {
      if (ts.isFunctionLike(node)) {
        const name = declaredName(node);
        if (name) {
          const set = calls.get(name) ?? new Set<string>();
          const inner = (n: ts.Node): void => {
            if (ts.isCallExpression(n)) {
              const callee = calleeName(n);
              if (callee) set.add(callee);
            }
            ts.forEachChild(n, inner);
          };
          ts.forEachChild(node, inner);
          calls.set(name, set);
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }

  // 2. Функции, зависящие от языка: прямо или через другие такие функции.
  const dependent = new Set<string>();
  for (const [name, set] of calls) if ([...set].some((c) => I18N.has(c))) dependent.add(name);
  for (let changed = true; changed; ) {
    changed = false;
    for (const [name, set] of calls) {
      if (!dependent.has(name) && [...set].some((c) => dependent.has(c))) {
        dependent.add(name);
        changed = true;
      }
    }
  }

  // 3. Вызовы таких функций (и самого t) на уровне модуля.
  const hits: string[] = [];
  for (const { file, line, sf } of parsed) {
    const visit = (node: ts.Node): void => {
      if (ts.isCallExpression(node)) {
        const name = calleeName(node);
        const direct = ts.isIdentifier(node.expression) && I18N.has(node.expression.text);
        if (name && (direct || dependent.has(name)) && atModuleLevel(node)) {
          const at = sf.getLineAndCharacterOfPosition(node.getStart()).line;
          hits.push(`${file}:${line + at}: ${node.getText().replace(/\s+/g, " ").slice(0, 70)}`);
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }
  return hits;
}

/** Код, выполняемый при загрузке модуля: весь `.ts` и блоки `<script module>` в `.svelte`. */
function moduleCode(file: string, text: string): Source[] {
  if (file.endsWith(".ts")) return [{ file, text, line: 1 }];
  const out: Source[] = [];
  for (const m of text.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)) {
    if (!/\bmodule\b|\bcontext\s*=\s*["']module["']/.test(m[1] ?? "")) continue;
    const upToTag = text.slice(0, (m.index ?? 0) + m[0].indexOf(">") + 1);
    out.push({ file, text: m[2] ?? "", line: upToTag.split("\n").length });
  }
  return out;
}

const sources = import.meta.glob<string>(["./**/*.ts", "./**/*.svelte", "../main.ts", "!./**/*.test.ts", "!./i18n.ts"], {
  query: "?raw",
  import: "default",
  eager: true,
});

describe("язык окна", () => {
  it("исходники прочитаны, блоки <script module> найдены", () => {
    const files = Object.keys(sources);
    expect(files.length).toBeGreaterThan(50);
    expect(files.some((f) => f === "./api/zapret.ts")).toBe(true);
    const withModule = Object.entries(sources).filter(([f, text]) => f.endsWith(".svelte") && moduleCode(f, text).length > 0);
    expect(withModule.length).toBeGreaterThan(0);
  });

  it("t() и другие тексты не вызываются на уровне модуля", () => {
    const code = Object.entries(sources).flatMap(([path, text]) =>
      moduleCode(path.startsWith("../") ? `src/${path.slice(3)}` : `src/lib/${path.slice(2)}`, text),
    );
    expect(scan(code), "язык выбирается после загрузки модулей: вынеси вызов в функцию").toEqual([]);
  });

  describe("поиск вызовов", () => {
    const run = (text: string) => scan([{ file: "x.ts", text, line: 1 }]);

    it("находит t() в константе", () => {
      expect(run(`const a = { title: t("а", "b") };`)).toHaveLength(1);
    });

    it("не трогает вызовы внутри функций", () => {
      expect(run(`const a = () => ({ title: t("а", "b") });\nfunction b() { return count(1, [], []); }`)).toEqual([]);
    });

    it("находит вызов через функцию, которая зовёт t(), и обратный вызов map на месте", () => {
      const hits = run(`const title = (id: string) => t(id, id);\nconst list = ["a"].map((id) => ({ title: title(id) }));`);
      expect(hits).toHaveLength(1);
      expect(hits[0]).toContain("title(id)");
    });

    it("поле класса считается при создании, а не при загрузке", () => {
      expect(run(`class A { label = t("а", "b"); }`)).toEqual([]);
    });
  });
});
