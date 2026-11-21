// Дымовой прогон интерфейса: превью (данные-заглушки из src/lib/api/preview.ts)
// открывается на обоих языках, каждый раздел показывается (и каждый кадр мини-панели
// из трея), в консоли нет ошибок.
//
// Запуск: `npm run smoke`. Vite поднимается здесь же на свободном порту. Браузер —
// установленный: Microsoft Edge на Windows, Google Chrome на Linux (раннер CI);
// Playwright ничего не скачивает. Свой: `KVT_BROWSER=chrome|msedge`.

import { chromium } from "playwright-core";
import { createServer } from "vite";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const channel = process.env.KVT_BROWSER ?? (process.platform === "win32" ? "msedge" : "chrome");

// Подписи разделов в боковой панели (NavRail.svelte) и то, что видно на каждом.
const PAGES = {
  ru: [
    ["Главная", "Серверы"],
    ["Подписки", "Подписки"],
    ["Маршрутизация", "Маршрутизация"],
    ["Zapret", "Zapret"],
    ["Проверка", "Почему не работает?"],
    ["Журнал", "Журнал"],
    ["Настройки", "Kill switch"],
  ],
  en: [
    ["Home", "Servers"],
    ["Subscriptions", "Subscriptions"],
    ["Routing", "Routing"],
    ["Zapret", "Zapret"],
    ["Check", "Why isn't it working?"],
    ["Log", "Log"],
    ["Settings", "Kill switch"],
  ],
};

/** Страница с языком окна и сбором ошибок: исключения, ошибки консоли, неудачные загрузки. */
async function open(browser, base, lang, url, viewport) {
  const errors = [];
  const context = await browser.newContext({ viewport });
  await context.addInitScript((value) => localStorage.setItem("kvt.lang", value), lang);
  const page = await context.newPage();
  page.on("pageerror", (e) => errors.push(`исключение: ${e.message}`));
  page.on("console", (m) => {
    // Неудачные загрузки — ниже, с адресом.
    if (m.type() === "error" && !m.text().startsWith("Failed to load resource")) {
      errors.push(`консоль: ${m.text()}`);
    }
  });
  page.on("response", (r) => {
    if (r.status() >= 400) errors.push(`${r.status()}: ${r.url().replace(base, "")}`);
  });
  await page.goto(`${base}/${url}`);
  return { page, context, errors };
}

async function run(browser, base, lang, query) {
  const { page, context, errors } = await open(browser, base, lang, query, { width: 1000, height: 680 });
  for (const [label, expected] of PAGES[lang]) {
    // Не точное совпадение: у «Настроек» бывает приписка о новой версии.
    await page.locator("nav").getByText(label).first().click();
    await page.locator("main").getByText(expected).first().waitFor({ timeout: 5000 });
  }
  await context.close();
  return errors.map((e) => `${lang} ${query || "/"}: ${e}`);
}

// Мини-панель из трея (mini.html): кадры состояний и заголовок, который в них виден.
const PANEL = [
  ["?demo", { ru: "Подключено", en: "Connected" }],
  ["?demo&frame=nodata&notice=update", { ru: "Сайты не открываются", en: "Sites don't open" }],
  ["?demo&frame=blocked", { ru: "Интернет закрыт", en: "Internet blocked" }],
  ["?demo&frame=zapret&notice=expiring", { ru: "Zapret работает", en: "Zapret is on" }],
  ["?demo&frame=off", { ru: "Отключено", en: "Disconnected" }],
  ["?demo&frame=connecting", { ru: "Подключение…", en: "Connecting…" }],
  ["", { ru: "Служба KVT не запущена", en: "The KVT service isn't running" }],
];

async function runPanel(browser, base, lang, query, title) {
  const { page, context, errors } = await open(browser, base, lang, `mini.html${query}`, { width: 420, height: 720 });
  await page.getByRole("dialog").getByText(title, { exact: true }).first().waitFor({ timeout: 5000 });
  await context.close();
  return errors.map((e) => `${lang} mini.html${query}: ${e}`);
}

const server = await createServer({
  root,
  logLevel: "error",
  server: { port: 0, strictPort: false },
});
await server.listen();
const base = server.resolvedUrls?.local[0]?.replace(/\/$/, "");
let browser;
let failed = [];
try {
  if (!base) throw new Error("Vite не сказал адрес");
  browser = await chromium.launch({ channel });
  for (const lang of ["ru", "en"]) {
    for (const query of ["", "?demo", "?servers=2000"]) {
      failed = failed.concat(await run(browser, base, lang, query));
      console.log(`ок: ${lang} ${query || "/"}`);
    }
    for (const [query, titles] of PANEL) {
      failed = failed.concat(await runPanel(browser, base, lang, query, titles[lang]));
      console.log(`ок: ${lang} mini.html${query}`);
    }
  }
} catch (e) {
  failed.push(String(e?.message ?? e));
} finally {
  await browser?.close();
  await server.close();
}
if (failed.length) {
  console.error(failed.join("\n"));
  process.exit(1);
}
console.log("дымовой прогон: всё открылось без ошибок");
