// Скриншоты для README из превью интерфейса в режиме `?demo` (VPN подключён,
// аккуратные серверы, без плашки о новой версии — см. `demo` в src/lib/api.ts).
//
// Запуск: в одном терминале `npm run dev`, в другом
//   node scripts/screenshots.mjs [адрес превью]   (по умолчанию http://localhost:5173)
// Браузер — установленный Microsoft Edge: Playwright ничего не скачивает.
// Снимки — в assets/screenshots/<экран>-<язык>.png, размер окна как у KVT.

import { chromium } from "playwright-core";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const base = (process.argv[2] ?? "http://localhost:5173").replace(/\/$/, "");
const out = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../assets/screenshots",
);

const LABELS = {
  ru: {
    hybrid: "Гибрид",
    connected: "Подключено",
    home: "Главная",
    routing: "Маршрутизация",
    why: "Почему не работает?",
  },
  en: {
    hybrid: "Hybrid",
    connected: "Connected",
    home: "Home",
    routing: "Routing",
    why: "Why isn't it working?",
  },
};

async function shoot(browser, lang) {
  const l = LABELS[lang];
  const context = await browser.newContext({
    // Размер окна KVT по умолчанию (tauri.conf.json), чёткость — как на 4K.
    viewport: { width: 1000, height: 680 },
    deviceScaleFactor: 2,
    colorScheme: "dark",
    locale: lang === "en" ? "en-US" : "ru-RU",
  });
  // Язык превью (`previewLang` в api.ts) — до загрузки страницы.
  await context.addInitScript((value) => {
    localStorage.setItem("kvt.lang", value);
  }, lang);
  const page = await context.newPage();
  const save = async (name) => {
    // Клик мог прокрутить страницу — снимаем с начала.
    await page.evaluate(() => {
      window.scrollTo(0, 0);
      for (const el of document.querySelectorAll("*")) if (el.scrollTop) el.scrollTop = 0;
    });
    await page.waitForTimeout(200);
    await page.screenshot({ path: path.join(out, `${name}-${lang}.png`) });
  };
  const nav = (label) =>
    page.locator("nav").getByText(label, { exact: true }).click();

  await page.goto(`${base}/?demo`);
  await page.getByText(l.connected, { exact: true }).waitFor();

  // Главная: «Гибрид» — VPN и zapret вместе, главное отличие KVT.
  await page.getByText(l.hybrid, { exact: true }).first().click();
  await page.getByText(l.connected, { exact: true }).waitFor({ timeout: 10_000 });
  await page.waitForTimeout(1500); // пинг серверов
  await save("home");

  await nav("Zapret");
  await page.waitForTimeout(800);
  await save("zapret");

  await nav(l.routing);
  await page.waitForTimeout(800);
  await save("routing");

  await nav(l.home);
  await page.getByText(l.why, { exact: true }).click();
  await page.waitForTimeout(3000); // шаги проверки в превью идут по очереди
  await save("why");

  await context.close();
}

await mkdir(out, { recursive: true });
const browser = await chromium.launch({ channel: "msedge" });
try {
  for (const lang of ["ru", "en"]) {
    await shoot(browser, lang);
    console.log(`снято: ${lang}`);
  }
} finally {
  await browser.close();
}
console.log(`скриншоты: ${out}`);
