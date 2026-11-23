import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SubscriptionItem } from "../api";
import { setLang } from "../i18n";
import { customized, details, expiry, protocolTitle, skippedCount, skippedSummary, trouble, usage } from "./format";

// 16 ноября 2026, полдень UTC: от этой точки считаются «3 ч назад», «осталось 5 дней».
const NOW = Date.UTC(2026, 10, 16, 12, 0, 0);
const sec = (ms: number) => Math.floor(ms / 1000);
const HOUR = 3600;
const DAY = 86_400;
const GB = 2 ** 30;

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(NOW);
});

afterEach(() => {
  vi.useRealTimers();
  setLang("ru");
});

/** Подписка по ссылке с настройками по умолчанию; нужное в тесте — через `over`. */
function sub(over: Partial<SubscriptionItem> = {}): SubscriptionItem {
  return {
    id: "a",
    title: "Подписка",
    byUrl: true,
    servers: 12,
    usedBytes: null,
    totalBytes: null,
    expire: null,
    updatedAt: sec(NOW) - 3 * HOUR,
    nextUpdate: sec(NOW) + 5 * HOUR,
    renamed: false,
    lastError: null,
    failedAt: null,
    supportUrl: null,
    webPageUrl: null,
    announce: null,
    info: [],
    protocols: [],
    skipped: [],
    duplicates: 0,
    warnings: [],
    keys: [],
    hidden: 0,
    options: { keep: [], drop: [], client: null, userAgent: null, hwid: "auto", ownHwid: false, hwidSent: false },
    ...over,
  };
}

describe("protocolTitle", () => {
  it("известные протоколы — со своими названиями, незнакомые — заглавными", () => {
    expect(protocolTitle("vless")).toBe("VLESS");
    expect(protocolTitle("hysteria2")).toBe("Hysteria2");
    expect(protocolTitle("socks")).toBe("SOCKS5");
    expect(protocolTitle("wireguard")).toBe("WireGuard");
    expect(protocolTitle("amneziawg")).toBe("AmneziaWG");
    expect(protocolTitle("mieru")).toBe("MIERU");
  });

  it("HTTP-прокси называется на языке окна", () => {
    expect(protocolTitle("http")).toBe("HTTP-прокси");
    setLang("en");
    expect(protocolTitle("http")).toBe("HTTP proxy");
  });
});

describe("details", () => {
  it("по ссылке: серверы, когда обновлена и когда обновится", () => {
    expect(details(sub())).toBe("12 серверов · обновлена 3 ч назад · следующее через 5 ч");
  });

  it("подписка, которую ещё не удалось загрузить", () => {
    expect(details(sub({ servers: 0 }))).toContain("ещё не загружена");
  });

  it("ключи вручную не обновляются", () => {
    expect(details(sub({ byUrl: false, servers: 3 }))).toBe("3 сервера · добавлены вручную, не обновляются");
  });

  it("серверы, скрытые фильтром, видны в строке", () => {
    expect(details(sub({ hidden: 2 }))).toContain("12 серверов (ещё 2 скрыто фильтром)");
  });

  it("по-английски скобка со скрытыми серверами отделена пробелом", () => {
    setLang("en");
    expect(details(sub({ hidden: 2 }))).toContain("12 servers (2 more hidden by the filter)");
  });

  it("только что и минуты", () => {
    expect(details(sub({ updatedAt: sec(NOW) }))).toContain("обновлена только что");
    expect(details(sub({ updatedAt: sec(NOW) - 5 * 60 }))).toContain("обновлена 5 мин назад");
  });
});

describe("expiry", () => {
  it("до срока больше трёх суток — спокойный тон", () => {
    const e = expiry(sec(NOW) + 5 * DAY);
    expect(e.tone).toBe("ok");
    expect(e.text).toContain("осталось 5 дней");
  });

  it("три дня и меньше — предупреждение", () => {
    expect(expiry(sec(NOW) + 3 * DAY).tone).toBe("warn");
    expect(expiry(sec(NOW) + 1 * DAY).tone).toBe("warn");
    // Даже минута до срока — это ещё «осталось 1 день».
    expect(expiry(sec(NOW) + 60).text).toContain("осталось 1 день");
  });

  it("сегодня и просрочено — тревога", () => {
    // Срок вышел меньше суток назад — для окна это ещё «сегодня».
    expect(expiry(sec(NOW) - HOUR)).toEqual({ text: "Заканчивается сегодня", tone: "danger" });
    const gone = expiry(sec(NOW) - 2 * DAY);
    expect(gone.tone).toBe("danger");
    expect(gone.text).toContain("продлите у провайдера");
  });

  it("по-английски", () => {
    setLang("en");
    expect(expiry(sec(NOW) + 5 * DAY).text).toContain("5 days left");
  });
});

describe("usage", () => {
  it("нет данных о трафике — нет строки", () => {
    expect(usage(sub())).toBeNull();
  });

  it("без лимита: только сколько израсходовано", () => {
    const u = usage(sub({ usedBytes: 3 * GB, totalBytes: 0 }));
    expect(u?.share).toBeNull();
    expect(u?.tone).toBe("ok");
    expect(u?.text).toContain("без лимита");
  });

  it("тон по доле: до 90 % — спокойно, выше — предупреждение, всё — тревога", () => {
    expect(usage(sub({ usedBytes: 50 * GB, totalBytes: 100 * GB }))?.tone).toBe("ok");
    expect(usage(sub({ usedBytes: 91 * GB, totalBytes: 100 * GB }))?.tone).toBe("warn");
    const out = usage(sub({ usedBytes: 120 * GB, totalBytes: 100 * GB }));
    expect(out?.tone).toBe("danger");
    expect(out?.share).toBe(1);
    expect(out?.text).toContain("Трафик закончился");
  });

  it("сколько осталось — в строке", () => {
    expect(usage(sub({ usedBytes: 25 * GB, totalBytes: 100 * GB }))?.text).toBe("25 из 100 ГБ · осталось 75 ГБ");
  });
});

describe("пропущенные строки", () => {
  it("считаются по всем причинам", () => {
    expect(skippedCount(sub())).toBe(0);
    expect(skippedCount(sub({ skipped: [{ reason: "a", count: 2 }, { reason: "b", count: 3 }] }))).toBe(5);
  });

  it("сводка: строки и повторы через точку", () => {
    const s = sub({ duplicates: 1 });
    expect(skippedSummary(s, 5)).toBe("Пропущено 5 строк · убрано повторов: 1");
    expect(skippedSummary(s, 0)).toBe("убрано повторов: 1");
    expect(skippedSummary(sub(), 1)).toBe("Пропущено 1 строка");
  });
});

describe("trouble", () => {
  it("причина с точкой на конце и пометка, что прежние серверы работают", () => {
    const s = sub({ lastError: "Нет ответа!", servers: 5 });
    expect(trouble(s, sec(NOW) - 2 * HOUR)).toBe("Не обновилась 2 ч назад: Нет ответа. Пока работают серверы из прошлой версии.");
  });

  it("без серверов — без пометки", () => {
    const s = sub({ lastError: "Нет ответа.", servers: 0 });
    expect(trouble(s, sec(NOW) - 2 * HOUR)).toBe("Не обновилась 2 ч назад: Нет ответа.");
  });

  it("по-английски пометка отделена от причины пробелом", () => {
    setLang("en");
    const s = sub({ lastError: "No answer!", servers: 5 });
    expect(trouble(s, sec(NOW) - 2 * HOUR)).toBe("Not updated 2 h ago: No answer. Servers from the previous version still work.");
  });
});

describe("customized", () => {
  it("настройки по умолчанию — не «настроено»", () => {
    expect(customized(sub())).toBe(false);
  });

  it("любое отличие видно", () => {
    const base = sub().options;
    expect(customized(sub({ options: { ...base, keep: ["NL"] } }))).toBe(true);
    expect(customized(sub({ options: { ...base, drop: ["test"] } }))).toBe(true);
    expect(customized(sub({ options: { ...base, client: "v2rayn" } }))).toBe(true);
    expect(customized(sub({ options: { ...base, hwid: "always" } }))).toBe(true);
    expect(customized(sub({ options: { ...base, ownHwid: true } }))).toBe(true);
  });
});
