import { describe, expect, it } from "vitest";
import type { PanelServer, PanelSubscription } from "../lib/api";
import {
  alternative,
  nextReceived,
  noticeAction,
  noticeText,
  pickNotice,
  pingText,
  protoLabel,
  usageOf,
} from "./format";

const server = (patch: Partial<PanelServer> = {}): PanelServer => ({
  key: "a",
  name: "Нидерланды",
  flag: "nl",
  protocol: "vless",
  transport: "tcp",
  security: "reality",
  pingMs: 38,
  health: "works",
  ...patch,
});

const sub = (patch: Partial<PanelSubscription> = {}): PanelSubscription => ({
  title: "Мой VPN",
  usedBytes: 34 * 2 ** 30,
  totalBytes: 200 * 2 ** 30,
  expire: null,
  ...patch,
});

const DAY = 86400;
const NOW = 1_800_000_000;

describe("protoLabel", () => {
  it("протокол и защита", () => {
    expect(protoLabel(server())).toBe("VLESS · REALITY");
    expect(protoLabel(server({ security: "tls", transport: "xhttp" }))).toBe("VLESS · XHTTP");
    expect(protoLabel(server({ security: "tls" }))).toBe("VLESS · TLS");
    expect(protoLabel(server({ protocol: "shadowsocks", security: "none" }))).toBe("Shadowsocks");
    expect(protoLabel(server({ protocol: "amneziawg", transport: "udp", security: "none" }))).toBe("AmneziaWG");
  });
});

describe("pingText", () => {
  it("задержка, неработающий и не проверенный", () => {
    expect(pingText(server())).toBe("38 мс");
    expect(pingText(server({ pingMs: null, health: "down" }))).toBe("не работает");
    expect(pingText(server({ pingMs: null, health: "unknown" }))).toBe("");
  });
});

describe("usageOf", () => {
  it("остаток трафика с полосой", () => {
    expect(usageOf(sub())).toEqual({ label: "Мой VPN · 34 из 200 ГБ", percent: 17 });
  });

  it("лимита нет — строки нет", () => {
    expect(usageOf(sub({ totalBytes: null }))).toBeNull();
    expect(usageOf(null)).toBeNull();
  });

  it("сколько израсходовано, не известно — только лимит, без полосы", () => {
    expect(usageOf(sub({ usedBytes: null }))).toEqual({ label: "Мой VPN · 200 ГБ", percent: null });
  });

  it("перерасход не вылезает за полосу", () => {
    expect(usageOf(sub({ usedBytes: 300 * 2 ** 30 }))?.percent).toBe(100);
  });
});

describe("pickNotice", () => {
  it("новая версия важнее срока подписки", () => {
    const n = pickNotice("0.9.8", sub({ expire: NOW + DAY }), NOW);
    expect(n).toEqual({ kind: "update", version: "0.9.8" });
    expect(noticeText(n!)).toBe("Вышла KVT 0.9.8");
    expect(noticeAction(n!)).toBe("Скачать");
  });

  it("подписка заканчивается через три суток и меньше", () => {
    expect(pickNotice(null, sub({ expire: NOW + 3 * DAY }), NOW)).toMatchObject({ kind: "expiring", days: 3 });
    expect(pickNotice(null, sub({ expire: NOW + 3 * DAY + 1 }), NOW)).toBeNull();
    expect(pickNotice(null, sub({ expire: NOW + 3600 }), NOW)).toMatchObject({ days: 1, expired: false });
  });

  it("подписка закончилась", () => {
    const n = pickNotice(null, sub({ expire: NOW - DAY }), NOW);
    expect(n).toMatchObject({ kind: "expiring", expired: true });
    expect(noticeText(n!)).toBe("Подписка «Мой VPN» закончилась");
  });

  it("без срока и без подписки напоминать не о чем", () => {
    expect(pickNotice(null, sub({ expire: null }), NOW)).toBeNull();
    expect(pickNotice(null, null, NOW)).toBeNull();
  });

  it("число суток склоняется", () => {
    const text = (days: number) => noticeText(pickNotice(null, sub({ expire: NOW + days * DAY }), NOW)!);
    expect(text(1)).toBe("Подписка «Мой VPN» заканчивается через 1 день");
    expect(text(2)).toBe("Подписка «Мой VPN» заканчивается через 2 дня");
    expect(text(3)).toBe("Подписка «Мой VPN» заканчивается через 3 дня");
  });
});

describe("nextReceived", () => {
  const prev = { secs: 100, at: 0 };

  it("ответ чуть позади своего счёта время назад не откатывает", () => {
    expect(nextReceived(prev, 101, 2000)).toBe(prev);
  });

  it("ответ впереди счёта — берём его", () => {
    expect(nextReceived(prev, 110, 2000)).toEqual({ secs: 110, at: 2000 });
  });

  it("сильно меньше — новый сеанс", () => {
    expect(nextReceived({ secs: 4000, at: 0 }, 5, 3000)).toEqual({ secs: 5, at: 3000 });
  });
});

describe("alternative", () => {
  it("первый не текущий и не нерабочий", () => {
    const list = [
      server({ key: "a" }),
      server({ key: "b", health: "down", pingMs: null }),
      server({ key: "c", pingMs: 60 }),
    ];
    expect(alternative(list, "a")?.key).toBe("c");
    expect(alternative(list, "c")?.key).toBe("a");
  });

  it("других нет", () => {
    expect(alternative([server({ key: "a" })], "a")).toBeNull();
    expect(alternative([], null)).toBeNull();
  });
});
