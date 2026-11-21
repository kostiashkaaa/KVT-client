import { describe, expect, it } from "vitest";
import { defaultDns, defaultRouting, defaultZapret } from "./api";
import { routingKeyOf, settingsKeyOf, telegramOf, zapretKeyOf } from "./connectKeys";

describe("zapretKeyOf", () => {
  it("автопроверка и автоподбор на запуск не влияют", () => {
    const z = defaultZapret();
    const same = zapretKeyOf({ ...z, autoCheck: !z.autoCheck, autoPick: !z.autoPick });
    expect(same).toBe(zapretKeyOf(z));
  });

  it("стратегия, игровой фильтр и Telegram меняют ключ", () => {
    const z = defaultZapret();
    const base = zapretKeyOf(z);
    expect(zapretKeyOf({ ...z, strategy: "general (ALT4)" })).not.toBe(base);
    expect(zapretKeyOf({ ...z, gameFilter: "all" })).not.toBe(base);
    expect(zapretKeyOf({ ...z, telegram: !z.telegram })).not.toBe(base);
  });
});

describe("routingKeyOf", () => {
  it("порядок выбора списков не важен", () => {
    const r = defaultRouting();
    const a = routingKeyOf({ ...r, overrides: { ads: "block", games: "direct" } });
    const b = routingKeyOf({ ...r, overrides: { games: "direct", ads: "block" } });
    expect(a).toBe(b);
  });

  it("другое действие для списка или режим списков меняют ключ", () => {
    const r = defaultRouting();
    const base = routingKeyOf({ ...r, overrides: { ads: "block" } });
    expect(routingKeyOf({ ...r, overrides: { ads: "proxy" } })).not.toBe(base);
    expect(routingKeyOf({ ...r, overrides: { ads: "block" }, listMode: "full" })).not.toBe(base);
  });
});

describe("settingsKeyOf", () => {
  it("kill switch и DNS меняют ключ", () => {
    const dns = defaultDns();
    const base = settingsKeyOf(false, dns);
    expect(settingsKeyOf(true, dns)).not.toBe(base);
    expect(settingsKeyOf(false, { ...dns, local: "google" })).not.toBe(base);
    expect(settingsKeyOf(false, { ...dns, remote: "quad9" })).not.toBe(base);
  });
});

describe("telegramOf", () => {
  it("из ключа zapret — только Telegram и его путь", () => {
    const z = { ...defaultZapret(), telegram: true, telegramRoute: "direct" as const };
    expect(telegramOf(zapretKeyOf(z))).toBe("true:direct");
    const other = { ...z, strategy: "general (ALT)", gameFilter: "tcp" as const };
    expect(telegramOf(zapretKeyOf(other))).toBe(telegramOf(zapretKeyOf(z)));
  });
});
