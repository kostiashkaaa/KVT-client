import { afterEach, describe, expect, it } from "vitest";
import type { WatchdogEvent } from "./api";
import { setLang } from "./i18n";
import { watchdogText } from "./appNotices.svelte";

afterEach(() => setLang("ru"));

const EVENTS: WatchdogEvent[] = [
  { kind: "captive_portal" },
  { kind: "server_removed", server: "Берлин" },
  { kind: "server_replaced", from: "Берлин", to: "Рига" },
  { kind: "switched", from: "Берлин", to: "Рига" },
  { kind: "no_network" },
  { kind: "no_alternative", server: "Берлин" },
  { kind: "gave_up" },
];

describe("watchdogText", () => {
  it("на каждое событие — своя фраза, имена серверов в ней есть", () => {
    const texts = EVENTS.map(watchdogText);
    expect(new Set(texts).size).toBe(EVENTS.length);
    expect(texts[1]).toContain("«Берлин»");
    expect(texts[2]).toContain("«Берлин»");
    expect(texts[2]).toContain("«Рига»");
    expect(texts[3]).toContain("«Рига»");
    expect(texts[5]).toContain("«Берлин»");
  });

  it("по-английски — своими словами и в своих кавычках", () => {
    setLang("en");
    const texts = EVENTS.map(watchdogText);
    expect(new Set(texts).size).toBe(EVENTS.length);
    expect(texts[1]).toContain("“Берлин”");
    expect(texts.every((x) => !/[а-я]/i.test(x.replace(/“Берлин”|“Рига”/g, "")))).toBe(true);
  });
});
