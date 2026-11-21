import { afterEach, describe, expect, it } from "vitest";
import type { ServicePick, ServicesSnapshot } from "../api";
import { setLang } from "../i18n";
import { ago, caption, isLastShown, stateText, toggledPick, viaHint, viaLabel } from "./format";

afterEach(() => setLang("ru"));

const NOW = 1_800_000_000_000;
const at = (secondsAgo: number) => NOW / 1000 - secondsAgo;

describe("ago", () => {
  it("только что, минуты, часы", () => {
    expect(ago(at(10), NOW)).toBe("только что");
    expect(ago(at(59), NOW)).toBe("только что");
    expect(ago(at(180), NOW)).toBe("3 мин назад");
    expect(ago(at(2 * 3600 + 5), NOW)).toBe("2 ч назад");
  });

  it("время из будущего (часы перевели назад) не уходит в минус", () => {
    expect(ago(at(-600), NOW)).toBe("только что");
  });

  it("по-английски", () => {
    setLang("en");
    expect(ago(at(300), NOW)).toBe("5 min ago");
    expect(ago(at(5), NOW)).toBe("just now");
  });
});

describe("подписи плиток", () => {
  it("путь и подсказка есть у каждого значения", () => {
    for (const via of ["vpn", "zapret", "direct", "proxy", "blocked"] as const) {
      expect(viaLabel(via)).not.toBe("");
      expect(viaHint("YouTube", via)).toContain("YouTube");
    }
    expect(viaLabel("direct")).toBe("напрямую");
    setLang("en");
    expect(viaLabel("direct")).toBe("direct");
    expect(viaLabel("vpn")).toBe("VPN");
  });

  it("состояние — словом, а не только цветом", () => {
    for (const state of ["unknown", "waiting", "works", "slow", "down"] as const) {
      expect(stateText(state)).not.toBe("");
    }
  });
});

describe("свой набор", () => {
  const pick = (id: string, chosen: boolean, offered = true): ServicePick => ({
    id,
    name: id,
    chosen,
    offered,
  });
  const picks = [pick("youtube", true), pick("discord", true), pick("instagram", false, false)];

  it("переключение снимает и ставит отметку, остальные не трогает", () => {
    expect(toggledPick(picks, "youtube")).toEqual(["discord"]);
    // Недоступный в режиме сервис не отмечается из окна, но если он уже в наборе — остаётся.
    const kept = [pick("youtube", true), pick("instagram", true, false)];
    expect(toggledPick(kept, "youtube")).toEqual(["instagram"]);
    expect(toggledPick(picks, "discord")).toEqual(["youtube"]);
  });

  it("набор по умолчанию в «Zapret»: сужение не теряет Instagram и ChatGPT", () => {
    // Без своего набора отмечено всё; два сервиса «Zapret» не показывает, но они остаются.
    const zapret = [
      pick("youtube", true),
      pick("discord", true),
      pick("instagram", true, false),
      pick("chatgpt", true, false),
    ];
    expect(toggledPick(zapret, "discord")).toEqual(["youtube", "instagram", "chatgpt"]);
  });

  it("последнюю показанную плитку снять нельзя", () => {
    expect(isLastShown(picks, "youtube")).toBe(false);
    const one = [pick("youtube", true), pick("discord", false), pick("instagram", true, false)];
    expect(isLastShown(one, "youtube")).toBe(true);
    expect(isLastShown(one, "discord")).toBe(false);
  });
});

describe("caption", () => {
  const snap = (over: Partial<ServicesSnapshot>): ServicesSnapshot => ({
    at: null,
    checking: false,
    running: "vpn",
    tiles: [],
    picks: [],
    custom: false,
    ...over,
  });

  it("не проверяли: без подключения — подсказка подключиться", () => {
    expect(caption(snap({ running: "off" }), NOW)).toMatch(/Подключитесь/);
    expect(caption(snap({}), NOW)).toBe("Ещё не проверяли");
  });

  it("проверка идёт", () => {
    expect(caption(snap({ checking: true, at: at(5) }), NOW)).toBe("Проверяю…");
  });

  it("итог: когда, и пометка, если шло мимо VPN", () => {
    expect(caption(snap({ at: at(240) }), NOW)).toBe("Проверено 4 мин назад");
    expect(caption(snap({ at: at(240), running: "off" }), NOW)).toBe("Проверено 4 мин назад · без VPN");
    setLang("en");
    expect(caption(snap({ at: at(240), running: "off" }), NOW)).toBe("Checked 4 min ago · without VPN");
  });
});
