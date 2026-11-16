import { afterEach, describe, expect, it } from "vitest";
import { defaultZapret, formatBytes, formatElapsed, strategyFor, strategyTitle } from "./api";
import { count, plural, setLang } from "./i18n";
import { tidy } from "./typography";

const NBSP = " ";

afterEach(() => setLang("ru"));

describe("formatElapsed", () => {
  it("минуты и секунды, часы — когда есть", () => {
    expect(formatElapsed(0)).toBe("0:00");
    expect(formatElapsed(42)).toBe("0:42");
    expect(formatElapsed(725)).toBe("12:05");
    expect(formatElapsed(4325)).toBe("1:12:05");
  });

  it("отрицательное и дробное не ломают строку", () => {
    expect(formatElapsed(-5)).toBe("0:00");
    expect(formatElapsed(59.9)).toBe("0:59");
  });
});

describe("formatBytes", () => {
  // Число и единица — через неразрывный пробел.
  it("по-русски — с запятой", () => {
    expect(formatBytes(512)).toBe(`512${NBSP}Б`);
    expect(formatBytes(84 * 1024 * 1024)).toBe(`84,0${NBSP}МБ`);
    expect(formatBytes(1.24 * 1024 ** 3)).toBe(`1,24${NBSP}ГБ`);
  });

  it("по-английски — с точкой и своими единицами", () => {
    setLang("en");
    expect(formatBytes(1.24 * 1024 ** 3)).toBe(`1.24${NBSP}GB`);
    expect(formatBytes(999)).toBe(`999${NBSP}B`);
  });

  it("больше терабайта остаётся в терабайтах", () => {
    expect(formatBytes(5000 * 1024 ** 4)).toBe(`5000${NBSP}ТБ`);
  });
});

describe("plural и count", () => {
  const ru: [string, string, string] = ["сервер", "сервера", "серверов"];
  const en: [string, string] = ["server", "servers"];

  it("русские формы, включая 11–14", () => {
    const cases: [number, string][] = [
      [1, "сервер"],
      [2, "сервера"],
      [5, "серверов"],
      [11, "серверов"],
      [12, "серверов"],
      [21, "сервер"],
      [22, "сервера"],
      [111, "серверов"],
      [0, "серверов"],
    ];
    for (const [n, word] of cases) expect(plural(n, ru, en), String(n)).toBe(word);
  });

  it("английские формы и count", () => {
    setLang("en");
    expect(count(1, ru, en)).toBe("1 server");
    expect(count(3, ru, en)).toBe("3 servers");
    expect(count(-1, ru, en)).toBe("-1 server");
  });
});

describe("стратегия zapret", () => {
  it("для сети — подобранная, иначе выбранная, иначе основная", () => {
    const z = { ...defaultZapret(), strategy: null, byNetwork: { home: "general (ALT4)" } };
    expect(strategyFor(z, "home")).toBe("general (ALT4)");
    expect(strategyFor(z, "cafe")).toBe("general");
    expect(strategyFor({ ...z, strategy: "general (ALT2)" }, "cafe")).toBe("general (ALT2)");
    expect(strategyFor({ ...z, strategy: "general (ALT2)" }, null)).toBe("general (ALT2)");
  });

  it("название без «general»", () => {
    expect(strategyTitle("general (ALT4)")).toBe("ALT4");
    expect(strategyTitle("general")).toBe("Основная");
    expect(strategyTitle("discord")).toBe("discord");
    setLang("en");
    expect(strategyTitle("general")).toBe("Main");
  });
});

describe("типографика", () => {
  it("предлог и число не отрываются, тире не начинает строку", () => {
    expect(tidy("в сети")).toBe(`в${NBSP}сети`);
    expect(tidy("скачано 200 КБ")).toBe(`скачано 200${NBSP}КБ`);
    expect(tidy("VPN — подключён")).toBe(`VPN${NBSP}— подключён`);
    expect(tidy("работает ли сайт")).toBe(`работает${NBSP}ли сайт`);
  });

  it("английский текст не меняется", () => {
    expect(tidy("Connect to a server")).toBe("Connect to a server");
  });
});
