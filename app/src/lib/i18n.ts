// Язык интерфейса: русский или английский. Тексты пишутся парой на месте —
// t("Подключить", "Connect"), — как `tr` в Rust. Язык ставится один раз до
// монтирования окна (main.ts); при смене в «Настройках» окно перезагружается,
// поэтому t() можно звать где угодно, без реактивности.

export type Lang = "ru" | "en";
export type LangChoice = "auto" | "ru" | "en";

let current: Lang = "ru";

export function setLang(lang: Lang): void {
  current = lang;
  document.documentElement.lang = lang;
}

export function lang(): Lang {
  return current;
}

export function isEn(): boolean {
  return current === "en";
}

/** Текст на текущем языке. */
export function t(ru: string, en: string): string {
  return current === "en" ? en : ru;
}

/** Слово при числе: русские формы «1 сервер, 2 сервера, 5 серверов» и
 *  английские «1 server, 2 servers». */
export function plural(
  n: number,
  ru: [one: string, few: string, many: string],
  en: [one: string, other: string],
): string {
  if (current === "en") return Math.abs(n) === 1 ? en[0] : en[1];
  const m10 = Math.abs(n) % 10;
  const m100 = Math.abs(n) % 100;
  if (m10 === 1 && m100 !== 11) return ru[0];
  if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return ru[1];
  return ru[2];
}

/** Число и слово: «3 сервера» / «3 servers». */
export function count(
  n: number,
  ru: [one: string, few: string, many: string],
  en: [one: string, other: string],
): string {
  return `${n} ${plural(n, ru, en)}`;
}

/** Локаль для дат и чисел. */
export function locale(): string {
  return current === "en" ? "en-US" : "ru-RU";
}

/** Язык браузера — для превью без приложения. */
export function browserLang(): Lang {
  const langs = navigator.languages?.length ? navigator.languages : [navigator.language];
  return langs.some((l) => /^(ru|be|kk)\b/i.test(l)) ? "ru" : "en";
}
