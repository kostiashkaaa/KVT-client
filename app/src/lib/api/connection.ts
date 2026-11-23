// Подключение: серверы и группы, выбор, маршрутизация, статус и сеанс службы.

import { isEn, t } from "../i18n";
import { inTauri, invoke } from "./bridge";
import type { DnsChoice, NetworkProfile } from "./network";
import { demo, demoState, previewAdd, setDemoState, previewData, withStressGroup } from "./preview";
import type { ZapretChoice } from "./zapret";

export interface ServerSummary {
  /** Постоянный ключ сервера: выбор и проверки привязаны к нему, а не к номеру. */
  key: string;
  /** Название как в подписке без ведущего флага; флаги внутри («→🇪🇪») остаются. */
  name: string;
  /** Страна (`ru`): по первому флагу в названии, как в других клиентах, а если его нет —
   *  по адресу-IP сервера (локальная база, без сети; у доменных адресов флага нет). */
  flag: string | null;
  protocol: string;
  transport: string;
  security: string;
  core: "xray" | "sing-box" | "sing-box-awg";
  /** Тот же сервер, что у ключа выше в списке: провайдер повторил его под другим
   *  названием. Автопереключение такой повтор не перебирает. */
  sameAs: string | null;
}

export interface SubscriptionInfo {
  title: string | null;
  usedBytes: number | null;
  totalBytes: number | null;
  /** Unix-время окончания подписки. */
  expire: number | null;
  supportUrl: string | null;
  announce: string | null;
}

/** Подписка или вручную добавленные ключи — группа в общем списке серверов. */
export interface Group {
  id: string;
  title: string;
  byUrl: boolean;
  updatedAt: number;
  meta: SubscriptionInfo;
  servers: ServerSummary[];
  info: string[];
  /** Сколько строк подписки не разобралось. */
  errors: number;
}

export interface Added {
  /** Первая добавленная группа. */
  group: string | null;
  /** Первый сервер новой подписки — его сразу выбираем. */
  first: string | null;
  servers: number;
  /** Сколько подписок по ссылке добавлено (или обновлено, если уже были). */
  subscriptions: number;
  /** Что не добавилось (часть вставки) — тексты без ссылок. */
  failed: string[];
}

export type Mode = "vpn" | "hybrid" | "zapret";


/** Любая вставка: ссылки на подписки (одна, несколько или внутри текста), ссылки
 *  «добавить в приложение» (happ://add/…), ключи, base64, конфиги Xray и sing-box.
 *  Разбирает Rust; если добавилась только часть, причины — в `failed`. */
export async function addSubscription(input: string): Promise<Added> {
  if (!inTauri) {
    if (
      /(^|\s)https?:\/\/(?![^\s/@]+@[^\s/?#]+\/?([?#\s]|$))/i.test(input) &&
      !/(vless|vmess|trojan|ss|hy2|hysteria2|tuic|anytls|socks5?):\/\//i.test(
        input,
      )
    )
      throw new Error(
        t("Загрузка подписки по ссылке работает в приложении (npm run tauri dev).", "Loading a subscription by link works in the app (npm run tauri dev)."),
      );
    return previewAdd(input);
  }
  return invoke<Added>("add_input", { input });
}

export type QuickResult =
  | { kind: "reachable"; latency_ms: number }
  | { kind: "unreachable" }
  | { kind: "dns_failed" }
  | { kind: "not_applicable" };

/** Быстрая проверка: TCP-пинг без TLS. `group` — одна подписка, `null` — все. Итог — по ключам серверов. */
export async function quickCheck(
  group: string | null,
): Promise<Record<string, QuickResult>> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 600));
    const out: Record<string, QuickResult> = {};
    previewData()
      .filter((g) => group === null || g.id === group)
      .flatMap((g) => g.servers)
      .forEach((s, i) => {
        const demoMs = [38, 47, 52, 61, 66, 74, 118, 83, 55];
        out[s.key] = demo
          ? { kind: "reachable", latency_ms: demoMs[i % demoMs.length]! }
          : i === 1
            ? { kind: "unreachable" }
            : { kind: "reachable", latency_ms: 40 + i * 37 };
      });
    return out;
  }
  return invoke<Record<string, QuickResult>>("quick_check", { group });
}

export type ServiceStatus =
  | { state: "disconnected" }
  | { state: "connecting" }
  | { state: "connected"; core: "xray" | "sing-box" | "sing-box-awg" }
  | { state: "zapret"; strategy: string }
  /** `blocked` — ядро остановилось, а kill switch держит интернет закрытым. */
  | { state: "failed"; reason: string; blocked?: boolean };

export type ListAction = "proxy" | "direct" | "block";

export interface RoutingSettings {
  /** compact — списки podkop (itdoginfo), full — реестр runetfreedom. */
  listMode: "compact" | "full";
  /** Куда идёт всё, что не попало в списки. */
  everythingElse: "proxy" | "direct";
  /** Выбор для отдельных списков: id → действие. */
  overrides: Record<string, ListAction>;
  /** Свои сайты и адреса: важнее списков. */
  custom: CustomRoute[];
}

/** Свой сайт: домен со всеми поддоменами, IP или подсеть. */
export interface CustomRoute {
  target: string;
  action: ListAction;
}

export const defaultRouting = (): RoutingSettings => ({
  listMode: "compact",
  everythingElse: "proxy",
  overrides: {},
  custom: [],
});

export interface Choice {
  /** Ключ выбранного сервера. */
  server: string | null;
  mode: Mode | null;
  killSwitch: boolean;
  routing: RoutingSettings;
  dns: DnsChoice;
  /** Переключаться на другой сервер, если через текущий перестали идти данные. */
  autoSwitch: boolean;
  networks: NetworkProfile[];
  zapret: ZapretChoice;
  /** Уведомления Windows, пока окно закрыто. */
  notifications: boolean;
  /** Подключаться к выбранному серверу при запуске KVT. */
  connectOnStart: boolean;
  /** Узнавать у GitHub, не вышла ли новая версия KVT. */
  checkUpdates: boolean;
  /** Подсказки первого запуска пройдены или пропущены. */
  onboarded: boolean;
  /** Левый клик по значку в трее открывает мини-панель; выключено — окно KVT. */
  miniPanel: boolean;
}

export interface ListInfo {
  id: string;
  title: string;
  kind: "region" | "category" | "service";
  /** Что входит в список; пусто — подсказки нет. */
  hint: string;
}

export async function listCatalog(): Promise<ListInfo[]> {
  if (!inTauri) {
    return [
      {
        id: "russia_inside",
        title: t("Заблокировано в России", "Blocked in Russia"),
        kind: "region",
        hint: t("Сайты и сервисы из реестра блокировок и замедленные", "Sites and services from the block registry, plus throttled ones"),
      },
      {
        id: "russia_outside",
        title: t("Российские сайты, закрытые для зарубежа", "Russian sites closed to foreign visitors"),
        kind: "region",
        hint: t("Госуслуги, банки, магазины — не открываются с зарубежных IP", "Gosuslugi, banks, shops — don't open from foreign IPs"),
      },
      {
        id: "geoblock",
        title: t("Сервисы, закрытые для России", "Services closed to Russia"),
        kind: "category",
        hint: t("ИИ, стриминг и магазины, которые сами не пускают из России", "AI, streaming and shops that refuse visitors from Russia"),
      },
      {
        id: "news",
        title: t("Новости", "News"),
        kind: "category",
        hint: t("Заблокированные СМИ", "Blocked media"),
      },
      {
        id: "youtube",
        title: "YouTube",
        kind: "service",
        hint: "youtube.com, googlevideo.com, ytimg.com",
      },
      {
        id: "discord",
        title: "Discord",
        kind: "service",
        hint: t("discord.com, discord.gg, голосовые серверы", "discord.com, discord.gg, voice servers"),
      },
      {
        id: "telegram",
        title: "Telegram",
        kind: "service",
        hint: t("t.me, telegram.org и адреса серверов", "t.me, telegram.org and server addresses"),
      },
      { id: "roblox", title: "Roblox", kind: "service", hint: "" },
    ];
  }
  return invoke<ListInfo[]>("list_catalog");
}

/** Свой сайт в том виде, в каком он попадёт в правило, или текст ошибки. */
export async function checkRouteTarget(target: string): Promise<string> {
  if (!inTauri) {
    const value = target.trim().toLowerCase();
    if (!value) throw t("Введите адрес сайта, IP или подсеть.", "Enter a site address, IP or subnet.");
    if (/\s/.test(value)) throw t("Одно правило — один адрес, без пробелов.", "One rule, one address, no spaces.");
    const host = value
      .replace(/^[a-z]+:\/\//, "")
      .split(/[/?#]/)[0]!
      .replace(/^.*@/, "")
      .replace(/:\d+$/, "")
      .replace(/^\*\./, "")
      .replace(/^www\./, "");
    if (!/^[\p{L}\d-]+(\.[\p{L}\d-]+)*$/u.test(host))
      throw t("Не похоже на адрес сайта. Пример: example.com", "Doesn't look like a site address. Example: example.com");
    return host;
  }
  return invoke<string>("check_route_target", { target });
}

/** Выбор сервера, режима и kill switch хранится в Rust — им пользуется и трей. */
export async function setChoice(choice: Choice): Promise<void> {
  if (inTauri) await invoke("set_choice", { choice });
}

/** Состояние для окна, открытого заново из трея. */
export async function snapshot(): Promise<{
  groups: Group[];
  choice: Choice | null;
}> {
  if (!inTauri) return { groups: withStressGroup(previewData()), choice: null };
  return invoke("snapshot");
}

export async function connect(): Promise<ServiceStatus> {
  if (demo) {
    await new Promise((r) => setTimeout(r, 1200));
    return setDemoState({ state: "connected", core: "xray" });
  }
  if (!inTauri)
    throw new Error(
      t("Подключение работает в приложении (npm run tauri dev) при запущенной службе.", "Connecting works in the app (npm run tauri dev) with the service running."),
    );
  return invoke<ServiceStatus>("connect");
}

export type CheckResult =
  | { verdict: "ok"; detail: string }
  | { verdict: "warning"; detail: string }
  | { verdict: "info"; detail: string };

export interface LeakReport {
  /** VPN был подключён: без него маршруты и DNS проверять не на что. */
  connected: boolean;
  openProxies: {
    port: number;
    process: string | null;
    knownScanPort: boolean;
  }[];
  ipv4Route: CheckResult;
  ipv6Route: CheckResult;
  dns: CheckResult;
}

export async function leakTest(): Promise<LeakReport> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 500));
    return {
      connected: false,
      openProxies: [
        { port: 10808, process: "example-vpn.exe", knownScanPort: false },
      ],
      ipv4Route: {
        verdict: "info",
        detail: t("VPN выключен: трафик идёт напрямую", "VPN is off: traffic goes direct"),
      },
      ipv6Route: {
        verdict: "ok",
        detail: t("IPv6 в интернет недоступен — утечки через IPv6 быть не может", "IPv6 internet is unavailable — no leak via IPv6 is possible"),
      },
      dns: {
        verdict: "info",
        detail: t("VPN выключен: DNS обслуживает провайдер", "VPN is off: DNS is served by your ISP"),
      },
    };
  }
  return invoke<LeakReport>("leak_test");
}

export async function disconnect(): Promise<ServiceStatus> {
  if (!inTauri) {
    return setDemoState({ state: "disconnected" });
  }
  return invoke<ServiceStatus>("disconnect");
}

/** `null` — служба не запущена. */
export async function serviceStatus(): Promise<ServiceStatus | null> {
  if (!inTauri) return demo ? demoState : null;
  return invoke<ServiceStatus | null>("service_status");
}

/** Сеанс — от «Подключить» до «Отключить»: время и трафик через адаптер KVT. */
export interface Session {
  secs: number;
  /** `null` — адаптера нет (режим Zapret). */
  rx: number | null;
  tx: number | null;
}

const previewStart = Date.now();

/** Последний сеанс, о котором сообщила служба (берётся после `serviceStatus`). */
export async function serviceSession(): Promise<Session | null> {
  if (!inTauri)
    return {
      secs: 4325 + Math.floor((Date.now() - previewStart) / 1000),
      rx: 1_331_000_000,
      tx: 88_200_000,
    };
  return invoke<Session | null>("service_session");
}

/** 0:42, 12:05, 1:12:05 — секунды сеанса для строки на главной. */
export function formatElapsed(secs: number): string {
  const s = Math.max(0, Math.floor(secs));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const ss = String(s % 60).padStart(2, "0");
  return h > 0 ? `${h}:${String(m).padStart(2, "0")}:${ss}` : `${m}:${ss}`;
}

/** 84 МБ, 1,24 ГБ — с запятой, без лишних знаков. */
export function formatBytes(bytes: number): string {
  const en = isEn();
  const units = en ? ["B", "KB", "MB", "GB", "TB"] : ["Б", "КБ", "МБ", "ГБ", "ТБ"];
  let value = bytes;
  let unit = 0;
  while (value >= 1000 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  const digits = unit === 0 || value >= 100 ? 0 : value >= 10 ? 1 : 2;
  const text = value.toFixed(digits);
  return `${en ? text : text.replace(".", ",")} ${units[unit]}`;
}
