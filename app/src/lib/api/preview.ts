import { t } from "../i18n";
import { inTauri } from "./bridge";
import type { Added, Group, Mode, ServerSummary, ServiceStatus } from "./connection";
import type { PanelServer, PanelView } from "./panel";
import type { ServicesSnapshot, ServiceTile } from "./services";

// Предпросмотр интерфейса в обычном браузере (npm run dev) без Rust-части.
// Флаг — первый эмодзи-флаг, ведущий уходит из названия (упрощённо, как kvt_core::flag).
function previewServer(name: string, i: number, group: string): ServerSummary {
  const first = /([\u{1F1E6}-\u{1F1FF}]{2})/u.exec(name);
  const flag = first
    ? Array.from(first[1]!, (c) =>
        String.fromCharCode(97 + c.codePointAt(0)! - 0x1f1e6),
      ).join("")
    : null;
  const leading = first?.index === 0;
  return {
    key: `${group}-${i}`,
    name: leading
      ? name.slice(first![1]!.length).replace(/^[\s|·,:\uFE0F]+/u, "")
      : name,
    flag,
    protocol: "vless",
    transport: i % 4 === 2 ? "xhttp" : "tcp",
    security: "reality",
    core: "xray",
    // В превью пятый сервер группы повторяет первый — видно пометку «тот же сервер».
    sameAs: i === 4 ? `${group}-0` : null,
  };
}

/** Превью: `?servers=10000` добавляет большую подписку — проверить главную на длинных списках. */
export function withStressGroup(groups: Group[]): Group[] {
  const n = Number(new URLSearchParams(location.search).get("servers") ?? 0);
  if (!n) return groups;
  const flags = ["🇳🇱", "🇩🇪", "🇫🇮", "🇩🇰", "🇺🇸"];
  const servers = Array.from({ length: n }, (_, i) =>
    previewServer(`${flags[i % flags.length]} Сервер ${i + 1}`, i, "big"),
  );
  return [
    ...groups,
    { ...groups[0]!, id: "big", title: `Большая подписка (${n})`, servers },
  ];
}

function sampleGroups(): Group[] {
  return [
  {
    id: "a",
    title: "KVT",
    byUrl: true,
    updatedAt: Math.floor(Date.now() / 1000) - 3 * 3600,
    meta: {
      title: "KVT",
      usedBytes: 34 * 2 ** 30,
      totalBytes: 100 * 2 ** 30,
      expire: Math.floor(Date.now() / 1000) + 45 * 86400,
      supportUrl: null,
      announce: null,
    },
    servers: [
      "🇷🇺→🇪🇪 для wifi · via RU",
      "🇪🇪 для wifi · прямой",
      "🇳🇱 Нидерланды",
      "🇩🇪 Германия ⚡",
      "🇫🇮 Финляндия",
      "🇺🇸 США · YouTube",
      "Резерв без флага",
    ].map((n, i) => previewServer(n, i, "a")),
    info: [],
    errors: 0,
  },
  {
    id: "b",
    title: t("Добавлено вручную", "Added manually"),
    byUrl: false,
    updatedAt: Math.floor(Date.now() / 1000) - 60,
    meta: {
      title: null,
      usedBytes: null,
      totalBytes: null,
      expire: null,
      supportUrl: null,
      announce: null,
    },
    servers: [previewServer("🇩🇰 DK для wifi-familydk", 0, "b")],
    info: [],
    errors: 0,
  },
  {
    id: "c",
    title: "Резервный провайдер",
    byUrl: true,
    updatedAt: Math.floor(Date.now() / 1000) - 3 * 86400,
    meta: {
      title: "Резервный провайдер",
      usedBytes: 47 * 2 ** 30,
      totalBytes: 50 * 2 ** 30,
      expire: Math.floor(Date.now() / 1000) + 2 * 86400,
      supportUrl: null,
      announce: null,
    },
    servers: [
      previewServer("🇸🇪 Швеция", 0, "c"),
      previewServer("🇵🇱 Польша", 1, "c"),
    ],
    info: [],
    errors: 0,
  },
  ];
}

/** Превью: `?demo` — вид для скриншотов README: VPN подключён, аккуратные серверы,
 *  без плашки о новой версии. Снимает их `app/scripts/screenshots.mjs`. */
export const demo =
  !inTauri &&
  typeof location !== "undefined" &&
  new URLSearchParams(location.search).has("demo");
export let demoState: ServiceStatus = { state: "connected", core: "xray" };

/** Подключение и отключение в превью `?demo`: импорт только читает `demoState`. */
export function setDemoState(state: ServiceStatus): ServiceStatus {
  demoState = state;
  return state;
}

// Кадры мини-панели: `/mini.html?demo&frame=…` задаёт начальное состояние службы, а
// `&notice=update|expiring` — напоминание. Без `?demo` служба «не запущена».
const FRAMES: Record<string, ServiceStatus> = {
  connecting: { state: "connecting" },
  off: { state: "disconnected" },
  nodata: { state: "connected", core: "xray" },
  zapret: { state: "zapret", strategy: "general (ALT4)" },
  blocked: { state: "failed", reason: "ядро остановилось", blocked: true },
};
const query = new URLSearchParams(typeof location === "undefined" ? "" : location.search);
const frame = query.get("frame");
if (demo && frame && frame in FRAMES) demoState = FRAMES[frame] ?? demoState;
/** Кадр «данные не идут»: VPN подключён, а через туннель ничего не проходит. */
export const previewNoData = demo && frame === "nodata";
/** Напоминание в мини-панели, которое просили показать. */
export const previewNotice = demo ? query.get("notice") : null;

function demoGroups(): Group[] {
  const now = Math.floor(Date.now() / 1000);
  const names: [string, string][] = [
    ["🇳🇱 Нидерланды", "🇳🇱 Netherlands"],
    ["🇩🇪 Германия", "🇩🇪 Germany"],
    ["🇫🇮 Финляндия", "🇫🇮 Finland"],
    ["🇸🇪 Швеция", "🇸🇪 Sweden"],
    ["🇵🇱 Польша", "🇵🇱 Poland"],
    ["🇬🇧 Лондон", "🇬🇧 London"],
    ["🇺🇸 США", "🇺🇸 United States"],
    ["🇹🇷 Турция", "🇹🇷 Turkey"],
  ];
  return [
    {
      id: "demo",
      title: t("Мой VPN", "My VPN"),
      byUrl: true,
      updatedAt: now - 2 * 3600,
      meta: {
        title: t("Мой VPN", "My VPN"),
        usedBytes: 34 * 2 ** 30,
        totalBytes: 200 * 2 ** 30,
        expire: now + 45 * 86400,
        supportUrl: null,
        announce: null,
      },
      servers: names.map(([ru, en], i) => ({
        ...previewServer(t(ru, en), i, "demo"),
        sameAs: null,
      })),
      info: [],
      errors: 0,
    },
    {
      id: "demo-manual",
      title: t("Добавлено вручную", "Added manually"),
      byUrl: false,
      updatedAt: now - 3 * 86400,
      meta: {
        title: null,
        usedBytes: null,
        totalBytes: null,
        expire: null,
        supportUrl: null,
        announce: null,
      },
      servers: [previewServer(t("🇫🇮 Свой сервер", "🇫🇮 My own server"), 0, "demo-manual")],
      info: [],
      errors: 0,
    },
  ];
}

let previewGroupsCache: Group[] | null = null;

/** Группы превью. Меняются на месте (добавление, удаление), как список в приложении. */
export function previewData(): Group[] {
  previewGroupsCache ??= demo ? demoGroups() : sampleGroups();
  return previewGroupsCache;
}

export function previewAdd(body: string): Added {
  const lines = body.split(/\r?\n/).filter((l) => l.includes("://"));
  // Как в приложении: ручные ключи — в одной группе.
  let group = previewData().find((g) => !g.byUrl);
  if (!group) {
    group = {
      id: "manual",
      title: t("Добавлено вручную", "Added manually"),
      byUrl: false,
      updatedAt: 0,
      meta: {
        title: null,
        usedBytes: null,
        totalBytes: null,
        expire: null,
        supportUrl: null,
        announce: null,
      },
      servers: [],
      info: [],
      errors: 0,
    };
    previewData().push(group);
  }
  const start = group.servers.length;
  const id = group.id;
  group.servers.push(
    ...lines.map((l, i) =>
      previewServer(
        decodeURIComponent(l.split("#")[1] ?? `Сервер ${i + 1}`),
        start + i,
        id,
      ),
    ),
  );
  group.updatedAt = Math.floor(Date.now() / 1000);
  return {
    group: id,
    first: lines.length > 0 ? `${id}-${start}` : null,
    servers: lines.length,
    subscriptions: 0,
    failed: [],
  };
}

// Сервисы на вкладке «Проверка». В `?demo` VPN подключён и всё открывается; в обычном превью
// ничего не подключено, а кнопка «Проверить» показывает все три вердикта. Тексты
// считаются при вызове: язык ставится до монтирования, а не при загрузке модуля.
let servicesChecked = false;
/** Свой набор плиток в превью (id); `null` — по умолчанию. */
let servicesPicked: string[] | null = null;

/** Сервисы плиток в превью: id и название (названия — торговые марки, не переводятся). */
const SERVICES = [
  { id: "youtube", name: "YouTube" },
  { id: "discord", name: "Discord" },
  { id: "telegram", name: "Telegram" },
  { id: "instagram", name: "Instagram" },
  { id: "chatgpt", name: "ChatGPT" },
] as const;

/** Название сервиса по id — для превью «Почему не работает?» про сервис. */
export function previewServiceName(id: string): string | undefined {
  return SERVICES.find((s) => s.id === id)?.name;
}

/** Выбор своего набора в превью: сохраняется до перезагрузки страницы. */
export function previewServicesPick(ids: string[] | null): ServicesSnapshot {
  const known = SERVICES.filter((s) => ids?.includes(s.id)).map((s) => s.id as string);
  // Как в Rust (`clean_picked`): пусто или отмечено всё — набор по умолчанию.
  servicesPicked = known.length > 0 && known.length < SERVICES.length ? known : null;
  return previewServices();
}

/** Превью сервисов; `check` — нажали «Проверить». */
export function previewServices(opts: { check?: boolean } = {}): ServicesSnapshot {
  if (opts.check) servicesChecked = true;
  const at = Math.floor(Date.now() / 1000) - 90;
  const tile = (
    id: string,
    name: string,
    via: ServiceTile["via"],
    state: ServiceTile["state"],
  ): ServiceTile => ({
    id,
    name,
    via,
    state,
    detail:
      state === "works"
        ? t("Открывается", "Opens")
        : state === "slow"
          ? t("Открывается, но медленно", "Opens, but slowly")
          : state === "down"
            ? t("Соединение обрывается — похоже на блокировку", "The connection drops — looks like a block")
            : "",
  });
  const states = servicesChecked
    ? (["down", "slow", "works", "down", "works"] as const)
    : (["unknown", "unknown", "unknown", "unknown", "unknown"] as const);
  // В `?demo` VPN подключён и всё открывается; иначе ничего не подключено.
  const tiles = SERVICES.map((s, i) =>
    tile(s.id, s.name, demo ? "vpn" : "direct", demo ? "works" : (states[i] ?? "unknown")),
  ).filter((tl) => servicesPicked === null || servicesPicked.includes(tl.id));
  return {
    at: demo || servicesChecked ? at : null,
    checking: false,
    running: demo ? "vpn" : "off",
    tiles,
    picks: SERVICES.map((s) => ({
      id: s.id,
      name: s.name,
      chosen: servicesPicked === null || servicesPicked.includes(s.id),
      offered: true,
    })),
    custom: servicesPicked !== null,
  };
}

// Мини-панель (`/mini.html`): выбор и переключатели живут до перезагрузки страницы.
const panelPreview = { mode: (frame === "zapret" ? "zapret" : "hybrid") as Mode, ks: true, auto: true, tg: true, selected: null as string | null };

/** Данные панели в превью: серверы первой подписки, пинги растут по списку. */
export function previewPanel(): PanelView {
  const groups = previewData();
  const toPanel = (s: ServerSummary, i: number): PanelServer => {
    const unknown = i === 5;
    return {
      key: s.key,
      name: s.name,
      flag: s.flag,
      protocol: s.protocol,
      transport: s.transport,
      security: s.security,
      pingMs: unknown ? null : 38 + i * 9 + (i % 3) * 4,
      health: unknown ? "unknown" : "works",
    };
  };
  const servers = (groups[0]?.servers ?? []).map(toPanel);
  const server = servers.find((s) => s.key === panelPreview.selected) ?? servers[0] ?? null;
  const group = groups.find((g) => g.servers.some((s) => s.key === server?.key));
  const meta = group?.meta;
  const day = 86400;
  const subscription =
    group && meta && (meta.totalBytes !== null || meta.expire !== null)
      ? {
          title: meta.title ?? group.title,
          usedBytes: meta.usedBytes,
          totalBytes: meta.totalBytes,
          expire: previewNotice === "expiring" ? Math.floor(Date.now() / 1000) + 2 * day : meta.expire,
        }
      : null;
  return {
    mode: panelPreview.mode,
    killSwitch: panelPreview.ks,
    autoSwitch: panelPreview.auto,
    telegram: panelPreview.tg,
    server,
    servers,
    total: servers.length,
    zapret: { strategy: t("Основная", "Main"), pickedFor: "Home 5G" },
    subscription,
  };
}

/** Действие панели в превью: переключатели меняются, подключение работает в `?demo`. */
export async function previewPanelAct(id: string): Promise<void> {
  if (id === "ks") panelPreview.ks = !panelPreview.ks;
  else if (id === "auto") panelPreview.auto = !panelPreview.auto;
  else if (id === "tg") panelPreview.tg = !panelPreview.tg;
  else if (id.startsWith("mode:")) panelPreview.mode = id.slice(5) as Mode;
  else if (id.startsWith("srv:")) panelPreview.selected = id.slice(4);
  else if (id === "toggle" && demo) {
    const running = demoState.state === "connected" || demoState.state === "zapret";
    if (running) setDemoState({ state: "disconnected" });
    else {
      await new Promise((r) => setTimeout(r, 900));
      setDemoState(
        panelPreview.mode === "zapret"
          ? { state: "zapret", strategy: "general (ALT4)" }
          : { state: "connected", core: "xray" },
      );
    }
  }
}
