import { t } from "../i18n";
import { inTauri } from "./bridge";
import type { Added, Group, ServerSummary, ServiceStatus } from "./connection";

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
