import { t } from "../i18n";
import { inTauri, invoke } from "./bridge";

// ── Перенос из других клиентов ──

export interface MigrationPreview {
  client: "v2rayn" | "throne" | "nekoray" | "hiddify" | "happ";
  title: string;
  /** Папка с данными клиента — она же идентификатор при переносе. */
  location: string;
  /** Только название и адрес сервера подписки: сама ссылка остаётся в Rust. */
  subscriptions: { name: string; host: string }[];
  servers: { name: string; protocol: string }[];
  skipped: { reason: string; count: number }[];
  note: string | null;
}

export interface MigrationReport {
  loaded: number;
  pending: number;
  existing: number;
  servers: number;
}

const previewMigration: MigrationPreview[] = [
  {
    client: "v2rayn",
    title: "v2rayN",
    location: String.raw`C:\Users\user\Downloads\v2rayN-windows-64`,
    subscriptions: [
      { name: "Мой провайдер", host: "sub.example.com" },
      { name: "Резерв", host: "panel.example.net" },
    ],
    servers: [
      { name: "Домашний сервер", protocol: "VLESS" },
      { name: "SS для игр", protocol: "Shadowsocks" },
    ],
    skipped: [{ reason: t("VMess не поддерживается", "VMess is not supported"), count: 3 }],
    note: null,
  },
  {
    client: "happ",
    title: "Happ",
    location: String.raw`C:\Users\user\AppData\Local\Happ`,
    subscriptions: [],
    servers: [],
    skipped: [],
    note: t("Happ хранит подписки в зашифрованном виде — KVT их не читает. Скопируйте в Happ ссылку на подписку и добавьте её в KVT кнопкой «+».", "Happ stores subscriptions encrypted — KVT can't read them. Copy the subscription link in Happ and add it to KVT with the “+” button."),
  },
];

export async function migrateScan(): Promise<MigrationPreview[]> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 1200));
    return previewMigration;
  }
  return invoke<MigrationPreview[]>("migrate_scan");
}

/** `null` — пользователь закрыл окно выбора папки. */
export async function migratePickFolder(): Promise<MigrationPreview[] | null> {
  if (!inTauri)
    throw new Error(t("Выбор папки работает в приложении (npm run tauri dev).", "Choosing a folder works in the app (npm run tauri dev)."));
  return invoke<MigrationPreview[] | null>("migrate_pick_folder");
}

export async function migrateImport(
  locations: string[],
  servers: boolean,
): Promise<MigrationReport> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 1000));
    return { loaded: 1, pending: 1, existing: 0, servers: servers ? 2 : 0 };
  }
  return invoke<MigrationReport>("migrate_import", {
    request: { locations, servers },
  });
}
