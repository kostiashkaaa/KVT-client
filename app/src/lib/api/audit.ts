import { t } from "../i18n";
import { inTauri, invoke } from "./bridge";

// ── Аудит ПК ──

export type ServiceFix =
  | { action: "reset_win_http_proxy" }
  | { action: "disable_teredo" }
  | { action: "disable_zapret_service"; name: string }
  | { action: "disable_autostart"; id: string };

export type AuditFix =
  | { kind: "disable_system_proxy" }
  | { kind: "close_process"; pid: number; name: string }
  | { kind: "stop_zapret" }
  | ({ kind: "service" } & ServiceFix)
  | { kind: "disable_user_autostart"; id: string };

export interface AuditFinding {
  group: "leaks" | "conflicts" | "zapret";
  level: "ok" | "info" | "warning";
  title: string;
  detail: string;
  fix: AuditFix | null;
}

export interface AuditReport {
  findings: AuditFinding[];
  ms: number;
}

let previewProxyOn = true;

export async function pcAudit(): Promise<AuditReport> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 1500));
    const findings: AuditFinding[] = [
      previewProxyOn
        ? {
            group: "leaks",
            level: "warning",
            title: t("Включён системный прокси", "System proxy is on"),
            detail:
              t("Браузеры и другие программы отправляют трафик на 127.0.0.1:10808 — обычно это остаток другого VPN-клиента. Если та программа закрыта, сайты не открываются; если запущена — трафик идёт через неё, а не через KVT.", "Browsers and other apps send traffic to 127.0.0.1:10808 — usually a leftover from another VPN client. If that app is closed, sites won't open; if it's running, traffic goes through it instead of KVT."),
            fix: { kind: "disable_system_proxy" },
          }
        : {
            group: "leaks",
            level: "ok",
            title: t("Системный прокси", "System proxy"),
            detail:
              t("Не задан: программы выходят в сеть обычным путём, через туннель KVT.", "Not set: apps reach the internet the normal way, through the KVT tunnel."),
            fix: null,
          },
      {
        group: "leaks",
        level: "ok",
        title: t("Прокси WinHTTP", "WinHTTP proxy"),
        detail: t("Не задан.", "Not set."),
        fix: null,
      },
      {
        group: "leaks",
        level: "ok",
        title: "Teredo",
        detail: t("Выключен или не используется.", "Off or not in use."),
        fix: null,
      },
      {
        group: "leaks",
        level: "info",
        title: t("Браузер использует свой DNS", "A browser uses its own DNS"),
        detail:
          t("Microsoft Edge (chrome.cloudflare-dns.com): защищённый DNS включён в настройках браузера. Запросы зашифрованы, но идут мимо DNS KVT — если сайты из списков маршрутизации открываются не так, выключите «Безопасный DNS» в настройках браузера.", "Microsoft Edge (chrome.cloudflare-dns.com): secure DNS is on in the browser settings. Queries are encrypted but bypass KVT's DNS — if sites from the routing lists open the wrong way, turn off “Secure DNS” in the browser settings."),
        fix: null,
      },
      {
        group: "conflicts",
        level: "warning",
        title: t("Запущен v2rayN", "v2rayN is running"),
        detail:
          t("Два VPN одновременно спорят за маршруты и DNS: часть трафика уходит не туда, подключение обрывается. Закройте другой клиент, пока работает KVT.", "Two VPNs at once fight over routes and DNS: some traffic goes the wrong way and the connection drops. Close the other client while KVT is running."),
        fix: { kind: "close_process", pid: 4242, name: "v2rayN" },
      },
      {
        group: "conflicts",
        level: "ok",
        title: t("Туннели других VPN", "Other VPN tunnels"),
        detail: t("Активных нет.", "None active."),
        fix: null,
      },
      {
        group: "conflicts",
        level: "info",
        title: t("Антивирус проверяет HTTPS", "Antivirus scans HTTPS"),
        detail:
          t("Kaspersky Plus может перехватывать защищённые соединения. Если подписки не загружаются или проверка серверов ошибается, добавьте папку KVT в исключения или выключите «Проверку защищённых соединений».", "Kaspersky Plus may intercept secure connections. If subscriptions don't load or server checks go wrong, add the KVT folder to exclusions or turn off encrypted connection scanning."),
        fix: null,
      },
      {
        group: "zapret",
        level: "warning",
        title: t("Служба zapret запускается вместе с Windows", "Service zapret starts with Windows"),
        detail:
          t("zapret стартует при каждом включении компьютера и мешает zapret в KVT. Исправление остановит её и переведёт в ручной запуск — ничего не удаляется.", "zapret starts every time the computer turns on and interferes with zapret in KVT. The fix stops it and sets it to manual start — nothing is deleted."),
        fix: {
          kind: "service",
          action: "disable_zapret_service",
          name: "zapret",
        },
      },
    ];
    return { findings, ms: 1500 };
  }
  return invoke<AuditReport>("pc_audit");
}

export async function pcAuditFix(fix: AuditFix): Promise<void> {
  if (!inTauri) {
    await new Promise((r) => setTimeout(r, 600));
    if (fix.kind === "disable_system_proxy") {
      previewProxyOn = false;
      return;
    }
    throw new Error(t("Служба KVT не запущена — это исправление выполняет она", "The KVT service isn't running — it performs this fix"));
  }
  await invoke("pc_audit_fix", { fix });
}
