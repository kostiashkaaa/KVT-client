// Сообщения окна по событиям Rust: служба и автопереключение (watchdog), автопроверка zapret,
// сообщения, накопленные до открытия окна. Эффекты ставятся при вызове из компонента, поэтому
// порядок подписок в нём остаётся тем, где вызвана функция.

import { t } from "./i18n";
import { onNotices, onWatchdog, onZapretAuto, takeNotices, type WatchdogEvent } from "./api";
import { push as pushNotice } from "./notices.svelte";

export function watchdogText(e: WatchdogEvent): string {
  switch (e.kind) {
    case "captive_portal":
      return t("Сеть просит войти (как Wi-Fi в гостинице или кафе), а VPN не даёт открыть страницу входа. Отключите VPN, войдите в сеть и подключитесь снова.", "The network asks you to sign in (like hotel or café Wi-Fi), and the VPN keeps the sign-in page from opening. Disconnect the VPN, sign in to the network and connect again.");
    case "server_removed":
      return t(`Сервер «${e.server}» больше не в подписках — VPN отключён. Выберите другой сервер и подключитесь.`, `Server “${e.server}” is no longer in your subscriptions — the VPN is disconnected. Pick another server and connect.`);
    case "server_replaced":
      return t(`Сервера «${e.from}» больше нет в подписке — KVT переключился на «${e.to}».`, `Server “${e.from}” is no longer in the subscription — KVT switched to “${e.to}”.`);
    case "switched":
      return t(`Через «${e.from}» перестали идти данные — KVT переключился на «${e.to}».`, `Data stopped going through “${e.from}” — KVT switched to “${e.to}”.`);
    case "no_network":
      return t("Пропала сеть. VPN снова заработает, когда она появится.", "The network is gone. The VPN will work again once it's back.");
    case "no_alternative":
      return t(`Через «${e.server}» перестали идти данные, а рабочей замены в подписках нет.`, `Data stopped going through “${e.server}”, and there's no working replacement in your subscriptions.`);
    case "gave_up":
      return t("Серверы слишком часто перестают работать — автопереключение приостановлено на полчаса.", "Servers fail too often — auto-switch is paused for half an hour.");
  }
}

/** Сообщения, которые появились до открытия окна (например, о повреждённых
 *  настройках) или пришли из трея, когда уведомления Windows выключены. */
export function watchStartupNotices() {
  $effect(() => {
    const take = () =>
      void takeNotices().then((list) => {
        for (const text of list) pushNotice({ text, key: `startup:${text}` });
      });
    take();
    return onNotices(take);
  });
}

/** События службы: замена сервера, пропавшая сеть, вход в сеть; автопроверка zapret. */
export function watchEventNotices(deps: {
  /** Работает VPN или только zapret. */
  active: () => boolean;
  ondisconnect: () => Promise<void>;
  /** Открыть вкладку Zapret. */
  openZapret: () => void;
}) {
  $effect(() =>
    onWatchdog((e) => {
      const text = watchdogText(e);
      // Замена сервера и пропавшая сеть — сведения, исчезают сами; остальное ждёт «Понятно».
      const info = e.kind === "switched" || e.kind === "server_replaced" || e.kind === "no_network";
      pushNotice({
        key: "watchdog",
        text,
        tone: info ? "info" : "warn",
        actions:
          e.kind === "captive_portal" && deps.active()
            ? [{ label: t("Отключить VPN", "Disconnect VPN"), primary: true, run: () => deps.ondisconnect() }]
            : [],
      });
    }),
  );

  // Автопроверка zapret: сама подобрала стратегию или просит внимания.
  $effect(() =>
    onZapretAuto((e) => {
      if (e.kind === "picked") {
        pushNotice({
          key: "zapret-auto",
          tone: "info",
          text: t(`zapret перестал справляться — KVT подобрал стратегию ${e.title} (${e.passed} из ${e.max}).`, `zapret stopped working — KVT picked strategy ${e.title} (${e.passed} of ${e.max}).`),
        });
      } else {
        pushNotice({
          key: "zapret-auto",
          text: t(`zapret справляется хуже: ${e.passed} из ${e.max} проверок.`, `zapret works worse: ${e.passed} of ${e.max} checks.`),
          actions: [{ label: t("Открыть Zapret", "Open Zapret"), run: deps.openZapret }],
        });
      }
    }),
  );
}
