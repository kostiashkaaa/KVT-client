// Ключи настроек, с которыми окно сравнивает «что выбрано» и «с чем подключено»: изменился
// ключ — нужно переподключиться (или показать «Переподключить»). Чистые функции: принимают
// снимки настроек (`$state.snapshot`), а читать состояние и подписываться на него остаётся
// компоненту.

import type { DnsChoice, RoutingSettings, ZapretChoice } from "./api";

/** Настройки zapret, с которыми запущена служба (стратегия, фильтр). Автопроверка
 *  на запуск не влияет: её переключатели не должны перезапускать zapret и VPN. */
export function zapretKeyOf(zapret: ZapretChoice): string {
  const { autoCheck: _check, autoPick: _pick, ...plan } = zapret;
  return JSON.stringify(plan);
}

/** Настройки маршрутизации без учёта порядка выбора списков. */
export function routingKeyOf(routing: RoutingSettings): string {
  return JSON.stringify({
    ...routing,
    overrides: Object.entries(routing.overrides).sort(([a], [b]) => a.localeCompare(b)),
  });
}

/** Kill switch и DNS: служба применяет их только при подключении. */
export function settingsKeyOf(killSwitch: boolean, dns: DnsChoice): string {
  return JSON.stringify({ killSwitch, dns });
}

/** В режиме «VPN» из настроек zapret на подключение влияет только прокси Telegram. */
export function telegramOf(zapretKey: string): string {
  const z = JSON.parse(zapretKey) as ZapretChoice;
  return `${z.telegram}:${z.telegramRoute}`;
}
