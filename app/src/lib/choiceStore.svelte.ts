// Выбор пользователя: сервер, режим, kill switch, маршрутизация, DNS, zapret и переключатели
// настроек. Rust хранит выбор целиком (`setChoice`) — окно отправляет все поля сразу после
// любого изменения. Про подключение (статус службы, с чем она работает сейчас) стор не
// знает — это `connectionStore`.

import {
  defaultDns,
  defaultRouting,
  defaultZapret,
  setChoice,
  type Choice,
  type DnsChoice,
  type Mode,
  type NetworkProfile,
  type RoutingSettings,
  type ZapretChoice,
} from "./api";

export const choice = $state({
  /** Ключ выбранного сервера. */
  selected: null as string | null,
  mode: "vpn" as Mode,
  killSwitch: false,
  routing: defaultRouting(),
  dns: defaultDns(),
  /** Переключаться на другой сервер, если через текущий перестали идти данные. */
  autoSwitch: true,
  /** Профили сетей: включать ли VPN в знакомых сетях. */
  networks: [] as NetworkProfile[],
  zapret: defaultZapret(),
  notifications: true,
  connectOnStart: false,
  checkUpdates: true,
  miniPanel: true,
  /** До восстановления выбора считаем пройденным — подсказки не мелькают. */
  onboarded: true,
  /** Выбор восстановлен из Rust: до этого его не отправляем. */
  restored: false,
});

/** Восстановить выбор из Rust. `fallback` — первый сервер первого непустого списка:
 *  если выбранного сервера в `Choice` нет, берём его. */
export function applyChoice(c: Choice, fallback: string | null) {
  choice.selected = c.server ?? fallback;
  choice.mode = c.mode ?? "vpn";
  choice.killSwitch = c.killSwitch;
  choice.routing = { ...defaultRouting(), ...c.routing };
  choice.dns = { ...defaultDns(), ...c.dns };
  choice.autoSwitch = c.autoSwitch ?? true;
  choice.networks = c.networks ?? [];
  choice.zapret = { ...defaultZapret(), ...c.zapret };
  choice.notifications = c.notifications ?? true;
  choice.connectOnStart = c.connectOnStart ?? false;
  choice.checkUpdates = c.checkUpdates ?? true;
  choice.miniPanel = c.miniPanel ?? true;
  choice.onboarded = c.onboarded ?? false;
}

/** Выбор целиком: Rust хранит его так, отправлять надо все поля, иначе остальные сбросятся. */
export function currentChoice(): Choice {
  return {
    server: choice.selected,
    mode: choice.mode,
    killSwitch: choice.killSwitch,
    routing: $state.snapshot(choice.routing),
    dns: $state.snapshot(choice.dns),
    autoSwitch: choice.autoSwitch,
    networks: $state.snapshot(choice.networks),
    zapret: $state.snapshot(choice.zapret),
    notifications: choice.notifications,
    connectOnStart: choice.connectOnStart,
    checkUpdates: choice.checkUpdates,
    miniPanel: choice.miniPanel,
    onboarded: choice.onboarded,
  };
}

/** Выбор хранится в Rust: после восстановления отправляем целиком при каждом изменении.
 *  Вызывается из окна — эффекту нужен его контекст. */
export function watchChoicePersisted() {
  $effect(() => {
    const snapshot = currentChoice();
    if (choice.restored) void setChoice(snapshot);
  });
}
