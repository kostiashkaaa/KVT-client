// Общий вид статуса: кадры, которые рисуют главное окно и мини-панель.

import { describe, expect, it } from "vitest";
import { statusView, type StatusInput } from "./statusView";

const base: StatusInput = { status: { state: "disconnected" }, tunnelOk: null, busy: false };
const view = (patch: Partial<StatusInput>) => statusView({ ...base, ...patch });

describe("statusView", () => {
  it("отключено", () => {
    expect(view({})).toMatchObject({ tone: "off", title: "Отключено", power: "off", connected: false });
  });

  it("подключено через VPN", () => {
    const v = view({ status: { state: "connected", core: "xray" }, tunnelOk: true });
    expect(v).toMatchObject({ tone: "on", title: "Подключено", power: "on", connected: true });
  });

  it("проверку туннеля ещё не делали — это не «нет данных»", () => {
    expect(view({ status: { state: "connected", core: "xray" }, tunnelOk: null }).noData).toBe(false);
  });

  it("сервер принял подключение, но данные не идут", () => {
    const v = view({ status: { state: "connected", core: "sing-box" }, tunnelOk: false });
    expect(v).toMatchObject({ tone: "warn", title: "Сайты не открываются", power: "on warn", noData: true });
  });

  it("только zapret", () => {
    const v = view({ status: { state: "zapret", strategy: "general" } });
    expect(v).toMatchObject({ tone: "on", title: "Zapret работает", connected: true });
    // Без VPN туннеля нет, и «данные не идут» к нему не относится.
    expect(view({ status: { state: "zapret", strategy: "general" }, tunnelOk: false }).noData).toBe(false);
  });

  it("идёт подключение: и по статусу службы, и по действию окна", () => {
    expect(view({ status: { state: "connecting" } })).toMatchObject({ tone: "pending", title: "Подключение…" });
    expect(view({ busy: true })).toMatchObject({ tone: "pending", power: "pending", title: "Подключение…" });
  });

  it("ядро остановилось, kill switch держит интернет закрытым", () => {
    const v = view({ status: { state: "failed", reason: "ядро остановилось", blocked: true } });
    expect(v).toMatchObject({ tone: "error", title: "Интернет закрыт", blocked: true, power: "on warn" });
  });

  it("ошибка без kill switch", () => {
    const v = view({ status: { state: "failed", reason: "не запустилось" } });
    expect(v).toMatchObject({ tone: "error", title: "Ошибка", blocked: false, power: "off" });
  });

  it("службы нет", () => {
    expect(view({ status: null, serviceDown: true })).toMatchObject({
      tone: "error",
      title: "Служба KVT не запущена",
    });
  });

  it("службу запускают: не красный, а «подключение»", () => {
    expect(view({ status: null, serviceDown: true, starting: true })).toMatchObject({
      tone: "pending",
      title: "Запускаем службу KVT…",
      serviceStarting: true,
    });
  });

  it("служба другой версии: запуск не поможет", () => {
    expect(view({ status: null, serviceDown: true, starting: true, mismatch: true })).toMatchObject({
      tone: "error",
      title: "Окно и служба KVT разных версий",
      serviceStarting: false,
    });
  });
});
