// Полная проверка серверов.

import { inTauri, invoke, listen } from "./bridge";
import { demo, previewData } from "./preview";

export type ProbeVerdict =
  | "works"
  | "slow"
  | "dns_failed"
  | "unreachable"
  | "tls_frozen"
  | "data_frozen"
  | "rejected"
  | "config_error";

export type Outcome =
  | { kind: "checked"; verdict: ProbeVerdict; latency_ms: number | null }
  | { kind: "deferred"; retry_after_secs: number };

/**
 * Полная проверка через тестовое ядро: одна подписка (`group`) или все (`null`).
 * Результаты приходят по одному, по ключам серверов.
 */
export async function fullCheck(
  group: string | null,
  onResult: (key: string, outcome: Outcome) => void,
): Promise<void> {
  if (!inTauri) {
    const keys = previewData()
      .filter((g) => group === null || g.id === group)
      .flatMap((g) => g.servers.map((s) => s.key));
    const demo: Outcome[] = [
      { kind: "checked", verdict: "works", latency_ms: 184 },
      { kind: "checked", verdict: "data_frozen", latency_ms: 240 },
      { kind: "checked", verdict: "slow", latency_ms: 2100 },
      { kind: "deferred", retry_after_secs: 170 },
    ];
    for (const [i, key] of keys.entries()) {
      await new Promise((r) => setTimeout(r, 250));
      onResult(key, demo[i % demo.length]!);
    }
    return;
  }
  const off = await listen<{ key: string; outcome: Outcome }>(
    "probe-result",
    (e) => onResult(e.payload.key, e.payload.outcome),
  );
  try {
    await invoke("full_check", { group });
  } finally {
    off();
  }
}
