// Состояние zapret, общее для главной и вкладки Zapret. Живёт дольше страниц:
// можно уйти на другую вкладку, а начатый подбор или проверка допишут итог сюда.

import {
  onZapretCheck,
  zapretAutoselect,
  zapretCheck,
  zapretDiagnose,
  zapretLast,
  type CheckRecord,
  type ZapretDiagnosis,
  type ZapretPick,
  type ZapretProgress,
} from "./api";

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

export const pick = $state({
  running: false,
  progress: null as ZapretProgress | null,
  result: null as ZapretPick | null,
  error: null as string | null,
});

export const check = $state({
  running: false,
  last: null as CheckRecord | null,
  error: null as string | null,
});

export const diagnosis = $state({
  running: false,
  result: null as ZapretDiagnosis | null,
  error: null as string | null,
});

/** Подбор стратегии: кнопка на главной, во вкладке или «Почему не работает?». */
export async function startAutoselect() {
  if (pick.running) return;
  pick.running = true;
  pick.result = null;
  pick.error = null;
  pick.progress = null;
  try {
    pick.result = await zapretAutoselect((p) => (pick.progress = p));
  } catch (e) {
    pick.error = message(e);
  } finally {
    pick.running = false;
  }
}

export async function runCheck() {
  if (check.running || pick.running) return;
  check.running = true;
  check.error = null;
  try {
    check.last = await zapretCheck();
  } catch (e) {
    check.error = message(e);
  } finally {
    check.running = false;
  }
}

export async function runDiagnosis() {
  if (diagnosis.running || pick.running) return;
  diagnosis.running = true;
  diagnosis.error = null;
  try {
    diagnosis.result = await zapretDiagnose();
  } catch (e) {
    diagnosis.error = message(e);
  } finally {
    diagnosis.running = false;
  }
}

// Итоги автопроверки и подбора приходят событием; при запуске — последний из Rust.
let listening = false;
export function listenChecks() {
  if (listening) return;
  listening = true;
  void zapretLast().then((r) => {
    if (r && !check.last) check.last = r;
  });
  onZapretCheck((r) => (check.last = r));
}
