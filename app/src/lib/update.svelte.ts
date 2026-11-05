// Новая версия KVT — одно состояние для всего окна: плашка на главной, точка у
// «Настроек» и раздел «О программе» показывают одно и то же.
//
// «Позже» на плашке прячет её до следующей версии, а точка у «Настроек» остаётся,
// пока новая версия не установлена: напоминание видно, но не мешает.

import { onUpdateAvailable, updateCheck, updateStatus, type UpdateStatus } from "./api";

const SKIPPED = "kvt.update.skipped";

function readSkipped(): string | null {
  try {
    return localStorage.getItem(SKIPPED);
  } catch {
    return null;
  }
}

let status = $state<UpdateStatus | null>(null);
let skipped = $state<string | null>(readSkipped());

export const update = {
  get status(): UpdateStatus | null {
    return status;
  },
  /** Номер новой версии, если она есть. */
  get version(): string | null {
    return status?.available && status.latest ? status.latest : null;
  },
  /** Плашка на главной: новая версия есть, и «Позже» для неё не нажимали. */
  get banner(): boolean {
    return this.version !== null && this.version !== skipped;
  },
};

/** Не напоминать плашкой об этой версии. */
export function skipUpdate() {
  skipped = update.version;
  try {
    if (skipped) localStorage.setItem(SKIPPED, skipped);
  } catch {
    // Без хранилища плашка вернётся при следующем запуске — не страшно.
  }
}

/** «Проверить сейчас» в «О программе». */
export async function checkUpdateNow(): Promise<void> {
  status = await updateCheck();
}

/** Читает известное о версии и следит за фоновой проверкой; возвращает отписку. */
export function watchUpdates(): () => void {
  const read = () => void updateStatus().then((u) => (status = u));
  read();
  return onUpdateAvailable(read);
}
