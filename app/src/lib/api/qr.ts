// Чтение QR-кода с картинки для панели «+». Картинку в яркости готовит окно
// (`lib/qr/image.ts`), поиск делает Rust (`kvt_core::qr`) локально, без сети.
// Текст кода — секрет (ключ или ссылка с токеном): он идёт только в поле добавления.

import { inTauri, invoke } from "./bridge";

/** Итог поиска: код итога сравнивается, текст для пользователя — дело окна. */
export type QrOutcome =
  | { kind: "found"; texts: string[] }
  | { kind: "not_found" }
  | { kind: "unreadable" }
  | { kind: "bad_image" };

/** Картинка в яркости: по байту на пиксель, 0 — чёрный, 255 — белый. */
export interface GrayImage {
  width: number;
  height: number;
  gray: Uint8Array;
}

/** Тело запроса: ширина и высота (по 4 байта, little-endian), затем пиксели. */
export function packQrRequest(image: GrayImage): Uint8Array {
  const body = new Uint8Array(8 + image.gray.length);
  const view = new DataView(body.buffer);
  view.setUint32(0, image.width, true);
  view.setUint32(4, image.height, true);
  body.set(image.gray, 8);
  return body;
}

/** Найти QR-коды на картинке и прочитать их. */
export async function qrDecode(image: GrayImage): Promise<QrOutcome> {
  if (!inTauri) {
    // Превью без Rust: настоящего поиска нет, отвечаем заведомо ненастоящей ссылкой.
    await new Promise((r) => setTimeout(r, 300));
    return { kind: "found", texts: ["https://example.com/sub/demo-token"] };
  }
  return invoke<QrOutcome>("qr_decode", packQrRequest(image));
}
