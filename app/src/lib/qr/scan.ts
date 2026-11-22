// QR-код с картинки в панель «+»: файл или буфер обмена → яркость → Rust → тексты.
// Тексты — секрет, поэтому ничего не пишем в консоль и не храним: они возвращаются
// вызывающему и идут только в поле добавления.

import { qrDecode } from "../api";
import { MAX_FILE_BYTES, readGray } from "./image";

/** Что не вышло: код для окна, текст для пользователя подбирает оно. */
export type ScanError = "not_found" | "unreadable" | "bad_image" | "too_big" | "open_failed" | "failed";

export type ScanResult = { texts: string[] } | { error: ScanError };

/** Прочитать QR-коды с картинки (файл или данные из буфера). */
export async function scanImage(blob: Blob): Promise<ScanResult> {
  if (blob.size > MAX_FILE_BYTES) return { error: "too_big" };
  let image;
  try {
    image = await readGray(blob);
  } catch {
    return { error: "open_failed" };
  }
  try {
    const outcome = await qrDecode(image);
    return outcome.kind === "found" ? { texts: outcome.texts } : { error: outcome.kind };
  } catch {
    return { error: "failed" };
  }
}

/** Тексты — в поле, каждый с новой строки; то, что уже в поле, остаётся. */
export function addLines(current: string, texts: string[]): string {
  const head = current.trimEnd();
  return [head, ...texts].filter((part) => part !== "").join("\n");
}

/**
 * Картинка в событии вставки (Ctrl+V): первый файл-картинка или `null`. Если вместе
 * с картинкой в буфере есть текст — это письмо провайдера или ячейка таблицы (Word,
 * Outlook, Excel кладут и снимок выделения): вставляется текст, картинку не берём.
 */
export function imageFromPaste(data: DataTransfer | null): File | null {
  if (!data || data.getData("text/plain").trim() !== "") return null;
  for (const item of Array.from(data.items ?? [])) {
    if (item.kind === "file" && item.type.startsWith("image/")) return item.getAsFile();
  }
  return null;
}

/**
 * Что лежит в буфере обмена: текст или картинка. Читается только по нажатию кнопки.
 * Текст важнее картинки: см. `imageFromPaste`.
 */
export async function readClipboard(): Promise<{ image: Blob | null; text: string }> {
  try {
    let image: Blob | null = null;
    for (const item of await navigator.clipboard.read()) {
      if (item.types.includes("text/plain")) {
        const text = await (await item.getType("text/plain")).text();
        if (text.trim() !== "") return { image: null, text };
      }
      const type = item.types.find((t) => t.startsWith("image/"));
      if (type && !image) image = await item.getType(type);
    }
    if (image) return { image, text: "" };
  } catch {
    /* `read()` нет или он запрещён — пробуем простой текст ниже */
  }
  return { image: null, text: await navigator.clipboard.readText() };
}
