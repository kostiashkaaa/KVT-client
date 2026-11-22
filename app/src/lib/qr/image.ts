// Картинка → яркость для поиска QR-кода (`api/qr.ts`). Файл и буфер обмена окно
// разбирает само (WebView умеет PNG, JPEG, WebP и прочее), а Rust получает только
// байты яркости: декодеров изображений в Rust-части нет, чужой формат ей не страшен.

import type { GrayImage } from "../api";

/** Длинная сторона после уменьшения: больше не нужно, а байты идут через мост окна. */
export const MAX_SIDE = 2048;
/** Файл больше этого не открываем: это уже не скриншот и не снимок экрана телефона. */
export const MAX_FILE_BYTES = 20 * 1024 * 1024;

/** Размер после уменьшения: длинная сторона не больше `max`, пропорции сохраняются. */
export function fitSize(width: number, height: number, max = MAX_SIDE): { width: number; height: number } {
  const scale = Math.min(1, max / Math.max(width, height));
  return {
    width: Math.max(1, Math.round(width * scale)),
    height: Math.max(1, Math.round(height * scale)),
  };
}

/** RGBA → яркость (Rec. 601). Прозрачное — белое: у PNG с прозрачным фоном код тёмный на белом. */
export function toGray(rgba: Uint8ClampedArray): Uint8Array {
  const gray = new Uint8Array(rgba.length >> 2);
  for (let px = 0; px < gray.length; px++) {
    const i = px * 4;
    const alpha = (rgba[i + 3] ?? 255) / 255;
    const luma = 0.299 * (rgba[i] ?? 0) + 0.587 * (rgba[i + 1] ?? 0) + 0.114 * (rgba[i + 2] ?? 0);
    gray[px] = Math.round(luma * alpha + 255 * (1 - alpha));
  }
  return gray;
}

/** Открыть картинку и получить её яркость, уменьшив до `MAX_SIDE`. Не картинка — исключение. */
export async function readGray(blob: Blob): Promise<GrayImage> {
  // `createImageBitmap` не требует разрешений CSP на `blob:`, в отличие от `<img>`.
  const bitmap = await createImageBitmap(blob);
  try {
    const { width, height } = fitSize(bitmap.width, bitmap.height);
    const canvas = document.createElement("canvas");
    canvas.width = width;
    canvas.height = height;
    const context = canvas.getContext("2d", { willReadFrequently: true });
    if (!context) throw new Error("canvas");
    context.imageSmoothingQuality = "high";
    context.drawImage(bitmap, 0, 0, width, height);
    return { width, height, gray: toGray(context.getImageData(0, 0, width, height).data) };
  } finally {
    bitmap.close();
  }
}
