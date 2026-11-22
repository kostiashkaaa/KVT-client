// Чистые части чтения QR-кода: размеры, яркость, склейка строк, запрос к Rust.
// Работа с канвой и мост — в приложении и в превью, здесь их нет.

import { describe, expect, it } from "vitest";
import { packQrRequest } from "../api/qr";
import { fitSize, MAX_SIDE, toGray } from "./image";
import { addLines, imageFromPaste } from "./scan";

describe("fitSize", () => {
  it("не трогает картинку, которая и так не больше предела", () => {
    expect(fitSize(800, 600)).toEqual({ width: 800, height: 600 });
    expect(fitSize(MAX_SIDE, 10)).toEqual({ width: MAX_SIDE, height: 10 });
  });

  it("уменьшает по длинной стороне и сохраняет пропорции", () => {
    expect(fitSize(4096, 2048)).toEqual({ width: 2048, height: 1024 });
    expect(fitSize(1000, 8000, 2000)).toEqual({ width: 250, height: 2000 });
  });

  it("узкая полоска не схлопывается в ноль", () => {
    expect(fitSize(100000, 1)).toEqual({ width: 2048, height: 1 });
  });
});

describe("toGray", () => {
  it("переводит цвет в яркость", () => {
    // чёрный, белый, чистый красный
    const rgba = new Uint8ClampedArray([0, 0, 0, 255, 255, 255, 255, 255, 255, 0, 0, 255]);
    expect(Array.from(toGray(rgba))).toEqual([0, 255, 76]);
  });

  it("прозрачное считает белым: у PNG с прозрачным фоном код тёмный на белом", () => {
    const rgba = new Uint8ClampedArray([0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 128]);
    expect(Array.from(toGray(rgba))).toEqual([255, 0, 127]);
  });

  it("пустая картинка — пустой результат", () => {
    expect(toGray(new Uint8ClampedArray(0)).length).toBe(0);
  });
});

describe("addLines", () => {
  it("кладёт тексты с новой строки и не теряет написанное", () => {
    expect(addLines("", ["vless://a"])).toBe("vless://a");
    expect(addLines("https://x.example/sub\n", ["vless://a", "vless://b"])).toBe(
      "https://x.example/sub\nvless://a\nvless://b",
    );
    expect(addLines("   ", ["vless://a"])).toBe("vless://a");
  });
});

describe("packQrRequest", () => {
  it("пишет размеры по 4 байта (little-endian), затем пиксели", () => {
    const body = packQrRequest({ width: 3, height: 258, gray: new Uint8Array([9, 8, 7]) });
    expect(Array.from(body)).toEqual([3, 0, 0, 0, 2, 1, 0, 0, 9, 8, 7]);
  });
});

describe("imageFromPaste", () => {
  const item = (kind: string, type: string, file: File | null) =>
    ({ kind, type, getAsFile: () => file }) as unknown as DataTransferItem;
  const data = (items: DataTransferItem[], text = "") =>
    ({ items, getData: (type: string) => (type === "text/plain" ? text : "") }) as unknown as DataTransfer;

  it("берёт первую картинку, когда в буфере только она (снимок экрана)", () => {
    const png = { name: "shot.png" } as File;
    expect(imageFromPaste(data([item("file", "image/png", png)]))).toBe(png);
  });

  it("с текстом в буфере картинку не берёт: Word, Outlook и Excel кладут и снимок выделения", () => {
    const png = { name: "selection.png" } as File;
    const items = [item("string", "text/plain", null), item("file", "image/png", png)];
    expect(imageFromPaste(data(items, "vless://a@example.com:443#A"))).toBeNull();
    // Пустой или из одних пробелов текст — это как будто его нет.
    expect(imageFromPaste(data(items, "  \n"))).toBe(png);
  });

  it("чужие файлы — не картинка", () => {
    expect(imageFromPaste(data([item("file", "application/pdf", {} as File)]))).toBeNull();
    expect(imageFromPaste(null)).toBeNull();
  });
});
