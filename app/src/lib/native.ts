// Окно KVT ведёт себя как программа, а не как веб-страница. WebView2 по умолчанию
// оставляет браузерное: меню правой кнопки («Назад», «Обновить», «Печать»,
// «Проверить»), перезагрузку по F5, печать, поиск по странице, перетаскивание
// ссылок и картинок, «назад» боковой кнопкой мыши. Масштаб Ctrl+колесом Tauri уже
// выключает сам (`zoomHotkeysEnabled`). Инструменты разработчика в релизе выключены.

/** Поле ввода: там меню «Вырезать / Копировать / Вставить» полезно, его оставляем. */
function editable(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  return (
    target.isContentEditable ||
    target.closest("input, textarea, select") !== null
  );
}

/** Клавиши браузера, которые в программе не нужны (Ctrl или ⌘ + буква / F-клавиша). */
const blockedWithCtrl = new Set([
  "r",
  "p",
  "f",
  "g",
  "s",
  "u",
  "o",
  "j",
  "h",
  "n",
  "t",
  "w",
]);
const blockedAlone = new Set([
  "F3",
  "F5",
  "F7",
  "BrowserBack",
  "BrowserForward",
  "BrowserRefresh",
]);

function blockedKey(e: KeyboardEvent): boolean {
  if (blockedAlone.has(e.key)) return true;
  // Alt+← / Alt+→ — «назад» и «вперёд» в браузере.
  if (e.altKey && (e.key === "ArrowLeft" || e.key === "ArrowRight"))
    return true;
  if (!(e.ctrlKey || e.metaKey) || e.altKey) return false;
  // В полях ввода Ctrl+буква — это правка текста (Ctrl+A/C/V/X/Z остаются всегда).
  return blockedWithCtrl.has(e.key.toLowerCase());
}

export function nativeWindow(): void {
  document.addEventListener("contextmenu", (e) => {
    if (!editable(e.target)) e.preventDefault();
  });
  document.addEventListener(
    "keydown",
    (e) => {
      if (blockedKey(e)) e.preventDefault();
    },
    { capture: true },
  );
  // Ссылки и картинки не утаскиваются в другие программы, текст из полей — можно.
  document.addEventListener("dragstart", (e) => {
    if (!editable(e.target)) e.preventDefault();
  });
  // Файл, брошенный в окно, WebView2 открыл бы вместо интерфейса.
  document.addEventListener("dragover", (e) => e.preventDefault());
  document.addEventListener("drop", (e) => e.preventDefault());
  // Боковые кнопки мыши («назад», «вперёд») и автопрокрутка средней кнопкой.
  document.addEventListener("mouseup", (e) => {
    if (e.button === 3 || e.button === 4) e.preventDefault();
  });
  document.addEventListener("mousedown", (e) => {
    if (e.button === 1 && !editable(e.target)) e.preventDefault();
  });
}
