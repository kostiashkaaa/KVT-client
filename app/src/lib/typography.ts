// Русская типографика для всего текста в окне: короткие предлоги и союзы не
// остаются висеть в конце строки, число не отрывается от единицы, тире не
// начинает строку. Работает и для текстов из Rust (итоги проверок).
//
// Меняются только текстовые узлы и только при появлении или изменении —
// MutationObserver, без таймеров и без обхода всего дерева на каждое обновление.

const NBSP = " ";

/** Предлог или союз из 1–2 букв и несколько частых трёхбуквенных. Частицы
 *  «ли», «же», «бы» сюда не входят: они прилипают к слову перед ними. */
const SHORT =
  /(?<=^|[\s («„"—])(?!(?:ли|же|бы)[\s ])([а-яё]{1,2}|для|без|при|про|под|над|или|что|как)\s+(?=\S)/giu;
/** «200 КБ», «3 мин», «13 проверок». */
const NUMBER = /(?<=\d)\s+(?=[а-яёa-z%°])/giu;
/** Тире прилипает к слову перед ним. */
const DASH = /\s+(?=[—–]\s)/gu;
/** Частицы «ли», «же», «бы» — к предыдущему слову. */
const PARTICLE = /\s+(?=(?:ли|же|бы)(?:[\s.,!?;:)»]|$))/giu;

export function tidy(text: string): string {
  return text.replace(SHORT, `$1${NBSP}`).replace(NUMBER, NBSP).replace(DASH, NBSP).replace(PARTICLE, NBSP);
}

/** Поля ввода и адреса не трогаем. */
function skip(node: Node): boolean {
  const el = node.parentElement;
  return !el || el.closest("textarea, input, code, pre, [data-raw]") !== null;
}

function fixNode(node: Node) {
  if (node.nodeType !== Node.TEXT_NODE || skip(node)) return;
  const value = node.nodeValue;
  if (!value || !/\s/.test(value)) return;
  const next = tidy(value);
  // Присваиваем, только если что-то поменялось, — иначе наблюдатель зациклится.
  if (next !== value) node.nodeValue = next;
}

function fixTree(root: Node) {
  if (root.nodeType === Node.TEXT_NODE) {
    fixNode(root);
    return;
  }
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  for (let n = walker.nextNode(); n; n = walker.nextNode()) fixNode(n);
}

export function typography(root: HTMLElement): () => void {
  fixTree(root);
  const observer = new MutationObserver((records) => {
    for (const r of records) {
      if (r.type === "characterData") fixNode(r.target);
      else r.addedNodes.forEach(fixTree);
    }
  });
  observer.observe(root, { subtree: true, childList: true, characterData: true });
  return () => observer.disconnect();
}
