//! Mica — материал Windows 11 под окном: подложка окна и боковой панели берёт цвет
//! обоев и тему системы, как у «Параметров». Нужна сборка 22000 и новее; на Windows 10
//! окно остаётся прежним — плотным и без прозрачности: прозрачное окно с плотной
//! страницей там ничего не даёт, а при изменении размера могло бы мигать.
//!
//! Решает Rust, а не страница: окно создаётся прозрачным, а на `<html>` до первого кадра
//! встаёт `data-mica` — по нему app.css делает подложку прозрачной (`--window`, `--rail`).
//! Светлую или тёмную Mica выбирает тема окна: `setTheme` в theme.svelte.ts красит и
//! заголовок, и материал, поэтому тёмная KVT в светлой системе получает тёмную Mica.
//!
//! Если в Windows выключены «Эффекты прозрачности» или включена экономия заряда, система
//! сама рисует вместо Mica плотный цвет темы — окно выглядит как обычно.

use tauri::window::{Effect, EffectsBuilder};
use tauri::{Manager, Runtime, WebviewWindowBuilder};

/// Первая сборка Windows 11: раньше материала Mica нет.
const FIRST_WINDOWS_11_BUILD: u32 = 22000;

/// Ставит на `<html>` флаг для app.css. Скрипт выполняется при создании документа, когда
/// `<html>` ещё нет, поэтому ждёт его появления — иначе первый кадр был бы плотным и
/// мигнул.
const MARK: &str = r#"(function () {
  var mark = function () { document.documentElement.setAttribute("data-mica", ""); };
  if (document.documentElement) { mark(); return; }
  new MutationObserver(function (_, observer) {
    if (document.documentElement) { observer.disconnect(); mark(); }
  }).observe(document, { childList: true });
})();"#;

fn supports(build: u32) -> bool {
    build >= FIRST_WINDOWS_11_BUILD
}

/// Номер сборки, если материал есть. Логирует и возвращает `None` на Windows 10.
fn windows11(what: &str) -> Option<u32> {
    let build = windows_version::OsVersion::current().build;
    if !supports(build) {
        tracing::info!(build, "окно без {what}: нужна Windows 11");
        return None;
    }
    tracing::info!(build, "окно с {what}");
    Some(build)
}

/// Окно под Mica: прозрачное, с материалом и флагом для страницы. На Windows 10 и
/// старше — без изменений.
pub fn prepare<'a, R: Runtime, M: Manager<R>>(
    builder: WebviewWindowBuilder<'a, R, M>,
) -> WebviewWindowBuilder<'a, R, M> {
    if windows11("Mica").is_none() {
        return builder;
    }
    builder
        .transparent(true)
        .effects(EffectsBuilder::new().effect(Effect::Mica).build())
        .initialization_script(MARK)
}

/// Мини-панель под Acrylic: её не перетаскивают, цена эффекта (перерисовка при
/// изменении фона) не страшна — как у всплывающих панелей самой Windows. Флаг тот
/// же, что у Mica: страница делает подложку прозрачной по нему (`--panel` в
/// app.css), карточки панели остаются плотными. На Windows 10 — без изменений.
pub fn prepare_panel<'a, R: Runtime, M: Manager<R>>(
    builder: WebviewWindowBuilder<'a, R, M>,
) -> WebviewWindowBuilder<'a, R, M> {
    if windows11("Acrylic").is_none() {
        return builder;
    }
    builder
        .transparent(true)
        .effects(EffectsBuilder::new().effect(Effect::Acrylic).build())
        .initialization_script(MARK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mica_starts_with_windows_11() {
        assert!(!supports(19045), "Windows 10 22H2");
        assert!(!supports(21999));
        assert!(supports(22000), "Windows 11 21H2");
        assert!(supports(26200));
    }

    /// Флаг, который ставит скрипт, и тот, что ждёт CSS, не должны разойтись — ни у
    /// главного окна, ни у мини-панели (подложка `--panel`).
    #[test]
    fn css_waits_for_the_flag_the_script_sets() {
        let css = include_str!("../../src/app.css");
        let panel = include_str!("../../src/mini/Panel.svelte");
        assert!(MARK.contains("\"data-mica\""));
        assert!(css.contains(":root[data-mica]"));
        assert!(css.contains("--panel: transparent"));
        assert!(panel.contains("var(--panel)"));
    }
}
