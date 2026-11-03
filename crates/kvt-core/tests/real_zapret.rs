//! Все стратегии настоящего релиза Flowseal проходят белый список флагов.
//! Комплект скачивает `scripts/fetch-zapret.ps1`; без него тест пропускается.

#![allow(clippy::unwrap_used)]

use kvt_core::zapret::{self, parse_bat, render, GameFilter, RenderContext};
use std::path::PathBuf;

#[test]
fn every_flowseal_strategy_is_accepted() {
    let dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/zapret/strategies");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        eprintln!("нет комплекта zapret ({}), пропуск", dir.display());
        return;
    };
    let mut parsed = Vec::new();
    for entry in entries {
        let path = entry.unwrap().path();
        let id = path.file_stem().unwrap().to_string_lossy().into_owned();
        let text = std::fs::read_to_string(&path).unwrap();
        let s = parse_bat(&id, &text).unwrap_or_else(|e| panic!("{id}: {e}"));
        let args = render(
            &s,
            &RenderContext {
                bin: r"C:\KVT\zapret\bin\",
                lists: r"C:\ProgramData\KVT\zapret\",
                game: GameFilter::Off,
                interface: None,
            },
        );
        assert!(args.iter().all(|a| !a.contains('%')), "{id}: {args:?}");
        parsed.push(s);
    }
    assert_eq!(parsed.len(), zapret::PREFERRED_ORDER.len());
    for s in &parsed {
        assert!(
            zapret::PREFERRED_ORDER.contains(&s.id.as_str()),
            "{} нет в PREFERRED_ORDER",
            s.id
        );
    }
    zapret::sort(&mut parsed);
    assert_eq!(parsed[0].id, "general");
    assert_eq!(parsed.last().unwrap().id, "general (ALT5)");
    assert!(!parsed.last().unwrap().recommended);
}
