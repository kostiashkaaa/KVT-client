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
        // KVT добавляет свои исключения, но не меняет, к какому трафику применяется
        // профиль: хостлист только там, где профиль и так выбирается по имени хоста
        // (иначе голос Discord и игровой фильтр перестали бы работать).
        let original: Vec<&[String]> = s.args.split(|a| a == "--new").collect();
        let rendered: Vec<&[String]> = args.split(|a| a == "--new").collect();
        assert_eq!(original.len(), rendered.len(), "{id}");
        for (o, r) in original.iter().zip(&rendered) {
            let has_hostlist = |p: &[String]| p.iter().any(|a| a.starts_with("--hostlist"));
            assert_eq!(has_hostlist(o), has_hostlist(r), "{id}: {r:?}");
            if r.iter().any(|a| a.starts_with("--filter-")) {
                assert!(
                    r.iter().any(|a| a.ends_with("ipset-exclude-user.txt")),
                    "{id}: {r:?}"
                );
            }
        }
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
