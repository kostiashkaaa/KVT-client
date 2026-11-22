//! Упаковывает CSV DB-IP Country Lite в `presets/dbip-country.bin`. Запускает
//! `scripts/update-dbip.ps1`; вручную:
//!
//!   cargo run -p kvt-core --example pack_dbip -- dbip-country-lite-2026-11.csv presets/dbip-country.bin

use std::process::ExitCode;

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let (Some(input), Some(output), None) = (args.next(), args.next(), args.next()) else {
        return Err("нужны два аргумента: исходный CSV и файл результата".into());
    };
    let csv = std::fs::read_to_string(&input).map_err(|e| format!("{input}: {e}"))?;
    let (bytes, stats) = kvt_core::geo::pack(&csv).map_err(|e| e.to_string())?;
    std::fs::write(&output, &bytes).map_err(|e| format!("{output}: {e}"))?;
    // Строки читает скрипт обновления: они попадают в `presets/dbip-country.txt`.
    println!("countries={}", stats.countries);
    println!("ranges_v4={}", stats.v4);
    println!("ranges_v6={}", stats.v6);
    println!("bytes={}", bytes.len());
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}
