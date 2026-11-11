//! Экспорт диагностики: архив с итогами проверок, журналами и сгенерированным
//! конфигом ядра. Ключи, пароли, UUID, ссылки подписок и адреса серверов скрыты
//! (`kvt_core::redact`). Сначала окно показывает каждый файл целиком
//! (`diag_preview`), и сохраняется ровно то, что пользователь видел (`diag_save`).

use crate::{errors, query_status, AppState, Plan};
use kvt_core::compile::{compile, CompileInput};
use kvt_core::diaglog::timestamp;
use kvt_core::ipc::{Request, Response};
use kvt_core::{netlog, redact};
use serde::Serialize;
use serde_json::{json, Value};
use std::io::Write as _;
use tauri::State;

#[derive(Debug, Clone, Serialize)]
pub struct DiagFile {
    pub name: String,
    pub text: String,
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_default()
}

fn file(name: &str, text: String) -> DiagFile {
    DiagFile {
        name: name.into(),
        // Последний рубеж: даже то, что собрано не через журнал, проходит маскировку.
        text: redact::text(&text),
    }
}

/// Сгенерированный конфиг ядра для текущего выбора — так, как его соберёт служба.
fn config(state: &AppState) -> Value {
    match crate::build_plan(state) {
        Ok(Plan::Vpn(plan)) => {
            // Как в службе: при отключённом IPv6 TUN собирается только с IPv4.
            let disabled = crate::winreg::get_machine_dword(
                r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters",
                "DisabledComponents",
            );
            let ipv6 = kvt_core::compile::ipv6_enabled(disabled);
            match compile(
                plan.core,
                &CompileInput {
                    server: &plan.server,
                    routing: &plan.routing,
                    dns: &plan.dns,
                    rule_set_dir: "C:/ProgramData/KVT/rules",
                    ipv6,
                },
            ) {
                Ok(c) => json!({
                    "core": c.core,
                    "ipv6": ipv6,
                    "ipv6DisabledComponents": disabled,
                    "killSwitch": plan.kill_switch,
                    "zapret": plan.zapret,
                    "warnings": c.warnings,
                    "config": redact::json(&c.config),
                }),
                Err(e) => json!({ "error": e.to_string() }),
            }
        }
        Ok(Plan::Zapret(plan)) => json!({ "mode": "zapret", "plan": plan }),
        Err(e) => json!({ "error": e }),
    }
}

async fn collect(state: &AppState) -> Vec<DiagFile> {
    let now = netlog::now_ms();
    let status = query_status().await;
    let (service_log, core_log) = match crate::service_client::call(Request::ServiceLog).await {
        Ok(Response::ServiceLog { log, core }) => (log, core),
        Ok(_) => (errors::unexpected().to_owned(), String::new()),
        Err(e) => (format!("Служба не ответила: {e}"), String::new()),
    };
    let choice = state.choice.lock().map(|c| c.clone()).ok();
    let groups = state.groups.lock().map(|g| g.clone()).unwrap_or_default();
    let outcomes = state.outcomes.lock().map(|o| o.clone()).unwrap_or_default();
    let network = tokio::task::spawn_blocking(crate::netinfo::current)
        .await
        .ok()
        .flatten();

    let readme = format!(
        "Диагностика KVT {version}\r\n\
         Собрана: {time}\r\n\
         Windows: {os}\r\n\r\n\
         Ключи, пароли, UUID, ссылки подписок и адреса серверов скрыты.\r\n\
         Файлы:\r\n\
         - status.json — состояние подключения, выбранный режим и настройки;\r\n\
         - checks.json — итоги «Почему не работает?», проверок DNS, zapret и серверов;\r\n\
         - config.json — конфиг VPN-ядра, который соберёт служба для текущего выбора;\r\n\
         - kvt.log — журнал приложения;\r\n\
         - service.log — журнал службы;\r\n\
         - core.log — последние строки VPN-ядра;\r\n\
         - tgproxy.log — журнал прокси для Telegram (без секрета);\r\n\
         - netlog.json — журнал сетевых запросов KVT (только хосты).\r\n",
        version = env!("CARGO_PKG_VERSION"),
        time = timestamp(now),
        os = os_version(),
    );

    let status_json = json!({
        "service": match &status {
            Ok(Some(s)) => serde_json::to_value(s).unwrap_or_default(),
            Ok(None) => json!("служба не отвечает"),
            Err(e) => json!(e),
        },
        "tunnelOk": state.tunnel.lock().ok().and_then(|t| *t),
        "choice": choice,
        "network": network.as_ref().map(|n| json!({ "kind": n.kind })),
        "subscriptions": groups.iter().map(|g| json!({
            "servers": g.servers.len(),
            "byUrl": g.by_url,
            "updatedAt": g.updated_at,
            "errors": g.errors,
        })).collect::<Vec<_>>(),
    });

    let mut verdicts: std::collections::BTreeMap<String, usize> = Default::default();
    for outcome in outcomes.values() {
        let key = serde_json::to_value(outcome)
            .ok()
            .and_then(|v| {
                v.get("verdict")
                    .or_else(|| v.get("kind"))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "?".into());
        *verdicts.entry(key).or_default() += 1;
    }
    let checks = json!({
        "troubleshoot": state.last_diagnosis.lock().ok().and_then(|d| d.clone()),
        "dns": state.dns_report.lock().ok().and_then(|d| d.as_ref().map(|(_, r)| r.clone())),
        "zapret": state.zapret_last.lock().ok().and_then(|z| z.clone()),
        "serverChecks": verdicts,
    });

    let journal = crate::journal::net_log().await.ok();

    vec![
        file("README.txt", readme),
        file("status.json", pretty(&status_json)),
        file("checks.json", pretty(&checks)),
        file("config.json", pretty(&config(state))),
        file("kvt.log", crate::applog::tail()),
        file("service.log", service_log),
        file("core.log", core_log),
        file("tgproxy.log", crate::tgproxy::log_tail()),
        file(
            "netlog.json",
            journal
                .map(|j| pretty(&serde_json::to_value(j).unwrap_or_default()))
                .unwrap_or_default(),
        ),
    ]
}

fn os_version() -> String {
    // `ver` есть в любой Windows и ничего не меняет.
    std::process::Command::new("cmd")
        .args(["/c", "ver"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default()
}

/// Что войдёт в архив — для показа перед сохранением.
#[tauri::command]
pub async fn diag_preview(state: State<'_, AppState>) -> Result<Vec<DiagFile>, String> {
    let files = collect(&state).await;
    *state.diag_files.lock().map_err(errors::state)? = files.clone();
    Ok(files)
}

/// Сохраняет показанное в `diag_preview` в zip-архив. `false` — пользователь
/// закрыл окно выбора файла.
#[tauri::command]
pub async fn diag_save(state: State<'_, AppState>) -> Result<bool, String> {
    let files = state.diag_files.lock().map_err(errors::state)?.clone();
    if files.is_empty() {
        return Err(kvt_core::i18n::tr(
            "Сначала откройте предпросмотр диагностики.",
            "Open the diagnostics preview first.",
        )
        .into());
    }
    let name = format!(
        "kvt-diagnostics-{}.zip",
        timestamp(netlog::now_ms())
            .replace([':', ' '], "-")
            .trim_end_matches('Z')
    );
    let picked = tokio::task::spawn_blocking(move || {
        rfd::FileDialog::new()
            .set_title(kvt_core::i18n::tr(
                "Сохранить диагностику KVT",
                "Save KVT diagnostics",
            ))
            .set_file_name(name)
            .add_filter(kvt_core::i18n::tr("Архив ZIP", "ZIP archive"), &["zip"])
            .save_file()
    })
    .await
    .map_err(|_| {
        kvt_core::i18n::tr(
            "Окно сохранения закрылось с ошибкой. Повторите.",
            "The save dialog closed with an error. Try again.",
        )
    })?;
    let Some(path) = picked else {
        return Ok(false);
    };
    write_zip(&path, &files).map_err(|e| {
        errors::io(
            kvt_core::i18n::tr("Не удалось сохранить архив", "Couldn't save the archive"),
            &e,
        )
    })?;
    tracing::info!("диагностика сохранена");
    Ok(true)
}

fn write_zip(path: &std::path::Path, files: &[DiagFile]) -> std::io::Result<()> {
    let out = std::fs::File::create(path)?;
    let mut zip = zip::ZipWriter::new(out);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for f in files {
        zip.start_file(f.name.as_str(), options)
            .map_err(std::io::Error::other)?;
        zip.write_all(f.text.as_bytes())?;
    }
    zip.finish().map_err(std::io::Error::other)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_contains_exactly_the_previewed_files() {
        let dir = std::env::temp_dir().join(format!("kvt-diag-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("d.zip");
        let files = vec![
            file("a.txt", "ключ b831381d-6324-4d53-ad4f-8cda48b30811".into()),
            file("b.json", "{}".into()),
        ];
        write_zip(&path, &files).unwrap();
        let mut zip = zip::ZipArchive::new(std::fs::File::open(&path).unwrap()).unwrap();
        assert_eq!(zip.len(), 2);
        let mut text = String::new();
        std::io::Read::read_to_string(&mut zip.by_name("a.txt").unwrap(), &mut text).unwrap();
        assert!(!text.contains("b831381d"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
