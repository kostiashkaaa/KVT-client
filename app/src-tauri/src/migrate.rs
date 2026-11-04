//! Перенос из других клиентов (преобразование записей — `kvt_core::migrate`).
//!
//! Данные чужих клиентов только читаются. Базы SQLite перед чтением копируются
//! во временную папку: клиент может быть запущен и держать базу открытой, а
//! свежие изменения могут лежать в журнале `-wal` рядом с ней.
//!
//! Ссылки подписок и ключи остаются в Rust: в интерфейс уходит только
//! [`kvt_core::migrate::Preview`] — названия, адреса серверов подписок и протоколы.

use crate::{subs, AppState};
use kvt_core::migrate::{self, Client, Collected, Preview};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};
use tauri::{AppHandle, State};

/// Сколько каталогов обходим при поиске (защита от очень больших дисков).
const MAX_DIRS: usize = 20_000;
/// Сколько профилей читаем из одного клиента.
const MAX_PROFILES: usize = 5_000;

/// Каталоги, в которые поиск не заходит.
const SKIP_DIRS: &[&str] = &[
    "windows",
    "$recycle.bin",
    "system volume information",
    "programdata",
    "appdata",
    "node_modules",
    ".git",
    "winsxs",
    "msocache",
    "recovery",
    "perflogs",
];

fn env_dir(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).map(PathBuf::from)
}

/// Где искать: папки пользователя, AppData, Program Files и корни дисков.
fn roots() -> Vec<(PathBuf, usize)> {
    let mut out = Vec::new();
    if let Some(home) = env_dir("USERPROFILE") {
        for sub in ["Desktop", "Downloads", "Documents", "OneDrive"] {
            out.push((home.join(sub), 3));
        }
        out.push((home.clone(), 2));
    }
    for (var, depth) in [
        ("LOCALAPPDATA", 2),
        ("APPDATA", 2),
        ("ProgramFiles", 2),
        ("ProgramFiles(x86)", 2),
    ] {
        if let Some(d) = env_dir(var) {
            out.push((d, depth));
        }
    }
    for letter in 'C'..='Z' {
        let root = PathBuf::from(format!("{letter}:\\"));
        if root.is_dir() {
            out.push((root, 3));
        }
    }
    out
}

/// Каталог похож на данные одного из клиентов.
fn detect(dir: &Path) -> Option<Client> {
    if dir.join("guiConfigs").join("guiNDB.db").is_file()
        || dir.join("guiConfigs").join("guiNConfig.json").is_file()
    {
        return Some(Client::V2rayN);
    }
    if dir.join("config").join("throne.db").is_file() {
        return Some(Client::Throne);
    }
    if dir.join("config").join("groups").join("pm.json").is_file() {
        let throne = dir.join("Throne.exe").is_file() || dir.join("throne.exe").is_file();
        return Some(if throne {
            Client::Throne
        } else {
            Client::NekoRay
        });
    }
    let name = dir
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let in_hiddify =
        name == "hiddify_portable_data" || dir.to_string_lossy().to_lowercase().contains("hiddify");
    if in_hiddify && dir.join("db.sqlite").is_file() {
        return Some(Client::Hiddify);
    }
    if name == "happ" && dir.join("subs.db").is_file() {
        return Some(Client::Happ);
    }
    None
}

/// Обход в ширину с ограничением глубины и общего числа каталогов.
fn discover() -> Vec<(Client, PathBuf)> {
    let mut found = Vec::new();
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut visited = 0usize;
    for (root, depth) in roots() {
        let mut queue = VecDeque::from([(root, 0usize)]);
        while let Some((dir, level)) = queue.pop_front() {
            if visited >= MAX_DIRS {
                break;
            }
            visited += 1;
            let key = dir.canonicalize().unwrap_or_else(|_| dir.clone());
            if !seen.insert(key) {
                continue;
            }
            if let Some(client) = detect(&dir) {
                found.push((client, dir.clone()));
                continue;
            }
            if level >= depth {
                continue;
            }
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let Ok(kind) = entry.file_type() else {
                    continue;
                };
                // Ссылки и точки соединения не открываем: так не уйдём в чужие диски и петли.
                if !kind.is_dir() || kind.is_symlink() {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().to_lowercase();
                // AppData пропускаем при обходе профиля: её папки — отдельные корни.
                if SKIP_DIRS.contains(&name.as_str()) {
                    continue;
                }
                queue.push_back((entry.path(), level + 1));
            }
        }
    }
    found
}

// ── SQLite ──

/// Копия базы (и её журналов) во временной папке, удаляется вместе с объектом.
struct DbCopy {
    dir: PathBuf,
    conn: Connection,
}

impl Drop for DbCopy {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn open_copy(db: &Path) -> Result<DbCopy, String> {
    let dir = std::env::temp_dir().join(format!(
        "kvt-migrate-{}-{}",
        std::process::id(),
        kvt_core::netlog::now_ms()
    ));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let name = db.file_name().ok_or("нет имени базы")?;
    let copy = dir.join(name);
    std::fs::copy(db, &copy).map_err(|e| format!("не удалось прочитать базу: {e}"))?;
    for suffix in ["-wal", "-shm"] {
        let mut side = db.as_os_str().to_owned();
        side.push(suffix);
        let side = PathBuf::from(side);
        if side.is_file() {
            let mut target = copy.as_os_str().to_owned();
            target.push(suffix);
            let _ = std::fs::copy(&side, PathBuf::from(target));
        }
    }
    let conn = Connection::open_with_flags(&copy, OpenFlags::SQLITE_OPEN_READ_WRITE)
        .map_err(|e| format!("не удалось открыть базу: {e}"))?;
    Ok(DbCopy { dir, conn })
}

/// Строки таблицы как JSON-объекты «столбец → значение» (схемы у версий разные).
fn rows(conn: &Connection, sql: &str) -> Result<Vec<Map<String, Value>>, String> {
    let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
    let names: Vec<String> = stmt.column_names().map(str::to_owned).collect();
    let mut out = Vec::new();
    let mut rs = stmt.query([]).map_err(|e| e.to_string())?;
    while let Some(row) = rs.next().map_err(|e| e.to_string())? {
        if out.len() >= MAX_PROFILES {
            break;
        }
        let mut m = Map::new();
        for (i, name) in names.iter().enumerate() {
            let value = match row.get_ref(i) {
                Ok(ValueRef::Integer(n)) => Value::from(n),
                Ok(ValueRef::Real(f)) => Value::from(f),
                Ok(ValueRef::Text(t)) => Value::from(String::from_utf8_lossy(t).into_owned()),
                _ => continue,
            };
            m.insert(name.clone(), value);
        }
        out.push(m);
    }
    Ok(out)
}

fn table_exists(conn: &Connection, table: &str) -> bool {
    conn.query_row(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [table],
        |_| Ok(()),
    )
    .is_ok()
}

fn s(m: &Map<String, Value>, key: &str) -> String {
    match m.get(key) {
        Some(Value::String(v)) => v.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

fn read_json(path: &Path) -> Option<Value> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()
}

// ── Клиенты ──

fn collect(client: Client, dir: &Path) -> Collected {
    let mut c = Collected::new(client, dir.display().to_string());
    let result = match client {
        Client::V2rayN => v2rayn(&mut c, dir),
        Client::Throne if dir.join("config").join("throne.db").is_file() => throne(&mut c, dir),
        Client::Throne | Client::NekoRay => nekoray(&mut c, dir),
        Client::Hiddify => hiddify(&mut c, dir),
        Client::Happ => {
            c.note = Some(
                "Happ хранит подписки в зашифрованном виде — KVT их не читает. Скопируйте в Happ \
                 ссылку на подписку и добавьте её в KVT кнопкой «+»."
                    .into(),
            );
            Ok(())
        }
    };
    if let Err(e) = result {
        c.note = Some(format!("Не удалось прочитать данные: {e}"));
    }
    c
}

/// v2rayN: подписки (`SubItem`) и ключи, добавленные вручную (`ProfileItem` без подписки).
fn v2rayn(c: &mut Collected, dir: &Path) -> Result<(), String> {
    let db_path = dir.join("guiConfigs").join("guiNDB.db");
    if !db_path.is_file() {
        return v2rayn_legacy(c, dir);
    }
    let db = open_copy(&db_path)?;
    let mut sub_ids = HashSet::new();
    if table_exists(&db.conn, "SubItem") {
        for row in rows(&db.conn, "SELECT * FROM SubItem")? {
            let url = s(&row, "Url");
            if !url.trim().is_empty() {
                sub_ids.insert(s(&row, "Id"));
                c.add_subscription(&s(&row, "Remarks"), &url);
            }
        }
    }
    if table_exists(&db.conn, "ProfileItem") {
        for row in rows(&db.conn, "SELECT * FROM ProfileItem")? {
            // Серверы подписок придут с самой подпиской.
            if sub_ids.contains(&s(&row, "Subid")) {
                continue;
            }
            c.add_server(&s(&row, "Remarks"), migrate::v2rayn_profile(&row));
        }
    }
    Ok(())
}

/// Старые версии v2rayN: всё в `guiNConfig.json`, ключи с маленькой буквы.
fn v2rayn_legacy(c: &mut Collected, dir: &Path) -> Result<(), String> {
    let cfg = read_json(&dir.join("guiConfigs").join("guiNConfig.json"))
        .ok_or("guiNConfig.json не читается")?;
    let pascal = |v: &Value| -> Map<String, Value> {
        v.as_object()
            .map(|o| {
                o.iter()
                    .map(|(k, v)| {
                        let mut chars = k.chars();
                        let key = chars
                            .next()
                            .map(|f| f.to_uppercase().chain(chars).collect())
                            .unwrap_or_default();
                        (key, v.clone())
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut sub_ids = HashSet::new();
    for sub in cfg
        .get("subItem")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let m = pascal(sub);
        let url = s(&m, "Url");
        if !url.trim().is_empty() {
            sub_ids.insert(s(&m, "Id"));
            c.add_subscription(&s(&m, "Remarks"), &url);
        }
    }
    for item in cfg
        .get("vmess")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_PROFILES)
    {
        let m = pascal(item);
        if sub_ids.contains(&s(&m, "Subid")) {
            continue;
        }
        c.add_server(&s(&m, "Remarks"), migrate::v2rayn_profile(&m));
    }
    Ok(())
}

/// Throne (новые версии): таблицы `groups` и `profiles` в `config\throne.db`.
fn throne(c: &mut Collected, dir: &Path) -> Result<(), String> {
    let db = open_copy(&dir.join("config").join("throne.db"))?;
    let mut sub_groups = HashSet::new();
    if table_exists(&db.conn, "groups") {
        for row in rows(&db.conn, "SELECT id, name, url FROM groups")? {
            let url = s(&row, "url");
            if !url.trim().is_empty() {
                sub_groups.insert(s(&row, "id"));
                c.add_subscription(&s(&row, "name"), &url);
            }
        }
    }
    if table_exists(&db.conn, "profiles") {
        for row in rows(&db.conn, "SELECT name, gid, outbound_json FROM profiles")? {
            if sub_groups.contains(&s(&row, "gid")) {
                continue;
            }
            let outbound: Value =
                serde_json::from_str(&s(&row, "outbound_json")).unwrap_or(Value::Null);
            if migrate::is_service_outbound(&outbound) {
                continue;
            }
            c.add_server(
                &s(&row, "name"),
                migrate::singbox_outbound(&outbound, &s(&row, "name")),
            );
        }
    }
    Ok(())
}

/// NekoRay и старый Throne: `config\groups\*.json` и `config\profiles\*.json`.
fn nekoray(c: &mut Collected, dir: &Path) -> Result<(), String> {
    let config = dir.join("config");
    let mut sub_groups = HashSet::new();
    for entry in std::fs::read_dir(config.join("groups"))
        .map_err(|e| e.to_string())?
        .flatten()
    {
        let Some(g) = read_json(&entry.path()) else {
            continue;
        };
        let url = g.get("url").and_then(Value::as_str).unwrap_or_default();
        if !url.trim().is_empty() {
            if let Some(id) = g.get("id").and_then(Value::as_i64) {
                sub_groups.insert(id);
            }
            let name = g.get("name").and_then(Value::as_str).unwrap_or_default();
            c.add_subscription(name, url);
        }
    }
    if let Ok(entries) = std::fs::read_dir(config.join("profiles")) {
        for entry in entries.flatten().take(MAX_PROFILES) {
            let Some(p) = read_json(&entry.path()) else {
                continue;
            };
            if p.get("gid")
                .and_then(Value::as_i64)
                .is_some_and(|g| sub_groups.contains(&g))
            {
                continue;
            }
            match migrate::nekoray_profile(&p) {
                Ok((name, link)) => c.add_server(&name, Ok(link)),
                Err(reason) => c.add_server("", Err(reason)),
            }
        }
    }
    Ok(())
}

/// Hiddify: профили в `db.sqlite`; у локальных профилей конфиг — `configs\<id>.json`.
fn hiddify(c: &mut Collected, dir: &Path) -> Result<(), String> {
    let db = open_copy(&dir.join("db.sqlite"))?;
    if !table_exists(&db.conn, "profile_entries") {
        return Err("в базе Hiddify нет профилей".into());
    }
    for row in rows(&db.conn, "SELECT id, type, name, url FROM profile_entries")? {
        let url = s(&row, "url");
        if s(&row, "type") == "remote" && !url.trim().is_empty() {
            c.add_subscription(&s(&row, "name"), &url);
        } else if let Some(config) =
            read_json(&dir.join("configs").join(format!("{}.json", s(&row, "id"))))
        {
            migrate::singbox_config(c, &config);
        }
    }
    Ok(())
}

// ── Команды ──

#[tauri::command]
pub async fn migrate_scan(state: State<'_, AppState>) -> Result<Vec<Preview>, String> {
    let found = tokio::task::spawn_blocking(|| {
        discover()
            .into_iter()
            .map(|(client, dir)| collect(client, &dir))
            .collect::<Vec<_>>()
    })
    .await
    .map_err(|_| "Поиск прервался")?;
    let previews = found.iter().map(Collected::preview).collect();
    *state.migration.lock().map_err(crate::errors::state)? = found;
    Ok(previews)
}

/// «Указать папку»: клиент лежит там, где поиск его не нашёл.
#[tauri::command]
pub async fn migrate_pick_folder(
    state: State<'_, AppState>,
) -> Result<Option<Vec<Preview>>, String> {
    let picked = tokio::task::spawn_blocking(|| {
        rfd::FileDialog::new()
            .set_title("Папка другого VPN-клиента")
            .pick_folder()
    })
    .await
    .map_err(|_| "Окно выбора папки закрылось с ошибкой")?;
    let Some(dir) = picked else {
        return Ok(None);
    };
    let collected = tokio::task::spawn_blocking(move || {
        // Выбрать могли и саму папку клиента, и папку данных внутри неё.
        [
            dir.clone(),
            dir.parent().map(Path::to_path_buf).unwrap_or_default(),
        ]
        .into_iter()
        .find_map(|d| detect(&d).map(|client| collect(client, &d)))
    })
    .await
    .map_err(|_| "Чтение папки прервалось")?
    .ok_or("В этой папке нет данных v2rayN, Throne, NekoRay или Hiddify")?;
    let mut found = state.migration.lock().map_err(crate::errors::state)?;
    found.retain(|c| c.location != collected.location);
    found.push(collected);
    Ok(Some(found.iter().map(Collected::preview).collect()))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportRequest {
    /// Расположения выбранных клиентов (как в `Preview::location`).
    pub locations: Vec<String>,
    pub servers: bool,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportReport {
    /// Подписки загружены.
    pub loaded: usize,
    /// Подписки сохранены, но сейчас не загрузились — обновятся позже.
    pub pending: usize,
    /// Такие подписки в KVT уже были.
    pub existing: usize,
    /// Серверов, добавленных вручную.
    pub servers: usize,
}

#[tauri::command]
pub async fn migrate_import(
    request: ImportRequest,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<ImportReport, String> {
    let chosen: Vec<Collected> = state
        .migration
        .lock()
        .map_err(crate::errors::state)?
        .iter()
        .filter(|c| request.locations.contains(&c.location))
        .cloned()
        .collect();
    if chosen.is_empty() {
        return Err("Выберите, откуда перенести".into());
    }
    let mut report = ImportReport::default();
    let mut seen = HashSet::new();
    // По одной подписке: NetGovernor и так не даст часто стучаться к одному серверу.
    for sub in chosen.iter().flat_map(|c| &c.subscriptions) {
        if !seen.insert(sub.url.expose().to_owned()) {
            continue;
        }
        match subs::import_url(&state, sub.url.expose(), &sub.name).await? {
            subs::Imported::Loaded => report.loaded += 1,
            subs::Imported::Pending => report.pending += 1,
            subs::Imported::Existing => report.existing += 1,
        }
    }
    if request.servers {
        let links: Vec<&str> = chosen
            .iter()
            .flat_map(|c| &c.servers)
            .map(|s| s.link.expose())
            .collect();
        report.servers = subs::import_links(&state, &links)?;
    }
    subs::changed(&app, &state)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kvt-mig-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    #[test]
    fn v2rayn_database_is_read_without_touching_original() {
        let dir = tmp("v2rayn");
        let cfg = dir.join("guiConfigs");
        std::fs::create_dir_all(&cfg).unwrap();
        let db_path = cfg.join("guiNDB.db");
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(&format!(
                "CREATE TABLE SubItem (Id TEXT, Remarks TEXT, Url TEXT, Enabled INTEGER);
                 INSERT INTO SubItem VALUES ('s1', 'Провайдер', 'https://sub.example.com/t/SECRET', 1);
                 CREATE TABLE ProfileItem (IndexId TEXT, ConfigType INTEGER, Subid TEXT, Remarks TEXT,
                    Address TEXT, Port INTEGER, Id TEXT, Network TEXT, StreamSecurity TEXT, Sni TEXT,
                    Security TEXT, Flow TEXT);
                 INSERT INTO ProfileItem VALUES ('a', 5, 's1', 'из подписки', 'a.example.com', 443, '{UUID}', 'tcp', 'tls', 'a.example.com', 'none', '');
                 INSERT INTO ProfileItem VALUES ('b', 5, '', 'Мой сервер', 'b.example.com', 443, '{UUID}', 'tcp', 'tls', 'b.example.com', 'none', '');
                 INSERT INTO ProfileItem VALUES ('c', 1, '', 'vmess', 'c.example.com', 443, '{UUID}', 'tcp', '', '', 'auto', '');"
            ))
            .unwrap();
        }
        let before = std::fs::read(&db_path).unwrap();
        assert_eq!(detect(&dir), Some(Client::V2rayN));
        let c = collect(Client::V2rayN, &dir);
        assert_eq!(c.note, None);
        assert_eq!(c.subscriptions.len(), 1);
        assert_eq!(c.servers.len(), 1);
        assert_eq!(c.servers[0].name, "Мой сервер");
        assert_eq!(c.skipped, vec!["VMess не поддерживается"]);
        assert_eq!(std::fs::read(&db_path).unwrap(), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nekoray_files_are_read() {
        let dir = tmp("neko");
        let config = dir.join("config");
        std::fs::create_dir_all(config.join("groups")).unwrap();
        std::fs::create_dir_all(config.join("profiles")).unwrap();
        std::fs::write(config.join("groups").join("pm.json"), "{}").unwrap();
        std::fs::write(
            config.join("groups").join("1.json"),
            r#"{"id": 1, "name": "Sub", "url": "https://sub.example.com/x"}"#,
        )
        .unwrap();
        std::fs::write(
            config.join("profiles").join("0.json"),
            format!(
                r#"{{"type":"vless","gid":0,"bean":{{"name":"Мой","addr":"n.example.com","port":443,"pass":"{UUID}","stream":{{"net":"tcp","sec":"tls","sni":"n.example.com"}}}}}}"#
            ),
        )
        .unwrap();
        std::fs::write(
            config.join("profiles").join("1.json"),
            format!(r#"{{"type":"vless","gid":1,"bean":{{"name":"из подписки","addr":"x","port":1,"pass":"{UUID}"}}}}"#),
        )
        .unwrap();
        assert_eq!(detect(&dir), Some(Client::NekoRay));
        let c = collect(Client::NekoRay, &dir);
        assert_eq!(c.subscriptions.len(), 1);
        assert_eq!(c.servers.len(), 1);
        assert!(c.skipped.is_empty(), "{:?}", c.skipped);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn happ_gives_a_note_not_data() {
        let root = tmp("happ");
        let dir = root.join("Happ");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("subs.db"), b"x").unwrap();
        assert_eq!(detect(&dir), Some(Client::Happ));
        let c = collect(Client::Happ, &dir);
        assert!(c.is_empty() && c.note.is_some());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Что найдётся на этом компьютере: `cargo test -p kvt-app real_migrate_scan -- --ignored --nocapture`.
    #[test]
    #[ignore = "обходит диски этого компьютера"]
    fn real_migrate_scan() {
        let start = std::time::Instant::now();
        for (client, dir) in discover() {
            let p = collect(client, &dir).preview();
            println!(
                "{} {} — подписок {}, серверов {}, пропущено {:?}, {:?}",
                p.title,
                p.location,
                p.subscriptions.len(),
                p.servers.len(),
                p.skipped,
                p.note
            );
        }
        println!("{} мс", start.elapsed().as_millis());
    }
}
