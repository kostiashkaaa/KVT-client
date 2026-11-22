//! Список подписок и ручных ключей для окна — только данные для показа.

use super::*;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionItem {
    id: String,
    title: String,
    by_url: bool,
    servers: usize,
    used_bytes: Option<u64>,
    total_bytes: Option<u64>,
    expire: Option<u64>,
    updated_at: u64,
    /// Когда подписка обновится сама (только у подписок по ссылке).
    next_update: Option<u64>,
    /// Название задал пользователь, а не провайдер.
    renamed: bool,
    /// Последнее обновление не удалось: когда и почему (без ссылки).
    last_error: Option<String>,
    failed_at: Option<u64>,
    /// Ссылки и текст провайдера (только https; текст выводится без разметки).
    support_url: Option<String>,
    web_page_url: Option<String>,
    announce: Option<String>,
    /// Служебные строки провайдера («Осталось 10 ГБ»).
    info: Vec<String>,
    /// Сколько серверов каждого протокола — по убыванию.
    protocols: Vec<ProtocolCount>,
    /// Почему часть строк подписки пропущена: причина и сколько раз.
    skipped: Vec<Skipped>,
    /// Точные повторы, которые выброшены.
    duplicates: usize,
    /// Что KVT у части серверов не применяет (например, `pinSHA256`): текст и
    /// сколько серверов. Сервер подключается, но пользователь знает, чем рискует.
    warnings: Vec<Skipped>,
    /// Ключи группы «Добавлено вручную» — каждый можно переименовать, заменить или
    /// удалить. У подписок по ссылке пусто: серверы там задаёт провайдер.
    keys: Vec<ManualKey>,
    /// Сколько серверов скрыл фильтр из «Расширенных».
    hidden: usize,
    options: OptionsView,
}

/// «Расширенные» подписки для окна. Свой ID устройства не показывается — только
/// то, что он задан.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OptionsView {
    keep: Vec<String>,
    drop: Vec<String>,
    client: Option<String>,
    user_agent: Option<String>,
    hwid: HwidMode,
    own_hwid: bool,
    /// ID устройства уходит провайдеру: он его попросил или так выбрано.
    hwid_sent: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolCount {
    protocol: &'static str,
    count: usize,
}

/// Причина пропуска строк. Текст ошибки разбора секретов не содержит: строку
/// подписки он не повторяет (см. `ParseError`).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Skipped {
    reason: String,
    count: usize,
}

pub(super) fn protocol_counts(servers: &[kvt_core::Server]) -> Vec<ProtocolCount> {
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for s in servers {
        *counts.entry(s.protocol.kind()).or_default() += 1;
    }
    let mut list: Vec<ProtocolCount> = counts
        .into_iter()
        .map(|(protocol, count)| ProtocolCount { protocol, count })
        .collect();
    list.sort_by_key(|x| std::cmp::Reverse(x.count));
    list
}

pub(super) fn skipped(errors: &[(usize, kvt_core::parser::ParseError)]) -> Vec<Skipped> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for (_, e) in errors {
        *counts.entry(e.to_string()).or_default() += 1;
    }
    let mut list: Vec<Skipped> = counts
        .into_iter()
        .map(|(reason, count)| Skipped { reason, count })
        .collect();
    list.sort_by_key(|x| std::cmp::Reverse(x.count));
    list
}

pub(super) fn warnings(servers: &[kvt_core::Server]) -> Vec<Skipped> {
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for w in servers.iter().flat_map(kvt_core::Server::warnings) {
        *counts.entry(w).or_default() += 1;
    }
    counts
        .into_iter()
        .map(|(reason, count)| Skipped {
            reason: reason.to_owned(),
            count,
        })
        .collect()
}

/// Ключ, добавленный вручную, для редактирования. Без секретов: ссылка (в ней
/// UUID или пароль) в окно не уходит — её можно только заменить новой.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManualKey {
    key: String,
    /// Название целиком, как в ссылке (с флагами-эмодзи) — для правки.
    name: String,
    /// Название без флагов — для списка: Windows рисует флаги-эмодзи буквами.
    title: String,
    /// Страна (из флага в названии или по IP-адресу) — для картинки флага.
    flag: Option<String>,
    protocol: &'static str,
    /// Транспорт (`tcp`, `xhttp`…): адрес сервера в окно не уходит.
    transport: &'static str,
}

/// Ключ, добавленный вручную, для списка: флаг — как у серверов (из названия или по IP).
fn manual_key(e: &catalog::Entry) -> ManualKey {
    let (title, flag) = crate::view::name_and_flag(&e.server);
    ManualKey {
        key: e.key.clone(),
        name: e.server.name.clone(),
        title,
        flag,
        protocol: e.server.protocol.kind(),
        transport: catalog::transport_kind(&e.server.transport),
    }
}

#[tauri::command]
pub fn list_subscriptions(state: State<'_, AppState>) -> Result<Vec<SubscriptionItem>, String> {
    let guard = state.store.lock().map_err(lock_err)?;
    let Some(store) = guard.as_ref() else {
        return Ok(Vec::new());
    };
    let entries = state.servers.lock().map_err(lock_err)?;
    Ok(store
        .subscriptions
        .iter()
        .map(|s| {
            let (content, hidden) = catalog::content(s);
            SubscriptionItem {
                id: s.id.clone(),
                title: catalog::title(s),
                by_url: s.url.is_some(),
                servers: content.servers.len(),
                used_bytes: s.meta.used_bytes(),
                total_bytes: s.meta.total,
                expire: s.meta.expire,
                updated_at: s.updated_at,
                next_update: s.url.is_some().then_some(s.next_update),
                renamed: s.custom_title.is_some(),
                last_error: s.last_error.as_ref().map(|e| e.message.clone()),
                failed_at: s.last_error.as_ref().map(|e| e.at),
                support_url: s.meta.support_url.clone(),
                web_page_url: s.meta.web_page_url.clone(),
                announce: s.meta.announce.clone(),
                info: content.info.clone(),
                protocols: protocol_counts(&content.servers),
                skipped: skipped(&content.errors),
                duplicates: content.duplicates,
                warnings: warnings(&content.servers),
                keys: if s.url.is_some() {
                    Vec::new()
                } else {
                    entries
                        .iter()
                        .filter(|e| e.sub == s.id)
                        .map(manual_key)
                        .collect()
                },
                hidden,
                options: OptionsView {
                    keep: s.options.filter.keep.clone(),
                    drop: s.options.filter.drop.clone(),
                    client: s.options.client.clone(),
                    user_agent: s.options.user_agent.clone(),
                    hwid: s.options.hwid,
                    own_hwid: s.own_hwid.is_some(),
                    hwid_sent: match s.options.hwid {
                        HwidMode::Always => true,
                        HwidMode::Auto => s.hwid_asked,
                        HwidMode::Never => false,
                    },
                },
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvt_core::parser::{parse_uri, Entry as Parsed};

    fn entry(uri: &str) -> catalog::Entry {
        let server = match parse_uri(uri).unwrap() {
            Parsed::Server(s) => *s,
            Parsed::Info(_) => panic!("ожидался сервер"),
        };
        catalog::Entry {
            key: "k".into(),
            sub: "s".into(),
            server,
            same_as: None,
        }
    }

    const KEY: &str = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@ADDR:443?security=reality&sni=a.com&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw#NAME";

    #[test]
    fn manual_key_without_emoji_gets_the_flag_from_its_ip() {
        let key = manual_key(&entry(
            &KEY.replace("ADDR", "8.8.8.8").replace("NAME", "Home"),
        ));
        assert_eq!(
            (key.flag.as_deref(), key.title.as_str()),
            (Some("us"), "Home")
        );
        // Название для правки остаётся как в ссылке.
        assert_eq!(key.name, "Home");
        // Эмодзи главнее адреса; у домена флага нет.
        let emoji = KEY
            .replace("ADDR", "8.8.8.8")
            .replace("NAME", "%F0%9F%87%B3%F0%9F%87%B1%20Home");
        assert_eq!(manual_key(&entry(&emoji)).flag.as_deref(), Some("nl"));
        let domain = KEY
            .replace("ADDR", "node.example.com")
            .replace("NAME", "Cloud");
        assert_eq!(manual_key(&entry(&domain)).flag, None);
    }
}
