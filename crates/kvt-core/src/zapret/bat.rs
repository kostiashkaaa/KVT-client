//! Разбор `.bat` Flowseal: из файла берутся только аргументы `winws.exe`, каждый флаг
//! сверяется с белым списком, пути — только через подстановки `%BIN%` и `%LISTS%`.

use super::{title, valid_id, Strategy, ZapretError};

/// Флаги winws, которые встречаются в стратегиях Flowseal. Остальные отвергаются.
const ALLOWED_FLAGS: &[&str] = &[
    "--new",
    "--wf-tcp",
    "--wf-udp",
    "--filter-tcp",
    "--filter-udp",
    "--filter-l3",
    "--filter-l7",
    "--hostlist",
    "--hostlist-exclude",
    "--hostlist-domains",
    "--hostlist-exclude-domains",
    "--ipset",
    "--ipset-exclude",
    "--ip-id",
    "--dpi-desync",
    "--dpi-desync-repeats",
    "--dpi-desync-fooling",
    "--dpi-desync-cutoff",
    "--dpi-desync-any-protocol",
    "--dpi-desync-badseq-increment",
    "--dpi-desync-split-pos",
    "--dpi-desync-split-seqovl",
    "--dpi-desync-split-seqovl-pattern",
    "--dpi-desync-fakedsplit-pattern",
    "--dpi-desync-hostfakesplit-mod",
    "--dpi-desync-fake-tls",
    "--dpi-desync-fake-tls-mod",
    "--dpi-desync-fake-http",
    "--dpi-desync-fake-quic",
    "--dpi-desync-fake-discord",
    "--dpi-desync-fake-stun",
    "--dpi-desync-fake-unknown",
    "--dpi-desync-fake-unknown-udp",
];

/// Флаги, значение которых может быть файлом из `bin` или `lists`.
const FILE_FLAGS: &[&str] = &[
    "--hostlist",
    "--hostlist-exclude",
    "--ipset",
    "--ipset-exclude",
    "--dpi-desync-split-seqovl-pattern",
    "--dpi-desync-fakedsplit-pattern",
    "--dpi-desync-fake-tls",
    "--dpi-desync-fake-http",
    "--dpi-desync-fake-quic",
    "--dpi-desync-fake-discord",
    "--dpi-desync-fake-stun",
    "--dpi-desync-fake-unknown",
    "--dpi-desync-fake-unknown-udp",
];

pub(super) const BIN: &str = "%BIN%";
pub(super) const LISTS: &str = "%LISTS%";
pub(super) const GAME_TCP: &str = "%GameFilterTCP%";
pub(super) const GAME_UDP: &str = "%GameFilterUDP%";

/// Склеивает строки с `^` в конце и берёт всё после `winws.exe"`.
fn command_tail(text: &str) -> Option<String> {
    let mut joined = String::new();
    let mut collecting = false;
    for line in text.lines() {
        let line = line.trim_end();
        if !collecting {
            let Some(pos) = line.find("winws.exe\"") else {
                continue;
            };
            collecting = true;
            joined.push_str(&line[pos + "winws.exe\"".len()..]);
        } else {
            joined.push(' ');
            joined.push_str(line);
        }
        match joined.strip_suffix('^') {
            Some(rest) => joined.truncate(rest.len()),
            None => return Some(joined),
        }
    }
    collecting.then_some(joined)
}

/// Разбор как в cmd: кавычки группируют, `^` экранирует следующий символ.
fn tokenize(s: &str) -> Result<Vec<String>, ZapretError> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => quoted = !quoted,
            '^' if !quoted => {
                if let Some(next) = chars.next() {
                    cur.push(next);
                }
            }
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if quoted {
        return Err(ZapretError::Quote);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    Ok(out)
}

fn safe_file_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// Значение без путей и спецсимволов cmd: порты, числа, режимы, `sni=ya.ru`, `!`.
fn safe_plain(value: &str) -> bool {
    value
        .replace(GAME_TCP, "")
        .replace(GAME_UDP, "")
        .chars()
        .all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | ',' | ':' | '=' | '+' | '_' | '-' | '!')
        })
}

fn check_arg(arg: &str) -> Result<(), ZapretError> {
    let (flag, value) = match arg.split_once('=') {
        Some((f, v)) => (f, Some(v)),
        None => (arg, None),
    };
    if !ALLOWED_FLAGS.contains(&flag) {
        return Err(ZapretError::Flag(flag.to_owned()));
    }
    let Some(value) = value else {
        return Ok(());
    };
    let bad = || ZapretError::Value(flag.to_owned(), value.to_owned());
    if let Some(name) = value
        .strip_prefix(BIN)
        .or_else(|| value.strip_prefix(LISTS))
    {
        return if FILE_FLAGS.contains(&flag) && safe_file_name(name) {
            Ok(())
        } else {
            Err(bad())
        };
    }
    if safe_plain(value) {
        Ok(())
    } else {
        Err(bad())
    }
}

/// Стратегия из текста `.bat`. Любой неизвестный флаг или путь — ошибка целиком.
pub fn parse_bat(id: &str, text: &str) -> Result<Strategy, ZapretError> {
    if !valid_id(id) {
        return Err(ZapretError::UnknownStrategy(id.to_owned()));
    }
    let tail = command_tail(text).ok_or(ZapretError::NoWinws)?;
    let args = tokenize(&tail)?;
    if args.is_empty() {
        return Err(ZapretError::NoWinws);
    }
    for arg in &args {
        check_arg(arg)?;
    }
    let needs_timestamps = args.iter().any(|a| {
        a.strip_prefix("--dpi-desync-fooling=")
            .is_some_and(|v| v.split(',').any(|f| f == "ts"))
    });
    Ok(Strategy {
        id: id.to_owned(),
        title: title(id),
        recommended: !text.contains("NOT RECOMMENDED"),
        needs_timestamps,
        args,
    })
}
